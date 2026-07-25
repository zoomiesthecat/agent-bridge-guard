"""Small, strict JSON-RPC boundary for EVM execution evidence.

The module deliberately exposes only the RPC operations needed by the execution
engine.  It never includes endpoint URLs in exceptions because endpoints can
contain private path tokens even when they do not use URL credentials.
"""

from __future__ import annotations

import ipaddress
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeAlias, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .models import JSONObject, JSONValue

DEFAULT_MAX_REQUEST_BYTES = 128 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024

Transport: TypeAlias = Callable[[str, bytes, float], bytes]
Sleep: TypeAlias = Callable[[float], None]
NormalizedLog: TypeAlias = tuple[str, tuple[str, ...], str, int, str, str, int, bool]
NormalizedReceipt: TypeAlias = tuple[str, int, int, str, tuple[NormalizedLog, ...]]


class RpcError(RuntimeError):
    """Base class for RPC boundary failures."""


class RpcConfigurationError(RpcError):
    """Raised for an endpoint that is unsafe to use."""


class RpcTransportError(RpcError):
    """Raised when a request cannot be completed."""


class RpcProtocolError(RpcError):
    """Raised for malformed JSON-RPC replies."""


class RpcRemoteError(RpcError):
    """A JSON-RPC error response, with its code but no endpoint disclosure."""

    def __init__(self, code: int, message: str) -> None:
        del message
        super().__init__(f"RPC remote error {code}")
        self.code = code


class NeedsReconciliationError(RpcError):
    """Evidence changed or disagreed and must not be considered verified."""

    state = "NEEDS_RECONCILIATION"


class RpcDisagreementError(NeedsReconciliationError):
    """Independent RPC endpoints do not agree on chain identity."""


class ReorgDetectedError(NeedsReconciliationError):
    """A receipt stopped matching the canonical block while waiting for finality."""


class TransactionFailedError(RpcError):
    """The mined transaction has an unsuccessful status."""

    def __init__(self, receipt: JSONObject) -> None:
        super().__init__("transaction receipt has unsuccessful status")
        # The receipt is only attached after its block and status have passed the
        # same canonical-finality checks as a successful transaction.  Callers
        # can therefore durably record a terminal source failure rather than
        # treating a transient/reorgable status=0 observation as final.
        self.receipt = receipt


def _json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value {value!r}")


def _normalize_response_json(value: object) -> JSONValue:
    if isinstance(value, float):
        raise RpcProtocolError("RPC returned a floating-point value")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, list):
        return [_normalize_response_json(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise RpcProtocolError("RPC returned an object with a non-string key")
        return {key: _normalize_response_json(item) for key, item in value.items()}
    raise RpcProtocolError("RPC returned an unsupported JSON value")


def _json_loads(raw: bytes) -> JSONValue:
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RpcProtocolError("RPC returned invalid JSON") from exc
    return _normalize_response_json(value)


def _is_localhost(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_endpoint(endpoint: str, allow_insecure_localhost: bool) -> None:
    parts = urlsplit(endpoint)
    if parts.username is not None or parts.password is not None:
        raise RpcConfigurationError("RPC endpoint must not contain URL credentials")
    if parts.fragment or not parts.hostname:
        raise RpcConfigurationError("RPC endpoint is invalid")
    if parts.scheme == "https":
        return
    if parts.scheme == "http" and allow_insecure_localhost and _is_localhost(parts.hostname):
        return
    raise RpcConfigurationError("RPC endpoint must use HTTPS")


def _post_json(endpoint: str, body: bytes, timeout: float, max_response_bytes: int) -> bytes:
    request = Request(  # noqa: S310 -- endpoint is validated before construction
        endpoint,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 -- endpoint is validated
            return cast(bytes, response.read(max_response_bytes + 1))
    except (HTTPError, URLError, OSError, TimeoutError) as exc:
        raise RpcTransportError("RPC transport request failed") from exc


def _quantity(value: object, field: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) < 3:
        raise RpcProtocolError(f"RPC {field} is not a hex quantity")
    try:
        number = int(value[2:], 16)
    except ValueError as exc:
        raise RpcProtocolError(f"RPC {field} is not a hex quantity") from exc
    if number < 0:
        raise RpcProtocolError(f"RPC {field} is negative")
    return number


def _hex_data(value: str, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"{field} must be 0x-prefixed hex")
    payload = value[2:]
    if (not payload and not allow_empty) or len(payload) % 2:
        raise ValueError(f"{field} must contain complete hex bytes")
    try:
        bytes.fromhex(payload)
    except ValueError as exc:
        raise ValueError(f"{field} must contain hex bytes") from exc
    return value.lower()


def _transaction_hash(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise RpcProtocolError(f"RPC {field} must be a transaction hash")
    try:
        normalized = _hex_data(value, field)
    except ValueError as exc:
        raise RpcProtocolError(f"RPC {field} must be a transaction hash") from exc
    if len(normalized) != 66:
        raise RpcProtocolError(f"RPC {field} must be a 32-byte hash")
    return normalized


def _object_or_none(value: JSONValue, method: str) -> JSONObject | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RpcProtocolError(f"RPC {method} result must be an object or null")
    return value


def _address(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise RpcProtocolError(f"RPC {field} must be an address")
    try:
        normalized = _hex_data(value, field)
    except ValueError as exc:
        raise RpcProtocolError(f"RPC {field} must be an address") from exc
    if len(normalized) != 42:
        raise RpcProtocolError(f"RPC {field} must be a 20-byte address")
    return normalized


def _normalized_log(
    log: object, transaction_hash: str, block_number: int, block_hash: str
) -> NormalizedLog:
    if not isinstance(log, dict):
        raise RpcProtocolError("RPC receipt log must be an object")
    address = _address(log.get("address"), "receipt log address")
    topics = log.get("topics")
    if not isinstance(topics, list):
        raise RpcProtocolError("RPC receipt log topics must be a list")
    normalized_topics = tuple(
        _transaction_hash(topic, "receipt log topic") for topic in topics
    )
    data = log.get("data")
    if not isinstance(data, str):
        raise RpcProtocolError("RPC receipt log data must be hex")
    try:
        normalized_data = _hex_data(data, "receipt log data", allow_empty=True)
    except ValueError as exc:
        raise RpcProtocolError("RPC receipt log data must be hex") from exc
    log_index = _quantity(log.get("logIndex"), "receipt log index")
    log_transaction_hash = _transaction_hash(
        log.get("transactionHash"), "receipt log transaction hash"
    )
    log_block_hash = _transaction_hash(log.get("blockHash"), "receipt log block hash")
    log_block_number = _quantity(log.get("blockNumber"), "receipt log block number")
    removed = log.get("removed")
    if not isinstance(removed, bool):
        raise RpcProtocolError("RPC receipt log removed must be a boolean")
    if (
        log_transaction_hash != transaction_hash
        or log_block_hash != block_hash
        or log_block_number != block_number
    ):
        raise NeedsReconciliationError("receipt log identity mismatch")
    return (
        address,
        normalized_topics,
        normalized_data,
        log_index,
        log_transaction_hash,
        log_block_hash,
        log_block_number,
        removed,
    )


def _normalized_receipt(
    receipt: JSONObject, transaction_hash: str
) -> NormalizedReceipt:
    receipt_transaction_hash = _transaction_hash(
        receipt.get("transactionHash"), "receipt transaction hash"
    )
    if receipt_transaction_hash != transaction_hash:
        raise NeedsReconciliationError("receipt transaction identity mismatch")
    status = _quantity(receipt.get("status"), "receipt status")
    block_number = _quantity(receipt.get("blockNumber"), "receipt block number")
    block_hash = _transaction_hash(receipt.get("blockHash"), "receipt block hash")
    logs = receipt.get("logs")
    if not isinstance(logs, list):
        raise RpcProtocolError("RPC receipt logs must be a list")
    normalized_logs = tuple(
        _normalized_log(log, transaction_hash, block_number, block_hash) for log in logs
    )
    return receipt_transaction_hash, status, block_number, block_hash, normalized_logs


@dataclass(frozen=True, slots=True)
class RpcClient:
    """Direct stdlib JSON-RPC client with strict request and reply bounds."""

    endpoint: str = field(repr=False)
    timeout: float = 15.0
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    allow_insecure_localhost: bool = False
    transport: Transport | None = None
    _next_id: int = field(default=1, repr=False, compare=False)

    def __post_init__(self) -> None:
        _validate_endpoint(self.endpoint, self.allow_insecure_localhost)
        if self.timeout <= 0 or self.max_request_bytes <= 0 or self.max_response_bytes <= 0:
            raise ValueError("RPC timeout and byte limits must be positive")

    def call(self, method: str, params: list[JSONValue]) -> JSONValue:
        if not method or not isinstance(method, str):
            raise ValueError("RPC method must be a non-empty string")
        request_id = self._next_id
        object.__setattr__(self, "_next_id", request_id + 1)
        request: dict[str, object] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        body = json.dumps(request, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(body) > self.max_request_bytes:
            raise RpcProtocolError("RPC request exceeds configured byte limit")
        raw = (
            self.transport(self.endpoint, body, self.timeout)
            if self.transport is not None
            else _post_json(self.endpoint, body, self.timeout, self.max_response_bytes)
        )
        if len(raw) > self.max_response_bytes:
            raise RpcProtocolError("RPC response exceeds configured byte limit")
        reply = _json_loads(raw)
        if not isinstance(reply, dict):
            raise RpcProtocolError("RPC response must be an object")
        allowed = {"jsonrpc", "id", "result", "error"}
        if set(reply) - allowed or reply.get("jsonrpc") != "2.0" or reply.get("id") != request_id:
            raise RpcProtocolError("RPC response schema or ID mismatch")
        has_result, has_error = "result" in reply, "error" in reply
        if has_result == has_error:
            raise RpcProtocolError("RPC response must contain exactly one result or error")
        if has_error:
            error = reply["error"]
            if not isinstance(error, dict) or set(error) - {"code", "message", "data"}:
                raise RpcProtocolError("RPC error schema is invalid")
            code, message = error.get("code"), error.get("message")
            if isinstance(code, bool) or not isinstance(code, int) or not isinstance(message, str):
                raise RpcProtocolError("RPC error schema is invalid")
            raise RpcRemoteError(code, message)
        return reply["result"]

    def chain_id(self) -> int:
        return _quantity(self.call("eth_chainId", []), "eth_chainId")

    def transaction_count(self, address: str, block: str = "pending") -> int:
        return _quantity(
            self.call("eth_getTransactionCount", [address, block]), "transaction count"
        )

    def send_raw_transaction(self, raw_transaction: str) -> str:
        raw_transaction = _hex_data(raw_transaction, "raw transaction")
        value = self.call("eth_sendRawTransaction", [raw_transaction])
        return _transaction_hash(value, "transaction hash")

    def transaction_by_hash(self, transaction_hash: str) -> JSONObject | None:
        return _object_or_none(
            self.call(
                "eth_getTransactionByHash",
                [_transaction_hash(transaction_hash, "transaction hash")],
            ),
            "eth_getTransactionByHash",
        )

    def receipt(self, transaction_hash: str) -> JSONObject | None:
        return _object_or_none(
            self.call(
                "eth_getTransactionReceipt",
                [_transaction_hash(transaction_hash, "transaction hash")],
            ),
            "eth_getTransactionReceipt",
        )

    def block_number(self) -> int:
        return _quantity(self.call("eth_blockNumber", []), "eth_blockNumber")

    def block(self, block_number: int) -> JSONObject | None:
        if isinstance(block_number, bool) or block_number < 0:
            raise ValueError("block number must be a non-negative integer")
        return _object_or_none(
            self.call("eth_getBlockByNumber", [hex(block_number), False]), "eth_getBlockByNumber"
        )


@dataclass(frozen=True, slots=True)
class RpcPool:
    """A primary RPC with an independently chain-ID-checked secondary."""

    primary: RpcClient
    secondary: RpcClient
    chain_id: int

    def __post_init__(self) -> None:
        primary_id, secondary_id = self.primary.chain_id(), self.secondary.chain_id()
        if primary_id != self.chain_id or secondary_id != self.chain_id:
            raise RpcDisagreementError("RPC chain identity disagreement")


def wait_for_final_receipt(
    rpc: RpcClient | RpcPool,
    transaction_hash: str,
    confirmations: int,
    *,
    poll_interval: float = 1.0,
    sleep: Sleep = time.sleep,
    max_polls: int | None = None,
) -> JSONObject:
    """Wait for a successful receipt and prove it remains in its canonical block."""

    if isinstance(confirmations, bool) or confirmations < 0:
        raise ValueError("confirmations must be a non-negative integer")
    if poll_interval < 0 or (max_polls is not None and max_polls <= 0):
        raise ValueError("poll interval must be non-negative and max polls positive")
    transaction_hash = _transaction_hash(transaction_hash, "transaction hash")
    primary = rpc.primary if isinstance(rpc, RpcPool) else rpc
    polls = 0
    while True:
        receipt = primary.receipt(transaction_hash)
        polls += 1
        if receipt is not None:
            break
        if max_polls is not None and polls >= max_polls:
            raise NeedsReconciliationError("receipt was not observed before poll limit")
        sleep(poll_interval)

    initial_receipt = _normalized_receipt(receipt, transaction_hash)
    initial_identity = initial_receipt[:4]
    _, status, block_number, block_hash = initial_identity

    while True:
        head = primary.block_number()
        if head - block_number >= confirmations:
            break
        # A head before a receipt's block cannot be resolved by additional local polling.
        if head < block_number:
            raise NeedsReconciliationError("RPC head precedes receipt block")
        polls += 1
        if max_polls is not None and polls >= max_polls:
            raise NeedsReconciliationError("receipt did not reach configured finality")
        sleep(poll_interval)

    refreshed = primary.receipt(transaction_hash)
    if refreshed is None:
        raise ReorgDetectedError("receipt disappeared during finality check")
    refreshed_receipt = _normalized_receipt(refreshed, transaction_hash)
    refreshed_identity = refreshed_receipt[:4]
    if refreshed_identity[1] != status:
        raise NeedsReconciliationError("receipt status changed during finality check")
    if refreshed_receipt != initial_receipt:
        raise ReorgDetectedError("receipt changed during finality check")
    canonical_block = primary.block(block_number)
    if canonical_block is None or not isinstance(canonical_block.get("hash"), str):
        raise NeedsReconciliationError("canonical block was unavailable")
    if _transaction_hash(cast(str, canonical_block["hash"]), "canonical block hash") != block_hash:
        raise ReorgDetectedError("receipt block is no longer canonical")
    if isinstance(rpc, RpcPool):
        secondary_head = rpc.secondary.block_number()
        if secondary_head - block_number < confirmations:
            raise RpcDisagreementError("secondary RPC has insufficient confirmation depth")
        secondary_receipt = rpc.secondary.receipt(transaction_hash)
        if secondary_receipt is None:
            raise RpcDisagreementError("secondary RPC did not observe receipt")
        if _normalized_receipt(secondary_receipt, transaction_hash) != refreshed_receipt:
            raise RpcDisagreementError("RPC receipt disagreement")
        secondary_block = rpc.secondary.block(block_number)
        if secondary_block is None or not isinstance(secondary_block.get("hash"), str):
            raise RpcDisagreementError("secondary RPC canonical block was unavailable")
        if (
            _transaction_hash(cast(str, secondary_block["hash"]), "canonical block hash")
            != block_hash
        ):
            raise RpcDisagreementError("RPC canonical block disagreement")
    if status != 1:
        raise TransactionFailedError(refreshed)
    return refreshed
