"""Fail-closed native-EVM quote validation for deBridge DLN.

This boundary deliberately owns neither signing nor broadcasting.  Its only
effects are calls to explicitly-injected transports; it has no route defaults.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import Protocol
from urllib.parse import urlencode, urlsplit

from eth_hash.auto import keccak

from agent_bridge_guard.models import Plan

NATIVE_TOKEN = "0x0000000000000000000000000000000000000000"  # noqa: S105
STRICT_SWAP_AND_CALL_SELECTOR = "0x4d8160ba"
CREATE_SALTED_ORDER_SELECTOR = "0xb9303701"
FULFILLED_ORDER_TOPIC = "0xc164aca37b9805a1c9027b6f32260a069723a82926f6e9ece4926e4dd3ea8ecf"
NATIVE_IN_SWAP_DLN_NATIVE_OUT = "native_in_swap_dln_native_out"
RESERVE_ERC20_DLN_NATIVE_OUT = "reserve_erc20_dln_native_out"
SENT_ORDER_CANCEL_EVENT = "SentOrderCancel"
CLAIMED_ORDER_CANCEL_EVENT = "ClaimedOrderCancel"
MAX_RESPONSE_BYTES = 1_000_000
MAX_FUTURE_QUOTE_SKEW_SECONDS = 5
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX_RE = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")
HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


class HttpJson(Protocol):
    """Transport that must validate TLS before returning decoded JSON."""

    def __call__(self, url: str) -> object: ...


class Rpc(Protocol):
    """Optional read-only RPC transport owned by the application layer."""

    def __call__(self, method: str, params: Sequence[object]) -> object: ...


def _rpc_quantity(value: object, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
        raise ValueError(f"{label} RPC result is not a quantity")
    return int(value, 16)


def _rpc_call(
    rpc: Rpc,
    *,
    signer: str,
    bridge_router: str,
    value_wei: int,
    data: str,
    source_swap_router: str,
) -> int:
    router_query = (
        "0x"
        + (
            keccak(b"supportedRouters(address)")[:4]
            + bytes(12)
            + bytes.fromhex(source_swap_router[2:])
        ).hex()
    )
    supported = rpc("eth_call", [{"to": bridge_router, "data": router_query}, "latest"])
    if _rpc_quantity(supported, "supportedRouters") != 1:
        raise ValueError("source swap router is not supported by bridge router")
    transaction = {
        "from": signer,
        "to": bridge_router,
        "value": hex(value_wei),
        "data": data,
    }
    # A revert is an exception from the injected transport.  Any malformed result
    # also fails closed instead of being interpreted as a successful simulation.
    result = rpc("eth_call", [transaction, "latest"])
    if not isinstance(result, str) or not HEX_RE.fullmatch(result):
        raise ValueError("exact transaction simulation returned malformed data")
    gas = _rpc_quantity(rpc("eth_estimateGas", [transaction]), "gas estimate")
    if gas <= 0:
        raise ValueError("gas estimate must be positive")
    return gas


def preflight_source_transaction(
    primary_rpc: Rpc,
    secondary_rpc: Rpc,
    *,
    signer: str,
    bridge_router: str,
    value_wei: int,
    data: str,
    source_swap_router: str,
    nonce: int,
    maximum_gas: int,
    required_total_spend_wei: int,
) -> dict[str, int]:
    """Prove exact source call is currently executable on two independent RPCs.

    This is deliberately separate from quote validation so callers can run it
    immediately before signing and again before first broadcast.  It has no
    side effects and fails if either injected RPC disagrees, reverts, reports an
    unsupported router, or reports insufficient balance.
    """
    signer = canonical_address(signer, "signer")
    bridge_router = canonical_address(bridge_router, "bridge router")
    source_swap_router = canonical_address(source_swap_router, "source swap router")
    if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0:
        raise ValueError("source nonce must be a non-negative integer")
    if value_wei <= 0 or maximum_gas <= 0 or required_total_spend_wei < value_wei:
        raise ValueError("source preflight limits are invalid")
    _hex(data, "transaction calldata", required=True)
    primary_latest = _rpc_quantity(
        primary_rpc("eth_getTransactionCount", [signer, "latest"]),
        "primary latest nonce",
    )
    primary_pending = _rpc_quantity(
        primary_rpc("eth_getTransactionCount", [signer, "pending"]),
        "primary pending nonce",
    )
    secondary_latest = _rpc_quantity(
        secondary_rpc("eth_getTransactionCount", [signer, "latest"]),
        "secondary latest nonce",
    )
    secondary_pending = _rpc_quantity(
        secondary_rpc("eth_getTransactionCount", [signer, "pending"]),
        "secondary pending nonce",
    )
    counts = {
        primary_latest,
        primary_pending,
        secondary_latest,
        secondary_pending,
    }
    if len(counts) != 1:
        raise ValueError("source nonce counts disagree")
    if counts != {nonce}:
        raise ValueError("source nonce does not match planned nonce")
    primary_gas = _rpc_call(
        primary_rpc,
        signer=signer,
        bridge_router=bridge_router,
        value_wei=value_wei,
        data=data,
        source_swap_router=source_swap_router,
    )
    secondary_gas = _rpc_call(
        secondary_rpc,
        signer=signer,
        bridge_router=bridge_router,
        value_wei=value_wei,
        data=data,
        source_swap_router=source_swap_router,
    )
    if primary_gas != secondary_gas:
        raise ValueError("source gas estimates disagree")
    if primary_gas > maximum_gas:
        raise ValueError("source gas estimate exceeds signed gas limit")
    primary_balance = _rpc_quantity(
        primary_rpc("eth_getBalance", [signer, "latest"]), "primary balance"
    )
    secondary_balance = _rpc_quantity(
        secondary_rpc("eth_getBalance", [signer, "latest"]), "secondary balance"
    )
    if primary_balance < required_total_spend_wei or secondary_balance < required_total_spend_wei:
        raise ValueError("source balance cannot cover exact value plus bounded gas")
    return {
        "gas": primary_gas,
        "nonce": nonce,
        "primary_balance_wei": primary_balance,
        "secondary_balance_wei": secondary_balance,
        "required_total_spend_wei": required_total_spend_wei,
    }


EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


def _abi_call(selector: bytes, *words: bytes) -> str:
    return "0x" + (selector + b"".join(words)).hex()


def _rpc_exact_direct_call(
    rpc: Rpc,
    *,
    signer: str,
    dln_proxy: str,
    reserve_token: str,
    amount_wei: int,
    fixed_fee_wei: int,
    data: str,
) -> tuple[int, int, int, int, str, int]:
    balance_query = _abi_call(
        keccak(b"balanceOf(address)")[:4], bytes(12) + bytes.fromhex(signer[2:])
    )
    allowance_query = _abi_call(
        keccak(b"allowance(address,address)")[:4],
        bytes(12) + bytes.fromhex(signer[2:]),
        bytes(12) + bytes.fromhex(dln_proxy[2:]),
    )
    fixed_fee_query = "0x" + keccak(b"globalFixedNativeFee()")[:4].hex()
    transfer_fee_query = "0x" + keccak(b"globalTransferFeeBps()")[:4].hex()
    balance = _rpc_quantity(
        rpc("eth_call", [{"to": reserve_token, "data": balance_query}, "latest"]),
        "reserve token balance",
    )
    allowance = _rpc_quantity(
        rpc("eth_call", [{"to": reserve_token, "data": allowance_query}, "latest"]),
        "reserve token allowance",
    )
    fixed_fee = _rpc_quantity(
        rpc("eth_call", [{"to": dln_proxy, "data": fixed_fee_query}, "latest"]),
        "global fixed native fee",
    )
    transfer_fee = _rpc_quantity(
        rpc("eth_call", [{"to": dln_proxy, "data": transfer_fee_query}, "latest"]),
        "global transfer fee",
    )
    transaction = {"from": signer, "to": dln_proxy, "value": hex(fixed_fee_wei), "data": data}
    result = rpc("eth_call", [transaction, "latest"])
    if not isinstance(result, str) or not HEX_RE.fullmatch(result):
        raise ValueError("exact transaction simulation returned malformed data")
    gas = _rpc_quantity(rpc("eth_estimateGas", [transaction]), "gas estimate")
    slot = rpc("eth_getStorageAt", [dln_proxy, EIP1967_IMPLEMENTATION_SLOT, "latest"])
    if not isinstance(slot, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", slot):
        raise ValueError("DLN implementation slot is malformed")
    implementation = "0x" + slot[-40:]
    code = rpc("eth_getCode", [implementation, "latest"])
    if not isinstance(code, str) or not HEX_RE.fullmatch(code) or code == "0x":
        raise ValueError("DLN implementation code is unavailable")
    return (
        balance,
        allowance,
        fixed_fee,
        transfer_fee,
        "0x" + keccak(bytes.fromhex(code[2:])).hex(),
        gas,
    )


def preflight_reserve_erc20_source_transaction(
    primary_rpc: Rpc,
    secondary_rpc: Rpc,
    *,
    signer: str,
    dln_proxy: str,
    reserve_token: str,
    amount_wei: int,
    fixed_fee_wei: int,
    data: str,
    nonce: int,
    maximum_gas: int,
    required_native_spend_wei: int,
    expected_implementation_codehash: str,
    expected_global_transfer_fee_bps: int,
) -> dict[str, int | str]:
    """Prove a direct reserve-ERC20 DLN call with two-RPC exact agreement."""
    signer = canonical_address(signer, "signer")
    dln_proxy = canonical_address(dln_proxy, "source DLN proxy")
    reserve_token = canonical_address(reserve_token, "source reserve token")
    if (
        amount_wei <= 0
        or fixed_fee_wei < 0
        or maximum_gas <= 0
        or required_native_spend_wei < fixed_fee_wei
    ):
        raise ValueError("direct source preflight limits are invalid")
    if not HASH_RE.fullmatch(expected_implementation_codehash):
        raise ValueError("expected DLN implementation codehash is invalid")
    counts = {
        _rpc_quantity(
            primary_rpc("eth_getTransactionCount", [signer, "latest"]), "primary latest nonce"
        ),
        _rpc_quantity(
            primary_rpc("eth_getTransactionCount", [signer, "pending"]), "primary pending nonce"
        ),
        _rpc_quantity(
            secondary_rpc("eth_getTransactionCount", [signer, "latest"]), "secondary latest nonce"
        ),
        _rpc_quantity(
            secondary_rpc("eth_getTransactionCount", [signer, "pending"]), "secondary pending nonce"
        ),
    }
    if counts != {nonce}:
        raise ValueError("source nonce counts disagree or do not match planned nonce")
    primary = _rpc_exact_direct_call(
        primary_rpc,
        signer=signer,
        dln_proxy=dln_proxy,
        reserve_token=reserve_token,
        amount_wei=amount_wei,
        fixed_fee_wei=fixed_fee_wei,
        data=data,
    )
    secondary = _rpc_exact_direct_call(
        secondary_rpc,
        signer=signer,
        dln_proxy=dln_proxy,
        reserve_token=reserve_token,
        amount_wei=amount_wei,
        fixed_fee_wei=fixed_fee_wei,
        data=data,
    )
    if primary != secondary:
        raise ValueError("direct source RPC evidence disagrees")
    balance, allowance, observed_fee, transfer_fee, codehash, gas = primary
    if allowance != amount_wei:
        raise ValueError(
            "reserve token allowance must equal the exact requested amount; approval is required"
        )
    if balance < amount_wei:
        raise ValueError("reserve token balance cannot cover exact requested amount")
    if observed_fee != fixed_fee_wei:
        raise ValueError("global fixed native fee does not match transaction value")
    if transfer_fee != expected_global_transfer_fee_bps:
        raise ValueError("global transfer fee differs from pinned policy")
    if codehash.lower() != expected_implementation_codehash.lower():
        raise ValueError("DLN implementation codehash differs from pinned policy")
    if gas <= 0 or gas > maximum_gas:
        raise ValueError("direct source gas estimate exceeds signed gas limit")
    balances = {
        _rpc_quantity(primary_rpc("eth_getBalance", [signer, "latest"]), "primary native balance"),
        _rpc_quantity(
            secondary_rpc("eth_getBalance", [signer, "latest"]), "secondary native balance"
        ),
    }
    if len(balances) != 1 or next(iter(balances)) < required_native_spend_wei:
        raise ValueError("native balance cannot cover exact fee plus bounded gas")
    return {
        "gas": gas,
        "nonce": nonce,
        "reserve_balance_wei": balance,
        "allowance_wei": allowance,
        "fixed_native_fee_wei": observed_fee,
        "global_transfer_fee_bps": transfer_fee,
        "implementation_codehash": codehash,
    }


@dataclass(frozen=True, slots=True)
class QuoteRequest:
    source_chain_id: int
    destination_chain_id: int
    amount_wei: int
    minimum_output_wei: int
    signer: str
    recipient: str
    nonce: int
    created_at: str
    expires_at: str


@dataclass(frozen=True, slots=True)
class RoutePolicy:
    """All values are route-specific and must be supplied by the caller."""

    allowed_bridge_routers: tuple[str, ...]
    allowed_source_swap_routers: tuple[str, ...]
    allowed_source_swap_selectors: tuple[str, ...]
    allowed_intermediary_give_tokens: tuple[str, ...]
    allowed_dln_sources: tuple[str, ...]
    allowed_refund_recipients: tuple[str, ...]
    destination_dln_proxy: str
    destination_fulfillment_topic: str
    maximum_total_spend_wei: int
    maximum_value_overhead_wei: int
    maximum_price_impact_bps: int
    maximum_swap_calldata_bytes: int
    maximum_metadata_bytes: int
    route_id: str
    route_kind: str = NATIVE_IN_SWAP_DLN_NATIVE_OUT
    maximum_quote_age_seconds: int | None = None
    maximum_plan_lifetime_seconds: int = 120
    source_reserve_token: str | None = None
    source_dln_proxy: str | None = None
    source_dln_implementation_codehash: str | None = None
    allowed_takers: tuple[str, ...] = ()
    maximum_fixed_native_fee_wei: int = 0
    maximum_input_token_amount: int = 0
    maximum_gas_limit: int = 0
    expected_global_transfer_fee_bps: int | None = None


def _validate_direct_semantics(
    decoded: Mapping[str, object], request: QuoteRequest, policy: RoutePolicy, source_token: str
) -> dict[str, object]:
    if policy.source_dln_proxy is None or policy.source_reserve_token is None:
        raise ValueError("direct route policy is incomplete")
    signer = canonical_address(request.signer, "signer")
    recipient = canonical_address(request.recipient, "recipient")
    order = _object(decoded["order"], "createSaltedOrder order")
    if decoded["affiliate_fee"] != b"" or decoded["permit"] != b"":
        raise ValueError("affiliate fees and permits are not allowed")
    if _integer(decoded["referral_code"], "referral code") != 0:
        raise ValueError("referral code is not allowed")
    metadata = decoded["metadata"]
    if not isinstance(metadata, bytes) or len(metadata) > policy.maximum_metadata_bytes:
        raise ValueError("metadata exceeds policy size")
    if canonical_address(order["give_token"], "order give token") != source_token:
        raise ValueError("order give token does not match source reserve token")
    if canonical_address(order["give_authority"], "give authority") != signer:
        raise ValueError("source authority mismatch")
    if _integer(order["take_chain_id"], "take chain") != request.destination_chain_id:
        raise ValueError("destination chain mismatch")
    if _bytes_address(order["take_token"], "take token") != NATIVE_TOKEN:
        raise ValueError("destination token is not native")
    if _bytes_address(order["receiver"], "receiver") != recipient:
        raise ValueError("destination receiver mismatch")
    if _bytes_address(order["take_authority"], "take authority") != recipient:
        raise ValueError("destination authority mismatch")
    if _integer(order["take_amount"], "take amount") < request.minimum_output_wei:
        raise ValueError("destination amount below minimum")
    if order["external_call"] != b"":
        raise ValueError("external calls are not allowed")
    if order["cancel_beneficiary"] not in (b"", bytes.fromhex(signer[2:])):
        raise ValueError("cancel beneficiary mismatch")
    allowed_taker = order["allowed_taker"]
    if not isinstance(allowed_taker, bytes):
        raise ValueError("allowed taker is invalid")
    normalized_taker = _bytes_address(allowed_taker, "allowed taker") if allowed_taker else None
    if normalized_taker is None or normalized_taker not in _allowlist(
        policy.allowed_takers, "allowed taker"
    ):
        raise ValueError("allowed taker is not allowlisted")
    give_amount = _integer(order["give_amount"], "order give amount", positive=True)
    if give_amount != request.amount_wei:
        raise ValueError("order give amount does not match exact reserve input")
    return {
        "source_dln_target": canonical_address(policy.source_dln_proxy, "source DLN proxy"),
        "source_order_token": source_token,
        "source_gross_amount_wei": give_amount,
        "source_swap_router": source_token,
        "source_swap_selector": CREATE_SALTED_ORDER_SELECTOR,
        "source_swap_calldata_sha256": sha256(b"").hexdigest(),
        "source_swap_calldata_length": 0,
        "metadata_sha256": sha256(metadata).hexdigest(),
        "metadata_length": len(metadata),
        "destination_amount_wei": _integer(order["take_amount"], "take amount"),
        "destination_receiver": recipient,
        "allowed_taker": normalized_taker,
        "external_call": False,
    }


def _validate_direct_quote(
    response: object, request: QuoteRequest, policy: RoutePolicy, now: datetime
) -> dict[str, object]:
    if (
        policy.source_reserve_token is None
        or policy.source_dln_proxy is None
        or policy.expected_global_transfer_fee_bps is None
    ):
        raise ValueError("direct route policy is incomplete")
    if request.amount_wei <= 0 or request.minimum_output_wei <= 0:
        raise ValueError("amounts must be positive")
    if request.amount_wei > policy.maximum_input_token_amount:
        raise ValueError("source input amount exceeds policy")
    if request.nonce < 0:
        raise ValueError("nonce must be non-negative")
    created_at = _utc_timestamp(request.created_at, "created_at")
    expires_at = _utc_timestamp(request.expires_at, "expires_at")
    if expires_at <= created_at:
        raise ValueError("expires_at must be after created_at")
    if (
        policy.maximum_plan_lifetime_seconds <= 0
        or (expires_at - created_at).total_seconds() > policy.maximum_plan_lifetime_seconds
    ):
        raise ValueError("plan lifetime exceeds policy")
    body = _response_object(response)
    _validate_freshness(
        body, policy, now, request_created_at=created_at
    )
    estimation = _object(body.get("estimation"), "estimation")
    if "srcChainTokenOut" in estimation:
        raise ValueError("direct route must not include a source swap output")
    source = _object(estimation.get("srcChainTokenIn"), "source estimation")
    destination = _object(estimation.get("dstChainTokenOut"), "destination estimation")
    source_token = canonical_address(source.get("address"), "source reserve token")
    if source_token != canonical_address(policy.source_reserve_token, "source reserve token"):
        raise ValueError("source reserve token is not pinned")
    if _integer(source.get("chainId"), "source chain") != request.source_chain_id:
        raise ValueError("source chain mismatch")
    if _integer(source.get("amount"), "source amount") != request.amount_wei:
        raise ValueError("source amount mismatch")
    if _integer(destination.get("chainId"), "destination chain") != request.destination_chain_id:
        raise ValueError("destination chain mismatch")
    if canonical_address(destination.get("address"), "destination token") != NATIVE_TOKEN:
        raise ValueError("destination token is not native")
    output = _integer(destination.get("recommendedAmount"), "destination amount", positive=True)
    if output < request.minimum_output_wei:
        raise ValueError("destination amount below minimum")
    try:
        impact_bps = abs(Decimal(str(body.get("usdPriceImpact"))) * 100)
    except (InvalidOperation, ValueError) as error:
        raise ValueError("invalid price impact") from error
    if not impact_bps.is_finite() or impact_bps > policy.maximum_price_impact_bps:
        raise ValueError("price impact exceeds policy")
    transaction = _object(body.get("tx"), "transaction")
    bridge_router = canonical_address(transaction.get("to"), "source DLN proxy")
    if bridge_router != canonical_address(policy.source_dln_proxy, "source DLN proxy"):
        raise ValueError("source DLN proxy is not pinned")
    value = _integer(transaction.get("value"), "transaction value")
    if value > policy.maximum_fixed_native_fee_wei:
        raise ValueError("fixed native fee exceeds policy")
    if "fixFee" in body and _integer(body.get("fixFee"), "fixed fee") != value:
        raise ValueError("transaction value does not match fixed fee")
    calldata = transaction.get("data")
    if not isinstance(calldata, str):
        raise ValueError("transaction calldata must be a string")
    decoded = decode_create_salted_order(calldata)
    semantic = _validate_direct_semantics(decoded, request, policy, source_token)
    protocol_fee = _integer(body.get("protocolFee"), "protocol fee")
    if protocol_fee <= 0 or protocol_fee >= request.amount_wei:
        raise ValueError("protocol fee leaves no source order amount")
    expected_protocol_fee = (
        request.amount_wei * policy.expected_global_transfer_fee_bps // 10_000
    )
    if protocol_fee != expected_protocol_fee:
        raise ValueError("protocol fee differs from pinned global transfer fee")
    source_net_amount = request.amount_wei - protocol_fee
    semantic["source_net_amount_wei"] = source_net_amount
    response_order = _object(body.get("order"), "quote order")
    if _hex(response_order.get("metadata"), "quote order metadata") != decoded["metadata"]:
        raise ValueError("quote order metadata does not match calldata")
    order = _object(decoded["order"], "order")
    order_id = deterministic_order_id(
        {
            **order,
            "give_chain_id": request.source_chain_id,
            "give_amount": source_net_amount,
        },
        maker=request.signer,
    )
    quoted_order_id = body.get("orderId")
    if not isinstance(quoted_order_id, str) or quoted_order_id.lower() != order_id:
        raise ValueError("quote order ID mismatch")
    gas_details = _object(
        _object(body.get("estimatedTransactionFee"), "gas estimate").get("details"), "gas details"
    )
    gas = _integer(transaction.get("gasLimit"), "transaction gas limit", positive=True)
    bounded_gas = _integer(gas_details.get("gasLimit"), "gas limit", positive=True)
    max_fee = _integer(gas_details.get("maxFeePerGas"), "max fee", positive=True)
    priority_fee = _integer(gas_details.get("maxPriorityFeePerGas"), "priority fee")
    if gas > bounded_gas or gas > policy.maximum_gas_limit or priority_fee > max_fee:
        raise ValueError("gas details are invalid")
    total_spend = value + gas * max_fee
    if total_spend > policy.maximum_total_spend_wei:
        raise ValueError("total spend exceeds policy")
    return {
        "bridge_router": bridge_router,
        "data": calldata,
        "value_wei": value,
        "total_spend_wei": total_spend,
        "gas": gas,
        "bounded_gas": bounded_gas,
        "max_fee_per_gas": max_fee,
        "max_priority_fee_per_gas": priority_fee,
        "output_wei": output,
        "price_impact_bps": int(impact_bps),
        "order_id": order_id,
        "fix_fee_amount_wei": value,
        "protocol_fee_amount_wei": protocol_fee,
        **semantic,
    }


def canonical_address(value: object, label: str = "address") -> str:
    if not isinstance(value, str) or not ADDRESS_RE.fullmatch(value):
        raise ValueError(f"{label} must be a 20-byte EVM address")
    return value.lower()


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _integer(value: object, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{label} must be an integer")
    try:
        result = int(value)
    except ValueError as error:
        raise ValueError(f"{label} must be an integer") from error
    if result < 0 or positive and result == 0:
        raise ValueError(f"{label} is out of range")
    return result


def _hex(value: object, label: str, *, required: bool = False) -> bytes:
    if not isinstance(value, str) or not HEX_RE.fullmatch(value):
        raise ValueError(f"{label} must be canonical hex")
    raw = bytes.fromhex(value[2:])
    if required and not raw:
        raise ValueError(f"{label} must not be empty")
    return raw


def _selector(value: object, label: str) -> str:
    raw = _hex(value, label, required=True)
    if len(raw) != 4:
        raise ValueError(f"{label} must be a 4-byte selector")
    return "0x" + raw.hex()


def _response_object(value: object) -> Mapping[str, object]:
    """Validate JSON shape and size before accessing a provider response."""
    try:
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError) as error:
        raise ValueError("provider response is not strict JSON") from error
    if len(encoded.encode()) > MAX_RESPONSE_BYTES:
        raise ValueError("provider response exceeds size limit")
    return _object(value, "provider response")


def _word(data: bytes, offset: int, label: str) -> int:
    if offset < 0 or offset + 32 > len(data):
        raise ValueError(f"{label} is truncated")
    return int.from_bytes(data[offset : offset + 32], "big")


def _dynamic(data: bytes, base: int, offset: int, label: str) -> bytes:
    if offset % 32:
        raise ValueError(f"{label} has unaligned offset")
    start = base + offset
    size = _word(data, start, label)
    end = start + 32 + size
    padded_end = start + 32 + ((size + 31) // 32) * 32
    if end > len(data) or padded_end > len(data):
        raise ValueError(f"{label} is truncated")
    if any(data[end:padded_end]):
        raise ValueError(f"{label} has non-zero ABI padding")
    return data[start + 32 : end]


def _abi_address(word: int, label: str) -> str:
    if word >> 160:
        raise ValueError(f"{label} address padding is non-zero")
    return "0x" + word.to_bytes(32, "big")[-20:].hex()


def _bytes_address(raw: object, label: str) -> str:
    if not isinstance(raw, bytes) or len(raw) != 20:
        raise ValueError(f"{label} must encode a 20-byte address")
    return "0x" + raw.hex()


def _decode_fulfilled_order_tuple(data: bytes, base: int) -> dict[str, object]:
    if base < 0 or base + 14 * 32 > len(data):
        raise ValueError("fulfilled order tuple is truncated")

    def word(index: int) -> int:
        return _word(data, base + index * 32, "fulfilled order tuple")

    return {
        "salt": word(0),
        "maker": _dynamic(data, base, word(1), "maker"),
        "give_chain_id": word(2),
        "give_token": _dynamic(data, base, word(3), "give token"),
        "give_amount": word(4),
        "take_chain_id": word(5),
        "take_token": _dynamic(data, base, word(6), "take token"),
        "take_amount": word(7),
        "receiver": _dynamic(data, base, word(8), "receiver"),
        "give_authority": _dynamic(data, base, word(9), "give authority"),
        "take_authority": _dynamic(data, base, word(10), "take authority"),
        "allowed_taker": _dynamic(data, base, word(11), "allowed taker"),
        "cancel_beneficiary": _dynamic(data, base, word(12), "cancel beneficiary"),
        "external_call": _dynamic(data, base, word(13), "external call"),
    }


def _decode_order_creation(data: bytes, base: int, salt: int) -> dict[str, object]:
    if base < 0 or base + 11 * 32 > len(data):
        raise ValueError("order creation tuple is truncated")

    def word(index: int) -> int:
        return _word(data, base + index * 32, "order creation tuple")

    return {
        "salt": salt,
        "give_token": _abi_address(word(0), "give token"),
        "give_amount": word(1),
        "take_token": _dynamic(data, base, word(2), "take token"),
        "take_amount": word(3),
        "take_chain_id": word(4),
        "receiver": _dynamic(data, base, word(5), "receiver"),
        "give_authority": _abi_address(word(6), "give authority"),
        "take_authority": _dynamic(data, base, word(7), "take authority"),
        "allowed_taker": _dynamic(data, base, word(8), "allowed taker"),
        "external_call": _dynamic(data, base, word(9), "external call"),
        "cancel_beneficiary": _dynamic(data, base, word(10), "cancel beneficiary"),
    }


def decode_create_salted_order(calldata: str) -> dict[str, object]:
    raw = _hex(calldata, "createSaltedOrder calldata", required=True)
    if raw[:4].hex() != CREATE_SALTED_ORDER_SELECTOR[2:]:
        raise ValueError("unsupported createSaltedOrder selector")
    body = raw[4:]
    if len(body) < 6 * 32:
        raise ValueError("createSaltedOrder calldata is truncated")
    order_offset = _word(body, 0, "order offset")
    if order_offset % 32:
        raise ValueError("order offset is unaligned")
    return {
        "order": _decode_order_creation(body, order_offset, _word(body, 32, "salt")),
        "affiliate_fee": _dynamic(body, 0, _word(body, 64, "affiliate fee"), "affiliate fee"),
        "referral_code": _word(body, 96, "referral code"),
        "permit": _dynamic(body, 0, _word(body, 128, "permit"), "permit"),
        "metadata": _dynamic(body, 0, _word(body, 160, "metadata"), "metadata"),
    }


def decode_strictly_swap_and_call(calldata: str) -> dict[str, object]:
    raw = _hex(calldata, "quote calldata", required=True)
    if raw[:4].hex() != STRICT_SWAP_AND_CALL_SELECTOR[2:]:
        raise ValueError("unsupported strictlySwapAndCall selector")
    body = raw[4:]
    if len(body) < 10 * 32:
        raise ValueError("strictlySwapAndCall calldata is truncated")

    def word(index: int) -> int:
        return _word(body, index * 32, "strictlySwapAndCall")

    target_data = _dynamic(body, 0, word(9), "target calldata")
    return {
        "swap_token_in": _abi_address(word(0), "swap input token"),
        "swap_amount_in": word(1),
        "swap_permit": _dynamic(body, 0, word(2), "swap permit"),
        "source_swap_router": _abi_address(word(3), "source swap router"),
        "swap_calldata": _dynamic(body, 0, word(4), "swap calldata"),
        "swap_token_out": _abi_address(word(5), "swap output token"),
        "swap_minimum_amount_out": word(6),
        "refund_recipient": _abi_address(word(7), "refund recipient"),
        "dln_source": _abi_address(word(8), "DLN source"),
        "create_salted_order": decode_create_salted_order("0x" + target_data.hex()),
    }


def deterministic_order_id(order: Mapping[str, object], *, maker: str) -> str:
    """Compute DLN packed-order id after proving external calls are absent."""
    fields = (
        "salt",
        "give_chain_id",
        "give_token",
        "give_amount",
        "take_chain_id",
        "take_token",
        "take_amount",
        "receiver",
        "give_authority",
        "take_authority",
        "allowed_taker",
        "cancel_beneficiary",
        "external_call",
    )
    if any(field not in order for field in fields):
        raise ValueError("order is incomplete")
    if order["external_call"] != b"":
        raise ValueError("external calls are not allowed")

    def uint(value: object, width: int, label: str) -> bytes:
        number = _integer(value, label)
        if number >= 1 << width * 8:
            raise ValueError(f"{label} overflows")
        return number.to_bytes(width, "big")

    def sized(value: object, label: str) -> bytes:
        if not isinstance(value, bytes) or len(value) > 255:
            raise ValueError(f"{label} is invalid")
        return bytes([len(value)]) + value

    def address_bytes(value: object, label: str) -> bytes:
        return bytes.fromhex(canonical_address(value, label)[2:])

    packed = b"".join(
        (
            uint(order["salt"], 8, "salt"),
            sized(address_bytes(maker, "maker"), "maker"),
            uint(order["give_chain_id"], 32, "give chain"),
            sized(address_bytes(order["give_token"], "give token"), "give token"),
            uint(order["give_amount"], 32, "give amount"),
            uint(order["take_chain_id"], 32, "take chain"),
            sized(order["take_token"], "take token"),
            uint(order["take_amount"], 32, "take amount"),
            sized(order["receiver"], "receiver"),
            sized(address_bytes(order["give_authority"], "give authority"), "give authority"),
            sized(order["take_authority"], "take authority"),
            sized(order["allowed_taker"], "allowed taker"),
            sized(order["cancel_beneficiary"], "cancel beneficiary"),
            b"\x00",
        )
    )
    return "0x" + keccak(packed).hex()


def _allowlist(values: Sequence[str], label: str) -> set[str]:
    addresses = {canonical_address(value, label) for value in values}
    if not addresses:
        raise ValueError(f"{label} allowlist is empty")
    return addresses


def _quote_timestamp(body: Mapping[str, object]) -> float | None:
    values = [body[key] for key in ("createdAt", "created_at") if key in body]
    if not values:
        return None
    value = values[0]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError as error:
            raise ValueError("quote timestamp is invalid") from error
    raise ValueError("quote timestamp is invalid")


def _utc_timestamp(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} is invalid") from error
    if parsed.tzinfo != UTC:
        raise ValueError(f"{label} must be UTC")
    return parsed


def _validate_freshness(
    body: Mapping[str, object],
    policy: RoutePolicy,
    now: datetime,
    *,
    request_created_at: datetime,
) -> None:
    expiry = next(
        (body[key] for key in ("expiresAt", "expires_at", "expiration") if key in body), None
    )
    if expiry is not None:
        expiry_at = _quote_timestamp({"createdAt": expiry})
        if expiry_at is None:
            raise ValueError("quote expiry is invalid")
        if expiry_at <= now.timestamp():
            raise ValueError("quote is expired")
    if policy.maximum_quote_age_seconds is not None:
        if policy.maximum_quote_age_seconds < 0:
            raise ValueError("maximum quote age is invalid")
        timestamp_keys = tuple(key for key in ("createdAt", "created_at") if key in body)
        if len(timestamp_keys) > 1:
            raise ValueError("quote must not have ambiguous created timestamps")
        created = _quote_timestamp(body) if timestamp_keys else request_created_at.timestamp()
        if created is None:
            raise ValueError("quote timestamp is invalid")
        if created - now.timestamp() > MAX_FUTURE_QUOTE_SKEW_SECONDS:
            raise ValueError("quote timestamp is too far in the future")
        if now.timestamp() - created > policy.maximum_quote_age_seconds:
            raise ValueError("quote is stale")


def _validate_semantics(
    decoded: Mapping[str, object], request: QuoteRequest, policy: RoutePolicy
) -> dict[str, object]:
    if policy.route_kind != NATIVE_IN_SWAP_DLN_NATIVE_OUT:
        raise ValueError("route kind is unsupported")
    signer = canonical_address(request.signer, "signer")
    recipient = canonical_address(request.recipient, "recipient")
    if canonical_address(decoded["refund_recipient"], "refund recipient") not in _allowlist(
        policy.allowed_refund_recipients, "refund recipient"
    ):
        raise ValueError("refund recipient is not allowlisted")
    if canonical_address(decoded["dln_source"], "DLN source") not in _allowlist(
        policy.allowed_dln_sources, "DLN source"
    ):
        raise ValueError("DLN source is not allowlisted")
    if canonical_address(decoded["source_swap_router"], "source swap router") not in _allowlist(
        policy.allowed_source_swap_routers, "source swap router"
    ):
        raise ValueError("source swap router is not allowlisted")
    if canonical_address(decoded["swap_token_in"], "swap input token") != NATIVE_TOKEN:
        raise ValueError("swap input is not native")
    if _integer(decoded["swap_amount_in"], "swap input") != request.amount_wei:
        raise ValueError("swap input amount mismatch")
    if decoded["swap_permit"] != b"":
        raise ValueError("swap permit is not allowed")
    swap_calldata = decoded["swap_calldata"]
    if not isinstance(swap_calldata, bytes):
        raise ValueError("swap calldata is invalid")
    if not swap_calldata:
        raise ValueError("swap calldata must not be empty")
    if len(swap_calldata) > policy.maximum_swap_calldata_bytes:
        raise ValueError("swap calldata exceeds policy size")
    swap_selector = "0x" + swap_calldata[:4].hex()
    if swap_selector not in {
        _selector(item, "source swap selector") for item in policy.allowed_source_swap_selectors
    }:
        raise ValueError("swap calldata selector is not allowlisted")
    intermediary_token = canonical_address(decoded["swap_token_out"], "swap output token")
    if intermediary_token not in _allowlist(
        policy.allowed_intermediary_give_tokens, "intermediary give token"
    ):
        raise ValueError("swap output token is not allowlisted")

    nested = _object(decoded["create_salted_order"], "createSaltedOrder")
    if nested["affiliate_fee"] != b"" or nested["permit"] != b"":
        raise ValueError("affiliate fees and permits are not allowed")
    if _integer(nested["referral_code"], "referral code") != 0:
        raise ValueError("referral code is not allowed")
    metadata = nested["metadata"]
    if not isinstance(metadata, bytes) or len(metadata) > policy.maximum_metadata_bytes:
        raise ValueError("metadata exceeds policy size")
    order = _object(nested["order"], "order")
    if canonical_address(order["give_token"], "order give token") != intermediary_token:
        raise ValueError("order give token does not match intermediary")
    if canonical_address(order["give_authority"], "give authority") != signer:
        raise ValueError("source authority mismatch")
    if _integer(order["take_chain_id"], "take chain") != request.destination_chain_id:
        raise ValueError("destination chain mismatch")
    if _bytes_address(order["take_token"], "take token") != NATIVE_TOKEN:
        raise ValueError("destination token is not native")
    if _bytes_address(order["receiver"], "receiver") != recipient:
        raise ValueError("destination receiver mismatch")
    if _bytes_address(order["take_authority"], "take authority") != recipient:
        raise ValueError("destination authority mismatch")
    if _integer(order["take_amount"], "take amount") < request.minimum_output_wei:
        raise ValueError("destination amount below minimum")
    if order["external_call"] != b"":
        raise ValueError("external calls are not allowed")
    if order["cancel_beneficiary"] not in (b"", bytes.fromhex(signer[2:])):
        raise ValueError("cancel beneficiary mismatch")

    allowed_taker = order["allowed_taker"]
    if not isinstance(allowed_taker, bytes):
        raise ValueError("allowed taker is invalid")
    allowed_taker = order["allowed_taker"]
    return {
        "source_dln_target": canonical_address(decoded["dln_source"], "DLN source"),
        "source_order_token": intermediary_token,
        "source_gross_amount_wei": _integer(order["give_amount"], "order give amount"),
        "swap_minimum_amount_out_wei": _integer(
            decoded["swap_minimum_amount_out"], "swap minimum output"
        ),
        "source_swap_router": canonical_address(
            decoded["source_swap_router"], "source swap router"
        ),
        "source_swap_selector": swap_selector,
        "source_swap_calldata_sha256": sha256(swap_calldata).hexdigest(),
        "source_swap_calldata_length": len(swap_calldata),
        "metadata_sha256": sha256(metadata).hexdigest(),
        "metadata_length": len(metadata),
        "destination_amount_wei": _integer(order["take_amount"], "take amount"),
        "destination_receiver": recipient,
        "allowed_taker": (
            _bytes_address(allowed_taker, "allowed taker") if allowed_taker else None
        ),
        "external_call": False,
    }


def validate_quote(
    response: object, request: QuoteRequest, policy: RoutePolicy, *, now: datetime | None = None
) -> dict[str, object]:
    """Validate full quote schema, spend limits, and both router layers."""
    if policy.route_kind == RESERVE_ERC20_DLN_NATIVE_OUT:
        return _validate_direct_quote(response, request, policy, now or datetime.now(UTC))
    if policy.route_kind != NATIVE_IN_SWAP_DLN_NATIVE_OUT:
        raise ValueError("route kind is unsupported")
    if request.amount_wei <= 0 or request.minimum_output_wei <= 0:
        raise ValueError("amounts must be positive")
    if request.nonce < 0:
        raise ValueError("nonce must be non-negative")
    created_at = _utc_timestamp(request.created_at, "created_at")
    expires_at = _utc_timestamp(request.expires_at, "expires_at")
    if expires_at <= created_at:
        raise ValueError("expires_at must be after created_at")
    if (
        policy.maximum_plan_lifetime_seconds <= 0
        or (expires_at - created_at).total_seconds() > policy.maximum_plan_lifetime_seconds
    ):
        raise ValueError("plan lifetime exceeds policy")
    if policy.maximum_total_spend_wei <= 0 or policy.maximum_price_impact_bps < 0:
        raise ValueError("policy limits are invalid")
    if canonical_address(policy.destination_dln_proxy, "destination DLN proxy") == NATIVE_TOKEN:
        raise ValueError("destination DLN proxy must not be the native token sentinel")
    if policy.destination_fulfillment_topic.lower() != FULFILLED_ORDER_TOPIC:
        raise ValueError("destination fulfillment topic is unsupported")
    body = _response_object(response)
    _validate_freshness(
        body,
        policy,
        now or datetime.now(UTC),
        request_created_at=created_at,
    )
    estimation = _object(body.get("estimation"), "estimation")
    transaction = _object(body.get("tx"), "transaction")
    source = _object(estimation.get("srcChainTokenIn"), "source estimation")
    source_out = _object(estimation.get("srcChainTokenOut"), "intermediary estimation")
    destination = _object(estimation.get("dstChainTokenOut"), "destination estimation")
    if _integer(source.get("chainId"), "source chain") != request.source_chain_id:
        raise ValueError("source chain mismatch")
    if canonical_address(source.get("address"), "source token") != NATIVE_TOKEN:
        raise ValueError("source token is not native")
    if _integer(source.get("amount"), "source amount") != request.amount_wei:
        raise ValueError("source amount mismatch")
    source_order_token = canonical_address(source_out.get("address"), "intermediary token")
    if _integer(source_out.get("chainId"), "intermediary chain") != request.source_chain_id:
        raise ValueError("intermediary chain mismatch")
    if source_order_token not in _allowlist(
        policy.allowed_intermediary_give_tokens, "intermediary give token"
    ):
        raise ValueError("intermediary token is not allowlisted")
    source_gross_amount = _integer(source_out.get("amount"), "intermediary amount", positive=True)
    protocol_fee = _integer(body.get("protocolFee"), "protocol fee")
    if protocol_fee >= source_gross_amount:
        raise ValueError("protocol fee leaves no source order amount")
    source_net_amount = source_gross_amount - protocol_fee
    output = _integer(destination.get("recommendedAmount"), "destination amount")
    if _integer(destination.get("chainId"), "destination chain") != request.destination_chain_id:
        raise ValueError("destination chain mismatch")
    if canonical_address(destination.get("address"), "destination token") != NATIVE_TOKEN:
        raise ValueError("destination token is not native")
    if output < request.minimum_output_wei:
        raise ValueError("destination amount below minimum")
    try:
        impact_bps = abs(Decimal(str(body.get("usdPriceImpact"))) * 100)
    except (InvalidOperation, ValueError) as error:
        raise ValueError("invalid price impact") from error
    if not impact_bps.is_finite() or impact_bps > policy.maximum_price_impact_bps:
        raise ValueError("price impact exceeds policy")

    bridge_router = canonical_address(transaction.get("to"), "bridge router")
    if bridge_router not in _allowlist(policy.allowed_bridge_routers, "bridge router"):
        raise ValueError("bridge router is not allowlisted")
    value = _integer(transaction.get("value"), "transaction value")
    if value < request.amount_wei:
        raise ValueError("transaction value is below requested input")
    value_overhead = value - request.amount_wei
    if value_overhead > policy.maximum_value_overhead_wei:
        raise ValueError("transaction value overhead exceeds policy")
    if "fixFee" in body and _integer(body.get("fixFee"), "fixed fee") != value_overhead:
        raise ValueError("transaction value overhead does not match fixed fee")
    gas_details = _object(
        _object(body.get("estimatedTransactionFee"), "gas estimate").get("details"),
        "gas details",
    )
    gas_limit = _integer(gas_details.get("gasLimit"), "gas limit", positive=True)
    max_fee = _integer(gas_details.get("maxFeePerGas"), "max fee", positive=True)
    priority_fee = _integer(gas_details.get("maxPriorityFeePerGas"), "priority fee")
    if priority_fee > max_fee:
        raise ValueError("priority fee exceeds max fee")
    transaction_gas = _integer(transaction.get("gasLimit"), "transaction gas limit", positive=True)
    if transaction_gas > gas_limit:
        raise ValueError("transaction gas limit exceeds bounded estimate")
    total_spend = value + transaction_gas * max_fee
    if total_spend > policy.maximum_total_spend_wei:
        raise ValueError("total spend exceeds policy")
    calldata = transaction.get("data")
    if not isinstance(calldata, str):
        raise ValueError("transaction calldata must be a string")
    decoded = decode_strictly_swap_and_call(calldata)
    semantic = _validate_semantics(decoded, request, policy)
    response_order = _object(body.get("order"), "quote order")
    response_metadata = _hex(response_order.get("metadata"), "quote order metadata")
    if response_metadata != _object(decoded["create_salted_order"], "order payload")["metadata"]:
        raise ValueError("quote order metadata does not match calldata")
    if semantic["source_order_token"] != source_order_token:
        raise ValueError("order give token does not match intermediary estimate")
    if semantic["source_gross_amount_wei"] != source_gross_amount:
        raise ValueError("order give amount does not match intermediary estimate")
    if semantic["swap_minimum_amount_out_wei"] != source_gross_amount:
        raise ValueError("swap minimum output does not match intermediary estimate")
    recomputed_order_id = deterministic_order_id(
        {
            **_object(_object(decoded["create_salted_order"], "order payload")["order"], "order"),
            "give_chain_id": request.source_chain_id,
            "give_amount": source_net_amount,
        },
        maker=canonical_address(request.signer, "signer"),
    )
    order_id_from_quote = body.get("orderId")
    if not isinstance(order_id_from_quote, str) or not HASH_RE.fullmatch(order_id_from_quote):
        raise ValueError("quote order ID is malformed")
    if recomputed_order_id.lower() != order_id_from_quote.lower():
        raise ValueError("quote order ID mismatch")
    return {
        "bridge_router": bridge_router,
        "data": calldata,
        "value_wei": value,
        "total_spend_wei": total_spend,
        "gas": transaction_gas,
        "bounded_gas": gas_limit,
        "max_fee_per_gas": max_fee,
        "max_priority_fee_per_gas": priority_fee,
        "output_wei": output,
        "price_impact_bps": int(impact_bps),
        "order_id": recomputed_order_id,
        "fix_fee_amount_wei": value_overhead,
        "protocol_fee_amount_wei": protocol_fee,
        "source_net_amount_wei": source_net_amount,
        **semantic,
    }


def create_plan(quote: Mapping[str, object], request: QuoteRequest, policy: RoutePolicy) -> Plan:
    return Plan.create(
        {
            "provider": {
                "name": "debridge",
                "version": "3" if policy.route_kind == RESERVE_ERC20_DLN_NATIVE_OUT else "2",
                "route_id": policy.route_id,
                "route_kind": policy.route_kind,
                "source_dln_target": quote["source_dln_target"],
                "source_reserve_token": policy.source_reserve_token,
                "source_dln_implementation_codehash": policy.source_dln_implementation_codehash,
                "expected_global_transfer_fee_bps": policy.expected_global_transfer_fee_bps,
                "destination_dln_proxy": canonical_address(policy.destination_dln_proxy),
                "destination_fulfillment_topic": policy.destination_fulfillment_topic.lower(),
            },
            "intent": {
                "created_at": request.created_at,
                "expires_at": request.expires_at,
                "source_chain_id": request.source_chain_id,
                "destination_chain_id": request.destination_chain_id,
                "amount_wei": request.amount_wei,
                "minimum_output_wei": request.minimum_output_wei,
                "recipient": canonical_address(request.recipient),
                "expected_signer": canonical_address(request.signer),
            },
            "policy": {
                "route_id": policy.route_id,
                "route_kind": policy.route_kind,
                "maximum_total_spend_wei": policy.maximum_total_spend_wei,
                "maximum_value_overhead_wei": policy.maximum_value_overhead_wei,
                "maximum_price_impact_bps": policy.maximum_price_impact_bps,
                "maximum_fixed_native_fee_wei": policy.maximum_fixed_native_fee_wei,
                "maximum_input_token_amount": policy.maximum_input_token_amount,
                "maximum_gas_limit": policy.maximum_gas_limit,
                "expected_global_transfer_fee_bps": policy.expected_global_transfer_fee_bps,
            },
            "unsigned_transaction": {
                "chain_id": request.source_chain_id,
                "nonce": request.nonce,
                "to": quote["bridge_router"],
                "value": quote["value_wei"],
                "data": quote["data"],
                "gas": quote["gas"],
                "max_fee_per_gas": quote["max_fee_per_gas"],
                "max_priority_fee_per_gas": quote["max_priority_fee_per_gas"],
            },
            "decoded_semantics": {
                "order_id": quote["order_id"],
                "total_spend_wei": quote["total_spend_wei"],
                "price_impact_bps": quote["price_impact_bps"],
                "transaction_calldata_sha256": sha256(
                    bytes.fromhex(str(quote["data"])[2:])
                ).hexdigest(),
                "source_order_token": quote["source_order_token"],
                "source_gross_amount_wei": quote["source_gross_amount_wei"],
                "fix_fee_amount_wei": quote["fix_fee_amount_wei"],
                "protocol_fee_amount_wei": quote["protocol_fee_amount_wei"],
                "source_net_amount_wei": quote["source_net_amount_wei"],
                "source_swap_router": quote["source_swap_router"],
                "source_swap_selector": quote["source_swap_selector"],
                "source_swap_calldata_sha256": quote["source_swap_calldata_sha256"],
                "source_swap_calldata_length": quote["source_swap_calldata_length"],
                "metadata_sha256": quote["metadata_sha256"],
                "metadata_length": quote["metadata_length"],
                "destination_receiver": quote["destination_receiver"],
                "destination_chain_id": request.destination_chain_id,
                "destination_token": NATIVE_TOKEN,
                "destination_amount_wei": quote["destination_amount_wei"],
                "allowed_taker": quote["allowed_taker"],
                "external_call": False,
            },
            "checks": (
                [
                    "reserve-erc20-input",
                    "direct-create-salted-order",
                    "exact-allowance-required",
                    "source-dln-proxy",
                    "implementation-codehash",
                    "allowlists",
                    "spend-cap",
                    "impact-cap",
                    "calldata",
                    "protocol-fee",
                    "deterministic-order-id",
                ]
                if policy.route_kind == RESERVE_ERC20_DLN_NATIVE_OUT
                else [
                    "native-input",
                    "intermediary-give",
                    "bridge-router",
                    "source-swap-router",
                    "allowlists",
                    "spend-cap",
                    "impact-cap",
                    "calldata",
                    "protocol-fee",
                    "deterministic-order-id",
                ]
            ),
        }
    )


def decode_fulfilled_order(
    log: object,
    *,
    destination_proxy: str,
    expected_order_id: str,
    expected_signer: str,
    source_chain_id: int,
    source_token: str,
    source_amount_wei: int,
    destination_chain_id: int,
    receiver: str,
    destination_token: str,
    minimum_amount_wei: int,
    expected_take_amount_wei: int,
    expected_allowed_taker: str | None = None,
) -> dict[str, object]:
    """Decode one raw FulfilledOrder log and bind every transfer identifier."""
    entry = _object(log, "receipt log")
    if canonical_address(entry.get("address"), "destination proxy") != canonical_address(
        destination_proxy, "destination proxy"
    ):
        raise ValueError("unexpected destination proxy")
    topics = entry.get("topics")
    if not isinstance(topics, list) or topics != [FULFILLED_ORDER_TOPIC]:
        raise ValueError("unexpected fulfillment topic")
    data = _hex(entry.get("data"), "fulfillment data", required=True)
    if len(data) < 5 * 32:
        raise ValueError("fulfillment data is truncated")
    order = _decode_fulfilled_order_tuple(data, _word(data, 0, "order offset"))
    order_id = "0x" + data[32:64].hex()
    amount = _word(data, 64, "actual fulfill amount")
    if order_id.lower() != expected_order_id.lower():
        raise ValueError("fulfillment order ID mismatch")
    if _integer(order["give_chain_id"], "give chain") != source_chain_id:
        raise ValueError("fulfillment source chain mismatch")
    if _bytes_address(order["give_token"], "give token") != canonical_address(
        source_token, "source token"
    ):
        raise ValueError("fulfillment source token mismatch")
    if _integer(order["give_amount"], "give amount") != source_amount_wei:
        raise ValueError("fulfillment source amount mismatch")
    if _integer(order["take_chain_id"], "take chain") != destination_chain_id:
        raise ValueError("fulfillment destination chain mismatch")
    if _bytes_address(order["receiver"], "receiver") != canonical_address(receiver, "receiver"):
        raise ValueError("fulfillment receiver mismatch")
    signer = canonical_address(expected_signer, "expected signer")
    if _bytes_address(order["maker"], "maker") != signer:
        raise ValueError("fulfillment maker mismatch")
    if _bytes_address(order["give_authority"], "give authority") != signer:
        raise ValueError("fulfillment give authority mismatch")
    if _bytes_address(order["take_authority"], "take authority") != canonical_address(
        receiver, "receiver"
    ):
        raise ValueError("fulfillment destination authority mismatch")
    if _bytes_address(order["take_token"], "take token") != canonical_address(
        destination_token, "destination token"
    ):
        raise ValueError("fulfillment token mismatch")
    if order["external_call"] != b"":
        raise ValueError("fulfillment external call is not allowed")
    allowed_taker = order["allowed_taker"]
    actual_allowed_taker = _bytes_address(allowed_taker, "allowed taker") if allowed_taker else None
    expected_taker = (
        canonical_address(expected_allowed_taker, "expected allowed taker")
        if expected_allowed_taker is not None
        else None
    )
    if actual_allowed_taker != expected_taker:
        raise ValueError("fulfillment allowed taker mismatch")
    cancel_beneficiary = order["cancel_beneficiary"]
    if cancel_beneficiary and _bytes_address(cancel_beneficiary, "cancel beneficiary") != signer:
        raise ValueError("fulfillment cancel beneficiary mismatch")
    if (
        amount < minimum_amount_wei
        or amount != expected_take_amount_wei
        or amount != _integer(order["take_amount"], "take amount")
    ):
        raise ValueError("fulfillment amount mismatch")
    recomputed_order_id = deterministic_order_id(
        {
            **order,
            "give_token": _bytes_address(order["give_token"], "give token"),
            "give_authority": _bytes_address(order["give_authority"], "give authority"),
        },
        maker=_bytes_address(order["maker"], "maker"),
    )
    if recomputed_order_id != order_id.lower():
        raise ValueError("fulfillment deterministic order ID mismatch")
    return {
        "order_id": order_id.lower(),
        "amount_wei": amount,
        "receiver": canonical_address(receiver),
        "destination_token": canonical_address(destination_token),
        "external_call": False,
    }


def validate_cancellation_events(events: Sequence[object], *, order_id: str) -> None:
    """Cancellation reconciliation is unsupported until both event ABIs are decoded."""
    del events, order_id
    raise NotImplementedError(
        "cancellation is fail-closed until SentOrderCancel and ClaimedOrderCancel are decoded"
    )


class DeBridgeProvider:
    """Injected-transport adapter. No endpoint, router, or DLN address defaults."""

    def __init__(self, http_json: HttpJson) -> None:
        self._http_json = http_json

    def quote(self, endpoint: str, request: QuoteRequest, policy: RoutePolicy) -> Plan:
        parts = urlsplit(endpoint)
        if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
            raise ValueError("quote endpoint must be an absolute HTTPS URL without user info")
        source_token = (
            policy.source_reserve_token
            if policy.route_kind == RESERVE_ERC20_DLN_NATIVE_OUT
            else NATIVE_TOKEN
        )
        if source_token is None:
            raise ValueError("direct route source reserve token is absent")
        query = urlencode(
            {
                "srcChainId": request.source_chain_id,
                "srcChainTokenIn": source_token,
                "srcChainTokenInAmount": request.amount_wei,
                "dstChainId": request.destination_chain_id,
                "dstChainTokenOut": NATIVE_TOKEN,
                "dstChainTokenOutRecipient": canonical_address(request.recipient),
                "senderAddress": canonical_address(request.signer),
                "srcChainOrderAuthorityAddress": canonical_address(request.signer),
                "dstChainOrderAuthorityAddress": canonical_address(request.recipient),
                "enableEstimate": "true",
                "prependOperatingExpenses": "false",
            }
        )
        separator = "&" if parts.query else "?"
        quote = validate_quote(self._http_json(endpoint + separator + query), request, policy)
        return create_plan(quote, request, policy)
