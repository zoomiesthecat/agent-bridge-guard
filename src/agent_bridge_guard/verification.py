"""Typed proof factories for canonical source and destination receipts."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import cast

from .execution_plan import ExecutionPlan
from .models import JSONObject, Plan
from .providers.debridge import decode_fulfilled_order

QUANTITY = re.compile(r"^0x[0-9a-fA-F]+$")
_PROOF_TOKEN = object()
VERIFIER_VERSION = "agent-bridge-guard/receipt-verifier/v1"


class VerificationError(ValueError):
    """A receipt does not prove the exact planned operation."""


def _quantity(value: object, label: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(value, str) and QUANTITY.fullmatch(value):
        return int(value, 16)
    raise VerificationError(f"receipt {label} is invalid")


def _identity(
    receipt: JSONObject,
    *,
    transaction_hash: str,
    receipt_status: int,
) -> tuple[int, str]:
    observed_hash = receipt.get("transactionHash")
    block_hash = receipt.get("blockHash")
    if (
        not isinstance(observed_hash, str)
        or observed_hash.lower() != transaction_hash.lower()
        or not isinstance(block_hash, str)
        or not re.fullmatch(r"0x[0-9a-fA-F]{64}", block_hash)
        or _quantity(receipt.get("status"), "status") != receipt_status
    ):
        raise VerificationError("receipt identity is invalid")
    return _quantity(receipt.get("blockNumber"), "block number"), block_hash.lower()


@dataclass(frozen=True, slots=True)
class VerifiedSourceReceipt:
    operation_id: str
    plan_id: str
    chain_id: int
    transaction_hash: str
    block_number: int
    block_hash: str
    confirmations: int
    receipt_status: int
    rpc_quorum: int = 2
    schema_version: int = 1
    verifier_version: str = VERIFIER_VERSION
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _PROOF_TOKEN:
            raise TypeError("verified source receipts must come from the receipt verifier")

    def to_dict(self) -> JSONObject:
        return {
            "schema_version": self.schema_version,
            "verifier_version": self.verifier_version,
            "plan_id": self.plan_id,
            "chain_id": self.chain_id,
            "transaction_hash": self.transaction_hash,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "confirmations": self.confirmations,
            "receipt_status": self.receipt_status,
            "rpc_quorum": self.rpc_quorum,
        }


@dataclass(frozen=True, slots=True)
class VerifiedSourceFailure(VerifiedSourceReceipt):
    pass


@dataclass(frozen=True, slots=True)
class VerifiedDestinationFulfillment:
    operation_id: str
    plan_id: str
    chain_id: int
    transaction_hash: str
    block_number: int
    block_hash: str
    confirmations: int
    order_id: str
    log_index: int
    log_address: str
    log_topic: str
    signer: str
    source_chain_id: int
    source_token: str
    source_amount_wei: int
    destination_chain_id: int
    receiver: str
    destination_token: str
    destination_amount_wei: int
    allowed_taker: str | None
    external_call: bool = False
    receipt_status: int = 1
    rpc_quorum: int = 2
    schema_version: int = 1
    verifier_version: str = VERIFIER_VERSION
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _PROOF_TOKEN:
            raise TypeError(
                "verified destination fulfillment must come from the receipt verifier"
            )

    def to_dict(self) -> JSONObject:
        return {
            "schema_version": self.schema_version,
            "verifier_version": self.verifier_version,
            "plan_id": self.plan_id,
            "chain_id": self.chain_id,
            "transaction_hash": self.transaction_hash,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "confirmations": self.confirmations,
            "receipt_status": self.receipt_status,
            "rpc_quorum": self.rpc_quorum,
            "order_id": self.order_id,
            "log_index": self.log_index,
            "log_address": self.log_address,
            "log_topic": self.log_topic,
            "signer": self.signer,
            "source_chain_id": self.source_chain_id,
            "source_token": self.source_token,
            "source_amount_wei": self.source_amount_wei,
            "destination_chain_id": self.destination_chain_id,
            "receiver": self.receiver,
            "destination_token": self.destination_token,
            "destination_amount_wei": self.destination_amount_wei,
            "allowed_taker": self.allowed_taker,
            "external_call": self.external_call,
        }


def verify_source_receipt(
    *,
    operation_id: str,
    plan: Plan,
    receipt: JSONObject,
    chain_id: int,
    transaction_hash: str,
    confirmations: int,
    receipt_status: int,
) -> VerifiedSourceReceipt | VerifiedSourceFailure:
    if confirmations <= 0 or receipt_status not in {0, 1}:
        raise VerificationError("source receipt policy is invalid")
    execution = ExecutionPlan.from_plan(plan, allow_expired=True)
    if chain_id != execution.source_chain_id:
        raise VerificationError("source receipt chain does not match plan")
    block_number, block_hash = _identity(
        receipt,
        transaction_hash=transaction_hash,
        receipt_status=receipt_status,
    )
    proof_type = VerifiedSourceReceipt if receipt_status == 1 else VerifiedSourceFailure
    return proof_type(
        operation_id=operation_id,
        plan_id=plan.plan_id,
        chain_id=chain_id,
        transaction_hash=transaction_hash.lower(),
        block_number=block_number,
        block_hash=block_hash,
        confirmations=confirmations,
        receipt_status=receipt_status,
        _token=_PROOF_TOKEN,
    )


def verify_destination_receipt(
    *,
    operation_id: str,
    plan: Plan,
    receipt: JSONObject,
    transaction_hash: str,
    confirmations: int,
) -> VerifiedDestinationFulfillment:
    if confirmations <= 0:
        raise VerificationError("destination confirmations must be positive")
    execution = ExecutionPlan.from_plan(plan, allow_expired=True)
    block_number, block_hash = _identity(
        receipt,
        transaction_hash=transaction_hash,
        receipt_status=1,
    )
    logs = receipt.get("logs")
    if not isinstance(logs, list):
        raise VerificationError("destination receipt has no log list")
    matching: list[tuple[dict[str, object], JSONObject]] = []
    for candidate in logs:
        if not isinstance(candidate, dict):
            continue
        try:
            decoded = decode_fulfilled_order(
                candidate,
                destination_proxy=execution.destination_dln_proxy,
                expected_order_id=execution.order_id,
                expected_signer=execution.signer,
                source_chain_id=execution.source_chain_id,
                source_token=execution.source_order_token,
                source_amount_wei=execution.source_order_amount_wei,
                destination_chain_id=execution.destination_chain_id,
                receiver=execution.recipient,
                destination_token=execution.destination_token,
                minimum_amount_wei=execution.minimum_output_wei,
                expected_take_amount_wei=execution.destination_amount_wei,
                expected_allowed_taker=execution.allowed_taker,
            )
        except ValueError:
            continue
        matching.append((decoded, candidate))
    if len(matching) != 1:
        raise VerificationError(
            "destination receipt must contain exactly one matching fulfillment event"
        )
    decoded, log = matching[0]
    address = log.get("address")
    topics = log.get("topics")
    if (
        not isinstance(address, str)
        or not isinstance(topics, list)
        or len(topics) != 1
        or not isinstance(topics[0], str)
    ):
        raise VerificationError("fulfillment log identity is invalid")
    return VerifiedDestinationFulfillment(
        operation_id=operation_id,
        plan_id=plan.plan_id,
        chain_id=execution.destination_chain_id,
        transaction_hash=transaction_hash.lower(),
        block_number=block_number,
        block_hash=block_hash,
        confirmations=confirmations,
        order_id=cast(str, decoded["order_id"]),
        log_index=_quantity(log.get("logIndex"), "log index"),
        log_address=address.lower(),
        log_topic=topics[0].lower(),
        signer=execution.signer,
        source_chain_id=execution.source_chain_id,
        source_token=execution.source_order_token,
        source_amount_wei=execution.source_order_amount_wei,
        destination_chain_id=execution.destination_chain_id,
        receiver=execution.recipient,
        destination_token=execution.destination_token,
        destination_amount_wei=execution.destination_amount_wei,
        allowed_taker=execution.allowed_taker,
        _token=_PROOF_TOKEN,
    )
