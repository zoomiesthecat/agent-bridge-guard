"""Strict extraction of the execution fields bound by an immutable plan."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast

from eth_utils import is_address, to_checksum_address  # type: ignore[attr-defined]

from .models import Plan
from .providers.debridge import (
    FULFILLED_ORDER_TOPIC,
    NATIVE_IN_SWAP_DLN_NATIVE_OUT,
    RESERVE_ERC20_DLN_NATIVE_OUT,
)
from .signers.base import EIP1559Transaction, normalize_transaction

ORDER_ID = re.compile(r"^0x[0-9a-fA-F]{64}$")
ROUTE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
NATIVE_TOKEN = "0x0000000000000000000000000000000000000000"  # noqa: S105


class ExecutionPlanError(ValueError):
    """The plan is incomplete, expired, or internally inconsistent."""


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ExecutionPlanError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _integer(value: object, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < (1 if positive else 0):
        qualifier = "positive" if positive else "non-negative"
        raise ExecutionPlanError(f"{label} must be a {qualifier} integer")
    return value


def _address(value: object, label: str) -> str:
    if not isinstance(value, str) or not is_address(value):
        raise ExecutionPlanError(f"{label} must be an EVM address")
    return cast(str, to_checksum_address(value))


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ExecutionPlanError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExecutionPlanError(f"{label} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ExecutionPlanError(f"{label} must be a UTC timestamp")
    return parsed


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """The only plan shape accepted by a signing or broadcast boundary."""

    plan: Plan
    route_id: str
    route_kind: str
    signer: str
    transaction: EIP1559Transaction = field(repr=False)
    source_chain_id: int
    destination_chain_id: int
    source_order_token: str
    source_order_amount_wei: int
    source_swap_router: str
    source_dln_implementation_codehash: str | None
    expected_global_transfer_fee_bps: int | None
    recipient: str
    minimum_output_wei: int
    destination_token: str
    destination_amount_wei: int
    order_id: str
    allowed_taker: str | None
    destination_dln_proxy: str
    destination_fulfillment_topic: str
    expires_at: datetime

    @classmethod
    def from_plan(
        cls,
        plan: Plan,
        *,
        at: datetime | None = None,
        allow_expired: bool = False,
    ) -> ExecutionPlan:
        body = plan.body()
        intent = _object(body.get("intent"), "intent")
        created_at = _timestamp(intent.get("created_at"), "created_at")
        expires_at = _timestamp(intent.get("expires_at"), "expires_at")
        if expires_at <= created_at:
            raise ExecutionPlanError("plan expiry must follow creation")
        now = at or datetime.now(UTC)
        if now.tzinfo is None:
            raise ExecutionPlanError("verification time must be timezone-aware")
        if not allow_expired and now >= expires_at:
            raise ExecutionPlanError("plan expired")

        provider = _object(body.get("provider"), "provider")
        if provider.get("name") != "debridge":
            raise ExecutionPlanError("provider must be debridge")
        route_kind = provider.get("route_kind")
        if route_kind not in {NATIVE_IN_SWAP_DLN_NATIVE_OUT, RESERVE_ERC20_DLN_NATIVE_OUT}:
            raise ExecutionPlanError("provider route kind is unsupported")
        if provider.get("version") != ("3" if route_kind == RESERVE_ERC20_DLN_NATIVE_OUT else "2"):
            raise ExecutionPlanError("provider plan version is unsupported")
        route_id = provider.get("route_id")
        if not isinstance(route_id, str) or not ROUTE_ID.fullmatch(route_id):
            raise ExecutionPlanError("provider route ID is invalid")
        destination_dln_proxy = _address(
            provider.get("destination_dln_proxy"), "destination DLN proxy"
        )
        destination_fulfillment_topic = provider.get("destination_fulfillment_topic")
        if not isinstance(destination_fulfillment_topic, str) or not ORDER_ID.fullmatch(
            destination_fulfillment_topic
        ):
            raise ExecutionPlanError("destination fulfillment topic must be a 32-byte hash")
        if destination_fulfillment_topic.lower() != FULFILLED_ORDER_TOPIC:
            raise ExecutionPlanError("destination fulfillment topic is unsupported")

        source_chain_id = _integer(intent.get("source_chain_id"), "source chain", positive=True)
        destination_chain_id = _integer(
            intent.get("destination_chain_id"), "destination chain", positive=True
        )
        amount_wei = _integer(intent.get("amount_wei"), "input amount", positive=True)
        minimum_output_wei = _integer(
            intent.get("minimum_output_wei"), "minimum output", positive=True
        )
        signer = _address(intent.get("expected_signer"), "expected signer")
        recipient = _address(intent.get("recipient"), "recipient")

        try:
            transaction = normalize_transaction(
                _object(body.get("unsigned_transaction"), "unsigned transaction")
            )
        except ValueError as exc:
            raise ExecutionPlanError(f"unsigned transaction is invalid: {exc}") from exc
        if transaction["chain_id"] != source_chain_id:
            raise ExecutionPlanError("source chain does not match unsigned transaction")
        if route_kind == NATIVE_IN_SWAP_DLN_NATIVE_OUT and transaction["value"] < amount_wei:
            raise ExecutionPlanError("transaction value is below the input amount")

        semantics = _object(body.get("decoded_semantics"), "decoded semantics")
        source_order_token = _address(semantics.get("source_order_token"), "source order token")
        source_gross_amount_wei = _integer(
            semantics.get("source_gross_amount_wei"),
            "source gross amount",
            positive=True,
        )
        protocol_fee_amount_wei = _integer(
            semantics.get("protocol_fee_amount_wei"),
            "protocol fee amount",
        )
        source_order_amount_wei = _integer(
            semantics.get("source_net_amount_wei"),
            "source net amount",
            positive=True,
        )
        source_swap_router = _address(semantics.get("source_swap_router"), "source swap router")
        raw_implementation_codehash = provider.get("source_dln_implementation_codehash")
        implementation_codehash = (
            raw_implementation_codehash.lower()
            if isinstance(raw_implementation_codehash, str)
            and ORDER_ID.fullmatch(raw_implementation_codehash)
            else None
        )
        raw_transfer_fee = provider.get("expected_global_transfer_fee_bps")
        expected_transfer_fee = (
            _integer(raw_transfer_fee, "expected global transfer fee")
            if raw_transfer_fee is not None
            else None
        )
        if route_kind == RESERVE_ERC20_DLN_NATIVE_OUT and (
            implementation_codehash is None or expected_transfer_fee is None
        ):
            raise ExecutionPlanError("direct route preflight policy is incomplete")
        if (
            protocol_fee_amount_wei >= source_gross_amount_wei
            or source_gross_amount_wei - protocol_fee_amount_wei != source_order_amount_wei
        ):
            raise ExecutionPlanError("source order fee accounting mismatch")
        order_id = semantics.get("order_id")
        if not isinstance(order_id, str) or not ORDER_ID.fullmatch(order_id):
            raise ExecutionPlanError("order ID must be a 32-byte hash")
        semantic_chain = _integer(
            semantics.get("destination_chain_id"), "semantic destination chain", positive=True
        )
        if semantic_chain != destination_chain_id:
            raise ExecutionPlanError("destination chain semantic mismatch")
        semantic_receiver = _address(semantics.get("destination_receiver"), "destination receiver")
        if semantic_receiver != recipient:
            raise ExecutionPlanError("destination receiver does not match recipient")
        destination_token = _address(semantics.get("destination_token"), "destination token")
        if destination_token.lower() != NATIVE_TOKEN:
            raise ExecutionPlanError("destination token must be native")
        destination_amount_wei = _integer(
            semantics.get("destination_amount_wei"), "destination amount", positive=True
        )
        if destination_amount_wei < minimum_output_wei:
            raise ExecutionPlanError("destination amount is below minimum output")
        if semantics.get("external_call") is not False:
            raise ExecutionPlanError("external calls are forbidden")
        raw_allowed_taker = semantics.get("allowed_taker")
        allowed_taker = (
            None
            if raw_allowed_taker is None or raw_allowed_taker == "" or raw_allowed_taker == "0x"
            else _address(raw_allowed_taker, "allowed taker")
        )

        return cls(
            plan=plan,
            route_id=route_id,
            route_kind=route_kind,
            signer=signer,
            transaction=transaction,
            source_chain_id=source_chain_id,
            destination_chain_id=destination_chain_id,
            source_order_token=source_order_token,
            source_order_amount_wei=source_order_amount_wei,
            source_swap_router=source_swap_router,
            source_dln_implementation_codehash=implementation_codehash,
            expected_global_transfer_fee_bps=expected_transfer_fee,
            recipient=recipient,
            minimum_output_wei=minimum_output_wei,
            destination_token=destination_token,
            destination_amount_wei=destination_amount_wei,
            order_id=order_id.lower(),
            allowed_taker=allowed_taker,
            destination_dln_proxy=destination_dln_proxy,
            destination_fulfillment_topic=destination_fulfillment_topic.lower(),
            expires_at=expires_at,
        )
