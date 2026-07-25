"""Advisory deBridge tracking discovery followed by separate on-chain proof."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlsplit

from .execution_plan import NATIVE_TOKEN, ExecutionPlan
from .models import Plan
from .providers.debridge import canonical_address

HttpJson = Callable[[str], object]
TX_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
SUCCESS_STATES = frozenset({"Fulfilled", "SentUnlock", "ClaimedUnlock"})


class TrackingError(RuntimeError):
    """Tracking response could not be bound to the exact operation."""


class TrackingPending(TrackingError):
    """The advisory service has not reported a final fulfillment."""

    def __init__(self, state: str) -> None:
        super().__init__("deBridge order is not yet fulfilled")
        self.state = state


@dataclass(frozen=True, slots=True)
class FulfillmentDiscovery:
    order_id: str
    state: str
    final_amount_wei: int
    destination_transaction_hash: str


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TrackingError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping) and isinstance(value.get("stringValue"), str):
        return cast(str, value["stringValue"])
    raise TrackingError(f"{label} is missing")


def _chain(value: object, label: str) -> int:
    text = _string(value, label)
    try:
        parsed = int(text)
    except ValueError as exc:
        raise TrackingError(f"{label} is invalid") from exc
    if parsed <= 0:
        raise TrackingError(f"{label} is invalid")
    return parsed


def _address(value: object, label: str) -> str:
    try:
        return canonical_address(_string(value, label), label)
    except ValueError as exc:
        raise TrackingError(f"{label} is invalid") from exc


class DeBridgeTrackingClient:
    """Use tracking only to discover a candidate destination transaction."""

    def __init__(self, base_url: str, http_json: HttpJson) -> None:
        parts = urlsplit(base_url)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise ValueError("tracking endpoint must be an absolute HTTPS base URL")
        self._base_url = base_url.rstrip("/")
        self._http_json = http_json

    def discover_fulfillment(
        self,
        plan: Plan,
        source_transaction_hash: str,
    ) -> FulfillmentDiscovery:
        if not TX_HASH.fullmatch(source_transaction_hash):
            raise ValueError("source transaction hash is invalid")
        execution = ExecutionPlan.from_plan(plan, allow_expired=True)
        index = _object(
            self._http_json(
                f"{self._base_url}/Transaction/{source_transaction_hash}/orderIds"
            ),
            "tracking order index",
        )
        raw_order_ids = index.get("orderIds")
        if not isinstance(raw_order_ids, list):
            raise TrackingError("tracking order index is missing order IDs")
        order_ids = [_string(item, "tracking order ID").lower() for item in raw_order_ids]
        if order_ids != [execution.order_id]:
            raise TrackingError("source transaction does not map to the exact planned order")

        status = _object(
            self._http_json(f"{self._base_url}/Orders/{execution.order_id}"),
            "tracking order",
        )
        order_id = _string(status.get("orderId"), "tracking order ID").lower()
        if order_id != execution.order_id:
            raise TrackingError("tracking order ID mismatch")
        state = status.get("state")
        if not isinstance(state, str):
            raise TrackingError("tracking order state is missing")
        if state not in SUCCESS_STATES:
            raise TrackingPending(state)
        if status.get("externalCallState") != "NoExtCall":
            raise TrackingError("tracking reports a destination external call")

        created = _object(status.get("createdSrcEventMetadata"), "source creation metadata")
        if _string(created.get("transactionHash"), "source transaction").lower() != (
            source_transaction_hash.lower()
        ):
            raise TrackingError("tracking source transaction mismatch")
        if _address(created.get("initiator"), "source initiator") != execution.signer.lower():
            raise TrackingError("tracking source initiator mismatch")
        if _address(status.get("receiverDst"), "destination receiver") != (
            execution.recipient.lower()
        ):
            raise TrackingError("tracking destination receiver mismatch")
        if _address(status.get("givePatchAuthoritySrc"), "source authority") != (
            execution.signer.lower()
        ):
            raise TrackingError("tracking source authority mismatch")
        if _address(status.get("orderAuthorityAddressDst"), "destination authority") != (
            execution.recipient.lower()
        ):
            raise TrackingError("tracking destination authority mismatch")

        give = _object(status.get("giveOfferWithMetadata"), "source offer")
        take = _object(status.get("takeOfferWithMetadata"), "destination offer")
        if _chain(give.get("chainId"), "source chain") != execution.source_chain_id:
            raise TrackingError("tracking source chain mismatch")
        if _chain(take.get("chainId"), "destination chain") != execution.destination_chain_id:
            raise TrackingError("tracking destination chain mismatch")
        if _address(take.get("tokenAddress"), "destination token") != NATIVE_TOKEN:
            raise TrackingError("tracking destination token mismatch")
        final_amount = _chain(take.get("finalAmount"), "destination amount")
        if final_amount < execution.minimum_output_wei:
            raise TrackingError("tracking destination amount is below minimum")

        fulfilled = _object(
            status.get("fulfilledDstEventMetadata"),
            "fulfillment metadata",
        )
        destination_transaction_hash = _string(
            fulfilled.get("transactionHash"),
            "destination transaction",
        ).lower()
        if not TX_HASH.fullmatch(destination_transaction_hash):
            raise TrackingError("destination transaction hash is invalid")
        return FulfillmentDiscovery(
            order_id=order_id,
            state=state,
            final_amount_wei=final_amount,
            destination_transaction_hash=destination_transaction_hash,
        )
