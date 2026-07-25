"""Strict, versioned route policy manifests supplied by the operator."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from .artifacts import read_json_object
from .models import JSONObject, canonical_json
from .providers.debridge import (
    FULFILLED_ORDER_TOPIC,
    NATIVE_IN_SWAP_DLN_NATIVE_OUT,
    RESERVE_ERC20_DLN_NATIVE_OUT,
    RoutePolicy,
    canonical_address,
)

DIRECT_FIELDS = frozenset(
    {
        "schema_version",
        "route_kind",
        "route_id",
        "source_chain_alias",
        "destination_chain_alias",
        "source_chain_id",
        "destination_chain_id",
        "source_reserve_token",
        "source_dln_proxy",
        "source_dln_implementation_codehash",
        "allowed_takers",
        "destination_dln_proxy",
        "destination_fulfillment_topic",
        "maximum_total_spend_wei",
        "maximum_input_token_amount",
        "maximum_fixed_native_fee_wei",
        "maximum_gas_limit",
        "maximum_price_impact_bps",
        "expected_global_transfer_fee_bps",
        "maximum_metadata_bytes",
        "maximum_quote_age_seconds",
        "maximum_plan_lifetime_seconds",
    }
)

OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
FIELDS = frozenset(
    {
        "schema_version",
        "route_kind",
        "route_id",
        "source_chain_alias",
        "destination_chain_alias",
        "source_chain_id",
        "destination_chain_id",
        "allowed_bridge_routers",
        "allowed_source_swap_routers",
        "allowed_source_swap_selectors",
        "allowed_intermediary_give_tokens",
        "allowed_dln_sources",
        "allowed_refund_recipients",
        "destination_dln_proxy",
        "destination_fulfillment_topic",
        "maximum_total_spend_wei",
        "maximum_value_overhead_wei",
        "maximum_price_impact_bps",
        "maximum_swap_calldata_bytes",
        "maximum_metadata_bytes",
        "maximum_quote_age_seconds",
        "maximum_plan_lifetime_seconds",
    }
)


class RouteManifestError(ValueError):
    """A route manifest is incomplete, unsafe, or unsupported."""


def _integer(
    value: object,
    label: str,
    *,
    positive: bool = False,
    maximum: int | None = None,
) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise RouteManifestError(f"{label} is out of range")
    if maximum is not None and value > maximum:
        raise RouteManifestError(f"{label} is out of range")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not OPAQUE_ID.fullmatch(value):
        raise RouteManifestError(f"{label} must be an opaque identifier")
    return value


def _addresses(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise RouteManifestError(f"{label} must be a non-empty address list")
    try:
        addresses = tuple(canonical_address(item, label) for item in value)
    except ValueError as exc:
        raise RouteManifestError(f"{label} contains an invalid address") from exc
    if len(set(addresses)) != len(addresses):
        raise RouteManifestError(f"{label} contains a duplicate address")
    return addresses


def _selectors(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise RouteManifestError(f"{label} must be a non-empty selector list")
    selectors: list[str] = []
    for item in value:
        if not isinstance(item, str) or not re.fullmatch(r"0x[0-9a-fA-F]{8}", item):
            raise RouteManifestError(f"{label} contains an invalid selector")
        selectors.append(item.lower())
    if len(set(selectors)) != len(selectors):
        raise RouteManifestError(f"{label} contains a duplicate selector")
    return tuple(selectors)


@dataclass(frozen=True, slots=True)
class RouteManifest:
    route_id: str
    route_kind: str
    source_chain_alias: str
    destination_chain_alias: str
    source_chain_id: int
    destination_chain_id: int
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
    maximum_quote_age_seconds: int
    maximum_plan_lifetime_seconds: int
    source_reserve_token: str | None = None
    source_dln_proxy: str | None = None
    source_dln_implementation_codehash: str | None = None
    allowed_takers: tuple[str, ...] = ()
    maximum_fixed_native_fee_wei: int = 0
    maximum_input_token_amount: int = 0
    maximum_gas_limit: int = 0
    expected_global_transfer_fee_bps: int | None = None

    @classmethod
    def load(cls, path: str | Path) -> RouteManifest:
        try:
            document = read_json_object(path)
        except Exception as exc:
            raise RouteManifestError("route manifest cannot be read") from exc
        return cls.parse_document(document)

    @classmethod
    def parse_document(cls, document: dict[str, object]) -> RouteManifest:
        if document.get("route_kind") == RESERVE_ERC20_DLN_NATIVE_OUT:
            return cls._load_direct(document)
        if set(document) != FIELDS:
            raise RouteManifestError("route manifest fields do not match schema")
        if document.get("schema_version") != 2:
            raise RouteManifestError("route manifest schema is unsupported")
        if document.get("route_kind") != NATIVE_IN_SWAP_DLN_NATIVE_OUT:
            raise RouteManifestError("route kind is unsupported")
        source_chain_id = _integer(
            document.get("source_chain_id"),
            "source_chain_id",
            positive=True,
        )
        destination_chain_id = _integer(
            document.get("destination_chain_id"),
            "destination_chain_id",
            positive=True,
        )
        if source_chain_id == destination_chain_id:
            raise RouteManifestError("source and destination chains must differ")
        topic = document.get("destination_fulfillment_topic")
        if not isinstance(topic, str) or topic.lower() != FULFILLED_ORDER_TOPIC:
            raise RouteManifestError("destination fulfillment topic is unsupported")
        try:
            proxy = canonical_address(
                document.get("destination_dln_proxy"),
                "destination_dln_proxy",
            )
        except ValueError as exc:
            raise RouteManifestError("destination DLN proxy is invalid") from exc
        source_swap_routers = _addresses(
            document.get("allowed_source_swap_routers"),
            "allowed_source_swap_routers",
        )
        source_swap_selectors = _selectors(
            document.get("allowed_source_swap_selectors"),
            "allowed_source_swap_selectors",
        )
        if len(source_swap_routers) != 1 or len(source_swap_selectors) != 1:
            raise RouteManifestError(
                "one route manifest must pin exactly one source swap router and selector"
            )
        return cls(
            route_id=_identifier(document.get("route_id"), "route_id"),
            route_kind=NATIVE_IN_SWAP_DLN_NATIVE_OUT,
            source_chain_alias=_identifier(
                document.get("source_chain_alias"),
                "source_chain_alias",
            ),
            destination_chain_alias=_identifier(
                document.get("destination_chain_alias"),
                "destination_chain_alias",
            ),
            source_chain_id=source_chain_id,
            destination_chain_id=destination_chain_id,
            allowed_bridge_routers=_addresses(
                document.get("allowed_bridge_routers"),
                "allowed_bridge_routers",
            ),
            allowed_source_swap_routers=source_swap_routers,
            allowed_source_swap_selectors=source_swap_selectors,
            allowed_intermediary_give_tokens=_addresses(
                document.get("allowed_intermediary_give_tokens"),
                "allowed_intermediary_give_tokens",
            ),
            allowed_dln_sources=_addresses(
                document.get("allowed_dln_sources"),
                "allowed_dln_sources",
            ),
            allowed_refund_recipients=_addresses(
                document.get("allowed_refund_recipients"),
                "allowed_refund_recipients",
            ),
            destination_dln_proxy=proxy,
            destination_fulfillment_topic=topic.lower(),
            maximum_total_spend_wei=_integer(
                document.get("maximum_total_spend_wei"),
                "maximum_total_spend_wei",
                positive=True,
            ),
            maximum_value_overhead_wei=_integer(
                document.get("maximum_value_overhead_wei"),
                "maximum_value_overhead_wei",
            ),
            maximum_price_impact_bps=_integer(
                document.get("maximum_price_impact_bps"),
                "maximum_price_impact_bps",
                maximum=10_000,
            ),
            maximum_swap_calldata_bytes=_integer(
                document.get("maximum_swap_calldata_bytes"),
                "maximum_swap_calldata_bytes",
                positive=True,
                maximum=131_072,
            ),
            maximum_metadata_bytes=_integer(
                document.get("maximum_metadata_bytes"),
                "maximum_metadata_bytes",
                maximum=16_384,
            ),
            maximum_quote_age_seconds=_integer(
                document.get("maximum_quote_age_seconds"),
                "maximum_quote_age_seconds",
                positive=True,
                maximum=3_600,
            ),
            maximum_plan_lifetime_seconds=_integer(
                document.get("maximum_plan_lifetime_seconds"),
                "maximum_plan_lifetime_seconds",
                positive=True,
                maximum=3_600,
            ),
        )

    @classmethod
    def _load_direct(cls, document: dict[str, object]) -> RouteManifest:
        if set(document) != DIRECT_FIELDS or document.get("schema_version") != 3:
            raise RouteManifestError("route manifest fields do not match direct schema")
        source_chain_id = _integer(
            document.get("source_chain_id"), "source_chain_id", positive=True
        )
        destination_chain_id = _integer(
            document.get("destination_chain_id"), "destination_chain_id", positive=True
        )
        if source_chain_id == destination_chain_id:
            raise RouteManifestError("source and destination chains must differ")
        codehash = document.get("source_dln_implementation_codehash")
        if (
            not isinstance(codehash, str)
            or not re.fullmatch(r"0x[0-9a-fA-F]{64}", codehash)
            or int(codehash, 16) == 0
        ):
            raise RouteManifestError("source DLN implementation codehash is invalid")
        topic = document.get("destination_fulfillment_topic")
        if not isinstance(topic, str) or topic.lower() != FULFILLED_ORDER_TOPIC:
            raise RouteManifestError("destination fulfillment topic is unsupported")
        reserve_tokens = _addresses([document.get("source_reserve_token")], "source_reserve_token")
        dln_proxy = _addresses([document.get("source_dln_proxy")], "source_dln_proxy")[0]
        return cls(
            route_id=_identifier(document.get("route_id"), "route_id"),
            route_kind=RESERVE_ERC20_DLN_NATIVE_OUT,
            source_chain_alias=_identifier(
                document.get("source_chain_alias"), "source_chain_alias"
            ),
            destination_chain_alias=_identifier(
                document.get("destination_chain_alias"), "destination_chain_alias"
            ),
            source_chain_id=source_chain_id,
            destination_chain_id=destination_chain_id,
            allowed_bridge_routers=(dln_proxy,),
            allowed_source_swap_routers=(reserve_tokens[0],),
            allowed_source_swap_selectors=("0xb9303701",),
            allowed_intermediary_give_tokens=reserve_tokens,
            allowed_dln_sources=(dln_proxy,),
            allowed_refund_recipients=(dln_proxy,),
            destination_dln_proxy=canonical_address(
                document.get("destination_dln_proxy"), "destination_dln_proxy"
            ),
            destination_fulfillment_topic=topic.lower(),
            maximum_total_spend_wei=_integer(
                document.get("maximum_total_spend_wei"), "maximum_total_spend_wei", positive=True
            ),
            maximum_value_overhead_wei=0,
            maximum_price_impact_bps=_integer(
                document.get("maximum_price_impact_bps"),
                "maximum_price_impact_bps",
                maximum=10_000,
            ),
            maximum_swap_calldata_bytes=4,
            maximum_metadata_bytes=_integer(
                document.get("maximum_metadata_bytes"), "maximum_metadata_bytes", maximum=16_384
            ),
            maximum_quote_age_seconds=_integer(
                document.get("maximum_quote_age_seconds"),
                "maximum_quote_age_seconds",
                positive=True,
                maximum=30,
            ),
            maximum_plan_lifetime_seconds=_integer(
                document.get("maximum_plan_lifetime_seconds"),
                "maximum_plan_lifetime_seconds",
                positive=True,
                maximum=30,
            ),
            source_reserve_token=reserve_tokens[0],
            source_dln_proxy=dln_proxy,
            source_dln_implementation_codehash=codehash.lower(),
            allowed_takers=_addresses(document.get("allowed_takers"), "allowed_takers"),
            maximum_fixed_native_fee_wei=_integer(
                document.get("maximum_fixed_native_fee_wei"),
                "maximum_fixed_native_fee_wei",
                positive=True,
            ),
            maximum_input_token_amount=_integer(
                document.get("maximum_input_token_amount"),
                "maximum_input_token_amount",
                positive=True,
            ),
            maximum_gas_limit=_integer(
                document.get("maximum_gas_limit"),
                "maximum_gas_limit",
                positive=True,
            ),
            expected_global_transfer_fee_bps=_integer(
                document.get("expected_global_transfer_fee_bps"),
                "expected_global_transfer_fee_bps",
                maximum=10_000,
            ),
        )

    def to_policy(self) -> RoutePolicy:
        return RoutePolicy(
            route_id=self.route_id,
            route_kind=self.route_kind,
            allowed_bridge_routers=self.allowed_bridge_routers,
            allowed_source_swap_routers=self.allowed_source_swap_routers,
            allowed_source_swap_selectors=self.allowed_source_swap_selectors,
            allowed_intermediary_give_tokens=self.allowed_intermediary_give_tokens,
            allowed_dln_sources=self.allowed_dln_sources,
            allowed_refund_recipients=self.allowed_refund_recipients,
            destination_dln_proxy=self.destination_dln_proxy,
            destination_fulfillment_topic=self.destination_fulfillment_topic,
            maximum_total_spend_wei=self.maximum_total_spend_wei,
            maximum_value_overhead_wei=self.maximum_value_overhead_wei,
            maximum_price_impact_bps=self.maximum_price_impact_bps,
            maximum_swap_calldata_bytes=self.maximum_swap_calldata_bytes,
            maximum_metadata_bytes=self.maximum_metadata_bytes,
            maximum_quote_age_seconds=self.maximum_quote_age_seconds,
            maximum_plan_lifetime_seconds=self.maximum_plan_lifetime_seconds,
            source_reserve_token=self.source_reserve_token,
            source_dln_proxy=self.source_dln_proxy,
            source_dln_implementation_codehash=self.source_dln_implementation_codehash,
            allowed_takers=self.allowed_takers,
            maximum_fixed_native_fee_wei=self.maximum_fixed_native_fee_wei,
            maximum_input_token_amount=self.maximum_input_token_amount,
            maximum_gas_limit=self.maximum_gas_limit,
            expected_global_transfer_fee_bps=self.expected_global_transfer_fee_bps,
        )

    def to_dict(self) -> JSONObject:
        if self.route_kind == RESERVE_ERC20_DLN_NATIVE_OUT:
            if (
                self.source_reserve_token is None
                or self.source_dln_proxy is None
                or self.source_dln_implementation_codehash is None
                or self.expected_global_transfer_fee_bps is None
            ):
                raise RouteManifestError("direct route manifest is incomplete")
            return {
                "schema_version": 3,
                "route_kind": self.route_kind,
                "route_id": self.route_id,
                "source_chain_alias": self.source_chain_alias,
                "destination_chain_alias": self.destination_chain_alias,
                "source_chain_id": self.source_chain_id,
                "destination_chain_id": self.destination_chain_id,
                "source_reserve_token": self.source_reserve_token,
                "source_dln_proxy": self.source_dln_proxy,
                "source_dln_implementation_codehash": self.source_dln_implementation_codehash,
                "allowed_takers": list(self.allowed_takers),
                "destination_dln_proxy": self.destination_dln_proxy,
                "destination_fulfillment_topic": self.destination_fulfillment_topic,
                "maximum_total_spend_wei": self.maximum_total_spend_wei,
                "maximum_input_token_amount": self.maximum_input_token_amount,
                "maximum_fixed_native_fee_wei": self.maximum_fixed_native_fee_wei,
                "maximum_gas_limit": self.maximum_gas_limit,
                "maximum_price_impact_bps": self.maximum_price_impact_bps,
                "expected_global_transfer_fee_bps": self.expected_global_transfer_fee_bps,
                "maximum_metadata_bytes": self.maximum_metadata_bytes,
                "maximum_quote_age_seconds": self.maximum_quote_age_seconds,
                "maximum_plan_lifetime_seconds": self.maximum_plan_lifetime_seconds,
            }
        return {
            "schema_version": 2,
            "route_kind": self.route_kind,
            "route_id": self.route_id,
            "source_chain_alias": self.source_chain_alias,
            "destination_chain_alias": self.destination_chain_alias,
            "source_chain_id": self.source_chain_id,
            "destination_chain_id": self.destination_chain_id,
            "allowed_bridge_routers": list(self.allowed_bridge_routers),
            "allowed_source_swap_routers": list(self.allowed_source_swap_routers),
            "allowed_source_swap_selectors": list(self.allowed_source_swap_selectors),
            "allowed_intermediary_give_tokens": list(
                self.allowed_intermediary_give_tokens
            ),
            "allowed_dln_sources": list(self.allowed_dln_sources),
            "allowed_refund_recipients": list(self.allowed_refund_recipients),
            "destination_dln_proxy": self.destination_dln_proxy,
            "destination_fulfillment_topic": self.destination_fulfillment_topic,
            "maximum_total_spend_wei": self.maximum_total_spend_wei,
            "maximum_value_overhead_wei": self.maximum_value_overhead_wei,
            "maximum_price_impact_bps": self.maximum_price_impact_bps,
            "maximum_swap_calldata_bytes": self.maximum_swap_calldata_bytes,
            "maximum_metadata_bytes": self.maximum_metadata_bytes,
            "maximum_quote_age_seconds": self.maximum_quote_age_seconds,
            "maximum_plan_lifetime_seconds": self.maximum_plan_lifetime_seconds,
        }

    @property
    def digest(self) -> str:
        encoded = canonical_json(self.to_dict()).encode("utf-8")
        return "sha256:" + sha256(encoded).hexdigest()
