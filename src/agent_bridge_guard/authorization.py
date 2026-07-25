"""Protected-policy and route-manifest binding for every execution boundary."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import cast

from eth_utils import to_checksum_address  # type: ignore[attr-defined]

from .approval import Approval
from .execution_plan import ExecutionPlan
from .models import JSONObject, Plan
from .policy import TrustedPolicy
from .providers.debridge import (
    RESERVE_ERC20_DLN_NATIVE_OUT,
    decode_create_salted_order,
    deterministic_order_id,
)
from .route_manifest import RouteManifest

POLICY_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "policy_id",
        "policy_version",
        "policy_digest",
        "route_id",
        "route_manifest_digest",
        "route_manifest",
    }
)
PolicyLoader = Callable[[str | Path], TrustedPolicy]


class AuthorizationError(ValueError):
    """A plan is not authorized by the current protected policy."""


@dataclass(frozen=True, slots=True)
class ValidatedAuthorization:
    execution: ExecutionPlan
    policy: TrustedPolicy
    route: RouteManifest


def policy_binding(policy: TrustedPolicy, route: RouteManifest) -> JSONObject:
    if route.route_kind != RESERVE_ERC20_DLN_NATIVE_OUT:
        raise AuthorizationError("legacy source-aggregator routes are quarantined")
    if not policy.authorizes_manifest(route.route_id, route.digest):
        raise AuthorizationError("route manifest is not authorized by trusted policy")
    policy.confirmations_for(route.source_chain_id)
    policy.confirmations_for(route.destination_chain_id)
    return {
        "schema_version": 1,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "policy_digest": policy.digest,
        "route_id": route.route_id,
        "route_manifest_digest": route.digest,
        "route_manifest": route.to_dict(),
    }


def bind_plan(plan: Plan, policy: TrustedPolicy, route: RouteManifest) -> Plan:
    """Bind a provider-validated v1 plan to a protected policy as plan schema v2."""

    return plan.bind_policy(
        cast(dict[str, object], policy_binding(policy, route))
    )


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise AuthorizationError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuthorizationError(f"{label} must be a non-negative integer")
    return value


def _bytes_address(value: object, label: str) -> str:
    if not isinstance(value, bytes) or len(value) != 20:
        raise AuthorizationError(f"{label} must be a 20-byte address")
    return cast(str, to_checksum_address("0x" + value.hex()))


def _address(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise AuthorizationError(f"{label} must be an EVM address")
    try:
        return cast(str, to_checksum_address(value))
    except ValueError as exc:
        raise AuthorizationError(f"{label} must be an EVM address") from exc


def _validate_direct_plan(
    plan: Plan,
    execution: ExecutionPlan,
    route: RouteManifest,
) -> None:
    if route.route_kind != RESERVE_ERC20_DLN_NATIVE_OUT:
        raise AuthorizationError("legacy source-aggregator routes are quarantined")
    if (
        route.source_reserve_token is None
        or route.source_dln_proxy is None
        or route.source_dln_implementation_codehash is None
        or route.expected_global_transfer_fee_bps is None
    ):
        raise AuthorizationError("direct route manifest is incomplete")
    if execution.route_kind != route.route_kind or execution.route_id != route.route_id:
        raise AuthorizationError("plan route identity does not match manifest")
    if (
        execution.source_chain_id != route.source_chain_id
        or execution.destination_chain_id != route.destination_chain_id
    ):
        raise AuthorizationError("plan chains do not match manifest")
    if execution.transaction["to"].lower() != route.source_dln_proxy.lower():
        raise AuthorizationError("source DLN proxy does not match manifest")
    if execution.source_order_token.lower() != route.source_reserve_token.lower():
        raise AuthorizationError("source reserve token does not match manifest")
    if (
        execution.source_dln_implementation_codehash
        != route.source_dln_implementation_codehash
    ):
        raise AuthorizationError("source DLN implementation codehash does not match manifest")
    if (
        execution.expected_global_transfer_fee_bps
        != route.expected_global_transfer_fee_bps
    ):
        raise AuthorizationError("source DLN transfer fee does not match manifest")
    if execution.destination_dln_proxy.lower() != route.destination_dln_proxy.lower():
        raise AuthorizationError("destination DLN proxy does not match manifest")
    if (
        execution.destination_fulfillment_topic
        != route.destination_fulfillment_topic
    ):
        raise AuthorizationError("destination fulfillment topic does not match manifest")
    if (
        execution.allowed_taker is None
        or execution.allowed_taker.lower()
        not in {value.lower() for value in route.allowed_takers}
    ):
        raise AuthorizationError("destination taker is not authorized by manifest")

    body = plan.body()
    intent = _mapping(body.get("intent"), "plan intent")
    semantics = _mapping(body.get("decoded_semantics"), "decoded semantics")
    policy = _mapping(body.get("policy"), "plan route policy")
    source_amount = _integer(intent.get("amount_wei"), "source input amount")
    protocol_fee = _integer(
        semantics.get("protocol_fee_amount_wei"), "protocol fee amount"
    )
    total_spend = _integer(semantics.get("total_spend_wei"), "total spend")
    price_impact = _integer(semantics.get("price_impact_bps"), "price impact")
    fixed_fee = _integer(semantics.get("fix_fee_amount_wei"), "fixed fee")
    if source_amount == 0 or source_amount > route.maximum_input_token_amount:
        raise AuthorizationError("source input amount exceeds manifest")
    if protocol_fee != source_amount * route.expected_global_transfer_fee_bps // 10_000:
        raise AuthorizationError("protocol fee does not match manifest")
    if execution.source_order_amount_wei != source_amount - protocol_fee:
        raise AuthorizationError("source order amount does not match exact fee accounting")
    if fixed_fee != execution.transaction["value"]:
        raise AuthorizationError("fixed fee does not match transaction value")
    if fixed_fee > route.maximum_fixed_native_fee_wei:
        raise AuthorizationError("fixed native fee exceeds manifest")
    if execution.transaction["gas"] > route.maximum_gas_limit:
        raise AuthorizationError("gas limit exceeds manifest")
    if total_spend != execution.transaction["value"] + (
        execution.transaction["gas"] * execution.transaction["max_fee_per_gas"]
    ):
        raise AuthorizationError("total spend does not match transaction")
    if total_spend > route.maximum_total_spend_wei:
        raise AuthorizationError("total spend exceeds manifest")
    if price_impact > route.maximum_price_impact_bps:
        raise AuthorizationError("price impact exceeds manifest")
    expected_policy = {
        "route_id": route.route_id,
        "route_kind": route.route_kind,
        "maximum_total_spend_wei": route.maximum_total_spend_wei,
        "maximum_value_overhead_wei": 0,
        "maximum_price_impact_bps": route.maximum_price_impact_bps,
        "maximum_fixed_native_fee_wei": route.maximum_fixed_native_fee_wei,
        "maximum_input_token_amount": route.maximum_input_token_amount,
        "maximum_gas_limit": route.maximum_gas_limit,
        "expected_global_transfer_fee_bps": route.expected_global_transfer_fee_bps,
    }
    if dict(policy) != expected_policy:
        raise AuthorizationError("embedded route policy does not match manifest")
    raw_data = execution.transaction["data"]
    calldata_digest = semantics.get("transaction_calldata_sha256")
    if calldata_digest != sha256(bytes.fromhex(raw_data[2:])).hexdigest():
        raise AuthorizationError("transaction calldata digest mismatch")

    try:
        decoded = decode_create_salted_order(raw_data)
    except ValueError as exc:
        raise AuthorizationError("transaction is not a direct createSaltedOrder call") from exc
    if (
        decoded.get("affiliate_fee") != b""
        or decoded.get("permit") != b""
        or decoded.get("referral_code") != 0
    ):
        raise AuthorizationError("affiliate, referral, and permit fields must be empty")
    metadata = decoded.get("metadata")
    if not isinstance(metadata, bytes) or len(metadata) > route.maximum_metadata_bytes:
        raise AuthorizationError("metadata exceeds manifest")
    order = _mapping(decoded.get("order"), "createSaltedOrder order")
    if _address(order.get("give_token"), "order give token").lower() != (
        route.source_reserve_token.lower()
    ):
        raise AuthorizationError("order give token does not match manifest")
    if _integer(order.get("give_amount"), "order give amount") != (
        source_amount
    ):
        raise AuthorizationError("order give amount does not match gross input")
    if _address(order.get("give_authority"), "order give authority").lower() != (
        execution.signer.lower()
    ):
        raise AuthorizationError("order source authority does not match signer")
    if _integer(order.get("take_chain_id"), "order destination chain") != (
        execution.destination_chain_id
    ):
        raise AuthorizationError("order destination chain does not match plan")
    if _bytes_address(order.get("take_token"), "order take token").lower() != (
        execution.destination_token.lower()
    ):
        raise AuthorizationError("order destination token does not match plan")
    if _bytes_address(order.get("receiver"), "order receiver").lower() != (
        execution.recipient.lower()
    ):
        raise AuthorizationError("order receiver does not match plan")
    if _bytes_address(order.get("take_authority"), "order authority").lower() != (
        execution.recipient.lower()
    ):
        raise AuthorizationError("order authority does not match plan")
    if _integer(order.get("take_amount"), "order take amount") != (
        execution.destination_amount_wei
    ):
        raise AuthorizationError("order destination amount does not match plan")
    if order.get("external_call") != b"":
        raise AuthorizationError("destination external call is forbidden")
    cancel_beneficiary = order.get("cancel_beneficiary")
    if cancel_beneficiary not in (b"", bytes.fromhex(execution.signer[2:])):
        raise AuthorizationError("cancel beneficiary does not match signer")
    if _bytes_address(order.get("allowed_taker"), "allowed taker").lower() != (
        execution.allowed_taker.lower()
    ):
        raise AuthorizationError("allowed taker does not match plan")
    recomputed_order_id = deterministic_order_id(
        {
            **order,
            "give_chain_id": execution.source_chain_id,
            "give_amount": execution.source_order_amount_wei,
        },
        maker=execution.signer,
    )
    if recomputed_order_id != execution.order_id:
        raise AuthorizationError("deterministic order ID mismatch")


def validate_bound_plan(
    plan: Plan,
    policy: TrustedPolicy,
    *,
    at: datetime | None = None,
    allow_expired: bool = False,
) -> tuple[ExecutionPlan, RouteManifest]:
    if plan.schema_version != 2:
        raise AuthorizationError("legacy unbound plan cannot authorize execution")
    binding = _mapping(plan.body().get("policy_binding"), "policy binding")
    if set(binding) != POLICY_BINDING_FIELDS or binding.get("schema_version") != 1:
        raise AuthorizationError("policy binding fields do not match schema")
    if (
        binding.get("policy_id") != policy.policy_id
        or binding.get("policy_version") != policy.policy_version
        or binding.get("policy_digest") != policy.digest
    ):
        raise AuthorizationError("trusted policy changed")
    manifest_value = binding.get("route_manifest")
    if not isinstance(manifest_value, dict):
        raise AuthorizationError("route manifest snapshot must be an object")
    try:
        route = RouteManifest.parse_document(cast(dict[str, object], manifest_value))
    except ValueError as exc:
        raise AuthorizationError("route manifest snapshot is invalid") from exc
    if (
        binding.get("route_id") != route.route_id
        or binding.get("route_manifest_digest") != route.digest
    ):
        raise AuthorizationError("route manifest digest mismatch")
    if not policy.authorizes_manifest(route.route_id, route.digest):
        raise AuthorizationError("route manifest was revoked")
    policy.confirmations_for(route.source_chain_id)
    policy.confirmations_for(route.destination_chain_id)
    execution = ExecutionPlan.from_plan(
        plan,
        at=at,
        allow_expired=allow_expired,
    )
    _validate_direct_plan(plan, execution, route)
    return execution, route


class AuthorizationValidator:
    """Reload protected policy and validate plan plus approval at each side effect."""

    def __init__(
        self,
        policy_path: str | Path,
        *,
        loader: PolicyLoader = TrustedPolicy.load,
    ) -> None:
        self._policy_path = Path(policy_path)
        self._loader = loader

    def validate(
        self,
        plan: Plan,
        approval: Approval,
        *,
        at: datetime | None = None,
    ) -> ValidatedAuthorization:
        policy = self._loader(self._policy_path)
        execution, route = validate_bound_plan(plan, policy, at=at)
        approval.verify_for(
            plan,
            allowed_issuers=policy.approval_issuers,
            expected_subject_signer=execution.signer,
            at=at,
            require_reviewable=True,
        )
        return ValidatedAuthorization(execution=execution, policy=policy, route=route)
