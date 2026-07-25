from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from test_debridge_provider import (
    ALLOWED_TAKER,
    AMOUNT,
    BRIDGE_ROUTER,
    DESTINATION_CHAIN,
    DESTINATION_PROXY,
    GAS_LIMIT,
    INTERMEDIARY_TOKEN,
    OUTPUT,
    RECIPIENT,
    SIGNER,
    SOURCE_CHAIN,
    direct_quote,
)

from agent_bridge_guard.approval import (
    APPROVAL_DOMAIN,
    Approval,
    ApprovalError,
    ApprovalSigningRequest,
    approval_intent,
)
from agent_bridge_guard.authorization import (
    AuthorizationError,
    bind_plan,
    validate_bound_plan,
)
from agent_bridge_guard.models import Plan, canonical_json
from agent_bridge_guard.policy import TrustedPolicy
from agent_bridge_guard.providers.debridge import QuoteRequest, create_plan, validate_quote
from agent_bridge_guard.route_manifest import RouteManifest

OPERATOR_KEY = "0x" + "99" * 32
OPERATOR = Account.from_key(OPERATOR_KEY).address
CREATED = "2026-07-24T00:00:00Z"
PLAN_EXPIRES = "2026-07-24T00:00:30Z"


def direct_route_document() -> dict[str, object]:
    return {
        "schema_version": 3,
        "route_kind": "reserve_erc20_dln_native_out",
        "route_id": "test-direct-reserve-route",
        "source_chain_alias": "arbitrum",
        "destination_chain_alias": "robinhood",
        "source_chain_id": SOURCE_CHAIN,
        "destination_chain_id": DESTINATION_CHAIN,
        "source_reserve_token": INTERMEDIARY_TOKEN,
        "source_dln_proxy": BRIDGE_ROUTER,
        "source_dln_implementation_codehash": "0x" + "aa" * 32,
        "allowed_takers": [ALLOWED_TAKER],
        "destination_dln_proxy": DESTINATION_PROXY,
        "destination_fulfillment_topic": (
            "0xc164aca37b9805a1c9027b6f32260a069723a82926f6e9ece4926e4dd3ea8ecf"
        ),
        "maximum_total_spend_wei": 500,
        "maximum_input_token_amount": AMOUNT,
        "maximum_fixed_native_fee_wei": 10,
        "maximum_gas_limit": GAS_LIMIT,
        "maximum_price_impact_bps": 10,
        "expected_global_transfer_fee_bps": 100,
        "maximum_metadata_bytes": 32,
        "maximum_quote_age_seconds": 30,
        "maximum_plan_lifetime_seconds": 30,
    }


def bound_plan() -> tuple[Plan, TrustedPolicy, RouteManifest]:
    route = RouteManifest.parse_document(direct_route_document())
    request = QuoteRequest(
        source_chain_id=SOURCE_CHAIN,
        destination_chain_id=DESTINATION_CHAIN,
        amount_wei=AMOUNT,
        minimum_output_wei=OUTPUT,
        signer=SIGNER,
        recipient=RECIPIENT,
        nonce=7,
        created_at=CREATED,
        expires_at=PLAN_EXPIRES,
    )
    quote = validate_quote(
        direct_quote(),
        request,
        route.to_policy(),
        now=datetime(2026, 7, 24, tzinfo=UTC),
    )
    unbound = create_plan(quote, request, route.to_policy())
    policy = TrustedPolicy.parse(
        {
            "schema_version": 1,
            "artifact_type": "trusted_policy",
            "policy_id": "test-production",
            "policy_version": 1,
            "approval_issuers": [OPERATOR],
            "authorized_route_manifests": [{"route_id": route.route_id, "sha256": route.digest}],
            "chains": [
                {"chain_id": SOURCE_CHAIN, "confirmations": 12},
                {"chain_id": DESTINATION_CHAIN, "confirmations": 20},
            ],
        }
    )
    return bind_plan(unbound, policy, route), policy, route


def reviewable_approval(plan: Plan) -> Approval:
    payload = Approval.signing_payload_reviewable(
        plan=plan,
        authorization_id="hunt-1",
        actor="operator",
        approved_at="2026-07-24T00:00:01Z",
        expires_at="2026-07-24T00:00:25Z",
    )
    signature = (
        "0x"
        + Account.sign_message(
            encode_defunct(primitive=payload),
            OPERATOR_KEY,
        ).signature.hex()
    )
    return Approval.create_reviewable(
        plan=plan,
        authorization_id="hunt-1",
        actor="operator",
        approved_at="2026-07-24T00:00:01Z",
        expires_at="2026-07-24T00:00:25Z",
        signature=signature,
    )


def test_bound_plan_revalidates_full_manifest_and_current_policy() -> None:
    plan, policy, route = bound_plan()

    execution, parsed_route = validate_bound_plan(
        plan,
        policy,
        at=datetime(2026, 7, 24, 0, 0, 10, tzinfo=UTC),
    )

    assert plan.schema_version == 2
    assert execution.route_id == route.route_id
    assert parsed_route.digest == route.digest

    revoked = TrustedPolicy.parse(
        {
            **policy.to_dict(),
            "policy_version": 2,
        }
    )
    with pytest.raises(AuthorizationError, match="trusted policy changed"):
        validate_bound_plan(
            plan,
            revoked,
            at=datetime(2026, 7, 24, 0, 0, 10, tzinfo=UTC),
        )


def test_copied_policy_binding_cannot_authorize_forged_execution_fields() -> None:
    plan, policy, _ = bound_plan()
    body = plan.body()
    semantics = body["decoded_semantics"]
    assert isinstance(semantics, dict)
    semantics["total_spend_wei"] = 499
    forged = Plan.create(body, schema_version=2)

    with pytest.raises(AuthorizationError, match="total spend"):
        validate_bound_plan(
            forged,
            policy,
            at=datetime(2026, 7, 24, 0, 0, 10, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("decoded_semantics", "fix_fee_amount_wei"), 99, "fixed fee"),
        (("decoded_semantics", "price_impact_bps"), 11, "price impact"),
        (("decoded_semantics", "transaction_calldata_sha256"), "bad", "calldata digest"),
        (("policy", "maximum_gas_limit"), 1, "embedded route policy"),
        (
            ("provider", "source_dln_implementation_codehash"),
            "0x" + "bb" * 32,
            "implementation codehash",
        ),
    ],
)
def test_bound_plan_rejects_direct_field_mutations(
    path: tuple[str, str], value: object, message: str
) -> None:
    plan, policy, _ = bound_plan()
    body = plan.body()
    section = body[path[0]]
    assert isinstance(section, dict)
    section[path[1]] = value
    forged = Plan.create(body, schema_version=2)

    with pytest.raises(AuthorizationError, match=message):
        validate_bound_plan(forged, policy, at=datetime(2026, 7, 24, 0, 0, 10, tzinfo=UTC))


def test_reviewable_request_and_approval_bind_exact_material_intent() -> None:
    plan, policy, _ = bound_plan()
    request = ApprovalSigningRequest.create_reviewable(
        plan=plan,
        authorization_id="hunt-1",
        actor="operator",
        approved_at="2026-07-24T00:00:01Z",
        expires_at="2026-07-24T00:00:25Z",
    )
    document = request.to_dict()

    assert "allowed_issuers" not in document
    assert "issuer" not in document
    assert document["intent"] == approval_intent(plan)
    assert document["intent"]["source_asset_kind"] == "erc20"
    assert document["intent"]["source_gross_amount_wei"] == AMOUNT
    assert document["intent"]["max_transaction_spend_wei"] == 205
    assert document["intent"]["transaction_calldata_sha256"].startswith("sha256:")

    approval = reviewable_approval(plan)
    approval.verify_for(
        plan,
        allowed_issuers=policy.approval_issuers,
        expected_subject_signer=SIGNER,
        at=datetime(2026, 7, 24, 0, 0, 10, tzinfo=UTC),
        require_reviewable=True,
    )
    assert approval.issuer == OPERATOR


def test_valid_signature_over_false_display_intent_is_rejected_for_plan() -> None:
    plan, policy, _ = bound_plan()
    candidate = reviewable_approval(plan).to_dict()
    false_intent = candidate["intent"]
    assert isinstance(false_intent, dict)
    false_intent["recipient"] = SIGNER
    body = {
        key: candidate[key]
        for key in (
            "schema_version",
            "artifact_type",
            "plan_id",
            "authorization_id",
            "actor",
            "approved_at",
            "expires_at",
            "intent",
        )
    }
    payload = canonical_json({"domain": APPROVAL_DOMAIN, "approval": body}).encode()
    signature = (
        "0x"
        + Account.sign_message(
            encode_defunct(primitive=payload),
            OPERATOR_KEY,
        ).signature.hex()
    )
    candidate["signature"] = signature
    candidate["issuer"] = OPERATOR
    candidate["approval_id"] = "eip191:" + sha256(payload).hexdigest()
    forged = Approval.parse(candidate)

    with pytest.raises(ApprovalError, match="intent does not match plan"):
        forged.verify_for(
            plan,
            allowed_issuers=policy.approval_issuers,
            expected_subject_signer=SIGNER,
            at=datetime(2026, 7, 24, 0, 0, 10, tzinfo=UTC),
            require_reviewable=True,
        )


def test_legacy_approval_cannot_authorize_production_execution() -> None:
    plan, policy, _ = bound_plan()
    payload = Approval.signing_payload(
        plan_id=plan.plan_id,
        authorization_id="hunt-1",
        actor="operator",
        subject_signer=SIGNER,
        approved_at="2026-07-24T00:00:01Z",
        expires_at="2026-07-24T00:00:25Z",
    )
    signature = (
        "0x"
        + Account.sign_message(
            encode_defunct(primitive=payload),
            OPERATOR_KEY,
        ).signature.hex()
    )
    legacy = Approval.create(
        plan_id=plan.plan_id,
        authorization_id="hunt-1",
        actor="operator",
        subject_signer=SIGNER,
        approved_at="2026-07-24T00:00:01Z",
        expires_at="2026-07-24T00:00:25Z",
        issuer=OPERATOR,
        signature=signature,
    )

    with pytest.raises(ApprovalError, match="legacy approval"):
        legacy.verify_for(
            plan,
            allowed_issuers=policy.approval_issuers,
            expected_subject_signer=SIGNER,
            at=datetime(2026, 7, 24, 0, 0, 10, tzinfo=UTC),
            require_reviewable=True,
        )
