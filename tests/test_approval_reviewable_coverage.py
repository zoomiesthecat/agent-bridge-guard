from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from test_authorization import (
    OPERATOR,
    SIGNER,
    bound_plan,
    reviewable_approval,
)

from agent_bridge_guard.approval import (
    Approval,
    ApprovalError,
    ApprovalSigningRequest,
)
from agent_bridge_guard.models import Plan

APPROVED_AT = "2026-07-24T00:00:01Z"
EXPIRES_AT = "2026-07-24T00:00:25Z"


def request() -> tuple[Plan, ApprovalSigningRequest]:
    plan, _, _ = bound_plan()
    return plan, ApprovalSigningRequest.create_reviewable(
        plan=plan,
        authorization_id="hunt-1",
        actor="operator",
        approved_at=APPROVED_AT,
        expires_at=EXPIRES_AT,
    )


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda value: value.update({"extra": True}), "invalid schema"),
        (
            lambda value: value.update({"artifact_type": "wrong"}),
            "unsupported approval signing request",
        ),
        (
            lambda value: value.update({"eip191_message_hex": "0x00"}),
            "message mismatch",
        ),
    ],
)
def test_reviewable_signing_request_parse_rejects_mutations(
    mutate: object, match: str
) -> None:
    _, signing_request = request()
    document = signing_request.to_dict()
    mutate(document)  # type: ignore[operator]

    with pytest.raises(ApprovalError, match=match):
        ApprovalSigningRequest.parse(document)


def test_reviewable_signing_request_verification_rejects_wrong_bindings() -> None:
    plan, signing_request = request()
    body = plan.body()
    intent = body["intent"]
    assert isinstance(intent, dict)
    intent["minimum_output_wei"] = 1
    other_plan = Plan.create(body, schema_version=2)

    with pytest.raises(ApprovalError, match="different plan"):
        signing_request.verify_for(other_plan, expected_subject_signer=SIGNER)
    with pytest.raises(ApprovalError, match="different subject"):
        signing_request.verify_for(plan, expected_subject_signer="0x" + "ee" * 20)

    forged_intent = dict(signing_request.intent or {})
    forged_intent["recipient"] = "0x" + "ee" * 20
    forged = replace(signing_request, intent=forged_intent)
    with pytest.raises(ApprovalError, match="intent does not match"):
        forged.verify_for(plan, expected_subject_signer=SIGNER)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda value: value.update({"extra": True}), "invalid schema"),
        (lambda value: value.update({"artifact_type": "wrong"}), "unsupported approval schema"),
        (lambda value: value.update({"intent": []}), "intent has an invalid schema"),
        (lambda value: value.update({"approval_id": "eip191:wrong"}), "approval_id mismatch"),
        (lambda value: value.update({"signature": 1}), "signature must be a string"),
        (
            lambda value: value.update({"issuer": "0x" + "ee" * 20}),
            "issuer does not match",
        ),
    ],
)
def test_reviewable_approval_parse_rejects_mutations(
    mutate: object, match: str
) -> None:
    plan, _, _ = bound_plan()
    document = reviewable_approval(plan).to_dict()
    mutate(document)  # type: ignore[operator]

    with pytest.raises(ApprovalError, match=match):
        Approval.parse(document)


def test_reviewable_approval_verification_rejects_time_and_authority_errors() -> None:
    plan, _, _ = bound_plan()
    approval = reviewable_approval(plan)
    valid_time = datetime(2026, 7, 24, 0, 0, 10, tzinfo=UTC)

    with pytest.raises(ApprovalError, match="allowlist is required"):
        approval.verify_for(
            plan,
            allowed_issuers=frozenset(),
            expected_subject_signer=SIGNER,
            at=valid_time,
        )
    with pytest.raises(ApprovalError, match="different subject signer"):
        approval.verify_for(
            plan,
            allowed_issuers=frozenset({OPERATOR}),
            expected_subject_signer="0x" + "ee" * 20,
            at=valid_time,
        )
    forged_intent = deepcopy(approval.intent)
    assert isinstance(forged_intent, dict)
    forged_intent["recipient"] = "0x" + "ee" * 20
    with pytest.raises(ApprovalError, match="intent does not match"):
        replace(approval, intent=forged_intent).verify_for(
            plan,
            allowed_issuers=frozenset({OPERATOR}),
            expected_subject_signer=SIGNER,
            at=valid_time,
        )
    with pytest.raises(ApprovalError, match="issuer is not allowed"):
        approval.verify_for(
            plan,
            allowed_issuers=frozenset({"0x" + "ee" * 20}),
            expected_subject_signer=SIGNER,
            at=valid_time,
        )
    with pytest.raises(ApprovalError, match="timezone-aware"):
        approval.verify_for(
            plan,
            allowed_issuers=frozenset({OPERATOR}),
            expected_subject_signer=SIGNER,
            at=datetime(2026, 7, 24, 0, 0, 10),
        )
    with pytest.raises(ApprovalError, match="not yet valid"):
        approval.verify_for(
            plan,
            allowed_issuers=frozenset({OPERATOR}),
            expected_subject_signer=SIGNER,
            at=datetime(2026, 7, 24, 0, 0, 0, tzinfo=UTC),
        )
    with pytest.raises(ApprovalError, match="expired"):
        approval.verify_for(
            plan,
            allowed_issuers=frozenset({OPERATOR}),
            expected_subject_signer=SIGNER,
            at=datetime(2026, 7, 24, 0, 0, 25, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("policy_id", "bad policy", "policy_id"),
        ("policy_version", 0, "policy_version"),
        ("policy_digest", "sha256:bad", "policy_digest"),
        ("route_manifest_digest", "sha256:bad", "route_manifest_digest"),
    ],
)
def test_reviewable_intent_rejects_invalid_policy_binding(
    field: str, value: object, match: str
) -> None:
    plan, _, _ = bound_plan()
    body = plan.body()
    binding = body["policy_binding"]
    assert isinstance(binding, dict)
    binding[field] = value
    mutated = Plan.create(body, schema_version=2)

    with pytest.raises(ApprovalError, match=match):
        ApprovalSigningRequest.create_reviewable(
            plan=mutated,
            authorization_id="hunt-1",
            actor="operator",
            approved_at=APPROVED_AT,
            expires_at=EXPIRES_AT,
        )


def test_reviewable_approval_cannot_outlive_plan() -> None:
    plan, _, _ = bound_plan()

    with pytest.raises(ApprovalError, match="must not exceed plan expiry"):
        ApprovalSigningRequest.create_reviewable(
            plan=plan,
            authorization_id="hunt-1",
            actor="operator",
            approved_at=APPROVED_AT,
            expires_at="2026-07-24T00:00:31Z",
        )
