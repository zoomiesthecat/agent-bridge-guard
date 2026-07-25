from datetime import UTC, datetime
from hashlib import sha256

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from agent_bridge_guard.approval import Approval, ApprovalError, ApprovalSigningRequest
from agent_bridge_guard.models import Plan

PRIVATE_KEY = "0x" + "11" * 32
ISSUER = Account.from_key(PRIVATE_KEY).address
SUBJECT_SIGNER = Account.from_key("0x" + "33" * 32).address


def plan() -> Plan:
    return Plan.create(
        {
            "created_at": "2026-07-24T21:50:00Z",
            "expires_at": "2026-07-24T22:00:00Z",
            "unsigned_transaction": {"chain_id": 42161, "nonce": 7},
        }
    )


def signed_approval(
    *, plan_id: str, issuer: str = ISSUER, private_key: str = PRIVATE_KEY
) -> Approval:
    payload = Approval.signing_payload(
        plan_id=plan_id,
        authorization_id="x-task:zoomies-lab-20260724",
        actor="operator",
        subject_signer=SUBJECT_SIGNER,
        approved_at="2026-07-24T21:51:00Z",
        expires_at="2026-07-24T21:55:00Z",
    )
    signature = (
        "0x" + Account.sign_message(encode_defunct(primitive=payload), private_key).signature.hex()
    )
    return Approval.create(
        plan_id=plan_id,
        authorization_id="x-task:zoomies-lab-20260724",
        actor="operator",
        subject_signer=SUBJECT_SIGNER,
        approved_at="2026-07-24T21:51:00Z",
        expires_at="2026-07-24T21:55:00Z",
        issuer=issuer,
        signature=signature,
    )


def test_operator_signature_binds_exact_plan_and_expires() -> None:
    approved = signed_approval(plan_id=plan().plan_id)
    parsed = Approval.parse(approved.to_dict())

    parsed.verify_for(
        plan(),
        allowed_issuers=frozenset({ISSUER}),
        expected_subject_signer=SUBJECT_SIGNER,
        at=datetime(2026, 7, 24, 21, 52, tzinfo=UTC),
    )

    with pytest.raises(ApprovalError, match="expired"):
        parsed.verify_for(
            plan(),
            allowed_issuers=frozenset({ISSUER}),
            expected_subject_signer=SUBJECT_SIGNER,
            at=datetime(2026, 7, 24, 21, 56, tzinfo=UTC),
        )
    with pytest.raises(ApprovalError, match="not yet valid"):
        parsed.verify_for(
            plan(),
            allowed_issuers=frozenset({ISSUER}),
            expected_subject_signer=SUBJECT_SIGNER,
            at=datetime(2026, 7, 24, 21, 50, tzinfo=UTC),
        )

    other = Plan.create({"unsigned_transaction": {"chain_id": 42161, "nonce": 8}})
    with pytest.raises(ApprovalError, match="different plan"):
        parsed.verify_for(
            other,
            allowed_issuers=frozenset({ISSUER}),
            expected_subject_signer=SUBJECT_SIGNER,
            at=datetime(2026, 7, 24, 21, 52, tzinfo=UTC),
        )


def test_tampering_wrong_key_and_missing_allowlist_fail_closed() -> None:
    approved = signed_approval(plan_id=plan().plan_id)
    tampered = approved.to_dict()
    tampered["actor"] = "attacker"
    tampered["approval_id"] = "eip191:" + sha256(
        Approval.signing_payload(
            plan_id=approved.plan_id,
            authorization_id=approved.authorization_id,
            actor="attacker",
            subject_signer=approved.subject_signer,
            approved_at=approved.approved_at,
            expires_at=approved.expires_at,
        )
    ).hexdigest()
    with pytest.raises(ApprovalError, match="does not match"):
        Approval.parse(tampered)

    second_issuer = Account.from_key("0x" + "22" * 32).address
    with pytest.raises(ApprovalError, match="not allowed"):
        approved.verify_for(
            plan(),
            allowed_issuers=frozenset({second_issuer}),
            expected_subject_signer=SUBJECT_SIGNER,
            at=datetime(2026, 7, 24, 21, 52, tzinfo=UTC),
        )
    with pytest.raises(ApprovalError, match="allowlist is required"):
        approved.verify_for(
            plan(),
            allowed_issuers=frozenset(),
            expected_subject_signer=SUBJECT_SIGNER,
            at=datetime(2026, 7, 24, 21, 52, tzinfo=UTC),
        )
    with pytest.raises(ApprovalError, match="different subject signer"):
        approved.verify_for(
            plan(),
            allowed_issuers=frozenset({ISSUER}),
            expected_subject_signer=second_issuer,
            at=datetime(2026, 7, 24, 21, 52, tzinfo=UTC),
        )


def test_signature_and_issuer_are_strict_and_private_material_is_not_rendered() -> None:
    approved = signed_approval(plan_id=plan().plan_id)
    document = approved.to_dict()
    document["issuer"] = Account.from_key("0x" + "22" * 32).address
    with pytest.raises(ApprovalError, match="does not match"):
        Approval.parse(document)

    document = approved.to_dict()
    document["extra"] = "forbidden"
    with pytest.raises(ApprovalError, match="invalid schema"):
        Approval.parse(document)

    with pytest.raises(ApprovalError, match="opaque identifier"):
        Approval.signing_payload(
            plan_id=plan().plan_id,
            authorization_id="operator said yes",
            actor="operator",
            subject_signer=SUBJECT_SIGNER,
            approved_at="2026-07-24T21:51:00Z",
            expires_at="2026-07-24T21:55:00Z",
        )
    assert PRIVATE_KEY not in repr(approved)
    assert (
        Approval.signing_payload_hex(
            plan_id=plan().plan_id,
            authorization_id="x-task:zoomies-lab-20260724",
            actor="operator",
            subject_signer=SUBJECT_SIGNER,
            approved_at="2026-07-24T21:51:00Z",
            expires_at="2026-07-24T21:55:00Z",
        )
        == "0x"
        + Approval.signing_payload(
            plan_id=plan().plan_id,
            authorization_id="x-task:zoomies-lab-20260724",
            actor="operator",
            subject_signer=SUBJECT_SIGNER,
            approved_at="2026-07-24T21:51:00Z",
            expires_at="2026-07-24T21:55:00Z",
        ).hex()
    )


def test_signing_request_round_trip_binds_plan_subject_message_and_allowlist() -> None:
    candidate = plan()
    request = ApprovalSigningRequest.create(
        plan_id=candidate.plan_id,
        authorization_id="x-task:zoomies-lab-20260724",
        actor="operator",
        subject_signer=SUBJECT_SIGNER,
        approved_at="2026-07-24T21:51:00Z",
        expires_at="2026-07-24T21:55:00Z",
        allowed_issuers=frozenset({ISSUER}),
    )

    parsed = ApprovalSigningRequest.parse(request.to_dict())
    parsed.verify_for(
        candidate,
        configured_issuers=frozenset({ISSUER}),
        expected_subject_signer=SUBJECT_SIGNER,
    )
    assert parsed.eip191_message_hex == Approval.signing_payload_hex(
        plan_id=candidate.plan_id,
        authorization_id="x-task:zoomies-lab-20260724",
        actor="operator",
        subject_signer=SUBJECT_SIGNER,
        approved_at="2026-07-24T21:51:00Z",
        expires_at="2026-07-24T21:55:00Z",
    )

    changed = request.to_dict()
    changed["eip191_message_hex"] = "0x00"
    with pytest.raises(ApprovalError, match="message mismatch"):
        ApprovalSigningRequest.parse(changed)

    second_issuer = Account.from_key("0x" + "22" * 32).address
    with pytest.raises(ApprovalError, match="allowlist changed"):
        parsed.verify_for(
            candidate,
            configured_issuers=frozenset({second_issuer}),
            expected_subject_signer=SUBJECT_SIGNER,
        )
