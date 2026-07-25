from __future__ import annotations

from datetime import UTC, datetime

from test_approval import signed_approval

from agent_bridge_guard.approval import ApprovalSigningRequest
from agent_bridge_guard.execution_plan import ExecutionPlan
from agent_bridge_guard.models import Plan
from agent_bridge_guard.policy import TrustedPolicy
from agent_bridge_guard.signers.base import SignedTransaction
from agent_bridge_guard.store import (
    Operation,
    OperationState,
    PreparationClaim,
    PreparationClaimState,
)


def test_sensitive_dataclass_reprs_hide_raw_signatures_documents_and_nested_operation() -> None:
    raw_canary = b"DO_NOT_PRINT_RAW_SIGNED_TRANSACTION"
    signed = SignedTransaction(raw_canary, "0x" + "cd" * 32, "0x" + "11" * 20)
    approved = signed_approval(plan_id="plan-canary")
    signature_canary = approved.signature
    request = ApprovalSigningRequest.create(
        plan_id="plan-canary",
        authorization_id="auth-canary",
        actor="actor",
        subject_signer="0x1111111111111111111111111111111111111111",
        approved_at="2026-07-24T00:00:00Z",
        expires_at="2026-07-24T00:01:00Z",
        allowed_issuers=frozenset({"0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A"}),
    )
    operation = Operation(
        operation_id="operation",
        idempotency_key="key",
        approval_id="approval",
        plan=Plan.create({"value": "plan"}),
        signer="0x" + "11" * 20,
        source_chain_id=1,
        nonce=1,
        state=OperationState.RESERVED,
        created_at_ns=1,
        raw_signed_tx=raw_canary,
        tx_hash=None,
        source_finality_evidence=None,
        destination_fulfillment_evidence=None,
        events=(),
        approval=approved,
    )
    claim = PreparationClaim(operation, PreparationClaimState.OWNED, "DO_NOT_PRINT_TOKEN")
    plan = Plan.create({"private_plan_field": "DO_NOT_PRINT_CANONICAL_PLAN"})
    policy = TrustedPolicy(
        policy_id="policy",
        policy_version=1,
        digest="sha256:" + "ab" * 32,
        approval_issuers=frozenset(),
        authorized_manifests=(),
        chains=(),
        _document_json='{"private_policy_field":"DO_NOT_PRINT_CANONICAL_POLICY"}',
    )
    execution_plan = ExecutionPlan(
        plan=plan,
        route_id="route",
        route_kind="route-kind",
        signer="0x" + "11" * 20,
        transaction={
            "chain_id": 1,
            "data": "0xDO_NOT_PRINT_CALLDATA",
            "gas": 1,
            "max_fee_per_gas": 1,
            "max_priority_fee_per_gas": 1,
            "nonce": 1,
            "to": "0x" + "22" * 20,
            "value": 1,
        },
        source_chain_id=1,
        destination_chain_id=2,
        source_order_token="0x" + "33" * 20,
        source_order_amount_wei=1,
        source_swap_router="0x" + "44" * 20,
        source_dln_implementation_codehash=None,
        expected_global_transfer_fee_bps=None,
        recipient="0x" + "55" * 20,
        minimum_output_wei=1,
        destination_token="0x" + "66" * 20,
        destination_amount_wei=1,
        order_id="0x" + "77" * 32,
        allowed_taker=None,
        destination_dln_proxy="0x" + "88" * 20,
        destination_fulfillment_topic="0x" + "99" * 32,
        expires_at=datetime(2026, 7, 25, tzinfo=UTC),
    )

    rendered = "\n".join(
        map(repr, (signed, approved, request, operation, claim, plan, policy, execution_plan))
    )
    assert raw_canary.decode() not in rendered
    assert signature_canary not in rendered
    assert approved._document_json not in rendered
    assert request._document_json not in rendered
    assert request.eip191_message_hex not in rendered
    assert "DO_NOT_PRINT_TOKEN" not in rendered
    assert plan._document_json not in rendered
    assert policy._document_json not in rendered
    assert "DO_NOT_PRINT_CANONICAL_PLAN" not in rendered
    assert "DO_NOT_PRINT_CANONICAL_POLICY" not in rendered
    assert "DO_NOT_PRINT_CALLDATA" not in rendered
