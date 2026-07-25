"""Extra crash-recovery and fenced-store regression coverage."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_authorization import bound_plan, reviewable_approval

from agent_bridge_guard.execution_plan import ExecutionPlan
from agent_bridge_guard.store import (
    OperationState,
    PreparationClaimState,
    SQLiteOperationStore,
    StateTransitionError,
    StoreError,
)
from agent_bridge_guard.verification import verify_source_receipt


def reserved_store(tmp_path: Path) -> tuple[SQLiteOperationStore, str]:
    plan, _, _ = bound_plan()
    approval = reviewable_approval(plan)
    execution = ExecutionPlan.from_plan(plan, allow_expired=True)
    store = SQLiteOperationStore(tmp_path / "operations.db")
    operation = store.reserve_operation(
        plan,
        idempotency_key="coverage-operation",
        signer=execution.signer,
        source_chain_id=execution.source_chain_id,
        nonce=execution.transaction["nonce"],
        approval=approval,
    )
    return store, operation.operation_id


def prepared_store(tmp_path: Path) -> tuple[SQLiteOperationStore, str]:
    store, operation_id = reserved_store(tmp_path)
    claim = store.claim_preparation(
        operation_id,
        kind="coverage-local",
        fingerprint="coverage-fingerprint",
        replay_safe=True,
    )
    assert claim.token is not None
    store.complete_preparation(operation_id, claim.token, b"\x01")
    return store, operation_id


def test_fenced_preparation_rejects_empty_claim_and_reports_terminal_states(tmp_path: Path) -> None:
    store, operation_id = reserved_store(tmp_path)

    with pytest.raises(ValueError, match="kind and fingerprint"):
        store.claim_preparation(operation_id, kind="", fingerprint="", replay_safe=True)

    claim = store.claim_preparation(
        operation_id,
        kind="coverage-local",
        fingerprint="coverage-fingerprint",
        replay_safe=True,
    )
    assert claim.token is not None
    failed = store.fail_preparation(operation_id, claim.token)
    assert failed.state is OperationState.FAILED_PRE_BROADCAST
    assert (
        store.claim_preparation(
            operation_id,
            kind="coverage-local",
            fingerprint="coverage-fingerprint",
            replay_safe=True,
        ).state
        is PreparationClaimState.FAILED
    )

    reopened = store.retry_pre_broadcast(operation_id)
    assert reopened.state is OperationState.RESERVED


def test_prepared_and_nonreserved_operations_cannot_be_claimed_again(tmp_path: Path) -> None:
    store, operation_id = prepared_store(tmp_path)

    assert (
        store.claim_preparation(
            operation_id,
            kind="coverage-local",
            fingerprint="coverage-fingerprint",
            replay_safe=True,
        ).state
        is PreparationClaimState.PREPARED
    )
    attempted = store.append_state_event(operation_id, OperationState.BROADCAST_ATTEMPTED)
    assert (
        store.claim_preparation(
            attempted.operation_id,
            kind="coverage-local",
            fingerprint="coverage-fingerprint",
            replay_safe=True,
        ).state
        is PreparationClaimState.UNAVAILABLE
    )


def test_proof_mapping_apis_remain_closed_and_failure_proof_is_durable(tmp_path: Path) -> None:
    store, operation_id = prepared_store(tmp_path)
    pending = store.append_state_event(operation_id, OperationState.BROADCAST_ATTEMPTED)
    pending = store.append_state_event(pending.operation_id, OperationState.SOURCE_PENDING)
    assert pending.tx_hash is not None

    with pytest.raises(StateTransitionError, match="verifier-produced"):
        store.record_source_failure(operation_id, {})
    with pytest.raises(StateTransitionError, match="verifier-produced"):
        store.record_destination_fulfillment(operation_id, {})

    proof = verify_source_receipt(
        operation_id=operation_id,
        plan=pending.plan,
        receipt={
            "transactionHash": pending.tx_hash,
            "blockNumber": 3,
            "blockHash": "0x" + "ab" * 32,
            "status": 0,
        },
        chain_id=pending.source_chain_id,
        transaction_hash=pending.tx_hash,
        confirmations=2,
        receipt_status=0,
    )
    failed = store._commit_source_failure(proof)

    assert failed.state is OperationState.SOURCE_FAILED
    assert failed.source_finality_evidence is not None
    assert failed.source_finality_evidence["receipt_status"] == 0


@pytest.mark.parametrize(
    ("column", "value", "message"),
    [
        ("plan_json", "not-json", "persisted plan"),
        ("plan_json", "[]", "persisted plan"),
        ("approval_json", "not-json", "persisted approval"),
        ("approval_json", "[]", "persisted approval"),
    ],
)
def test_corrupt_persisted_plan_or_approval_fails_closed(
    tmp_path: Path, column: str, value: str, message: str
) -> None:
    store, operation_id = reserved_store(tmp_path)
    with store._transaction() as connection:
        connection.execute(
            f"UPDATE operations SET {column} = ? WHERE operation_id = ?",  # noqa: S608
            (value, operation_id),
        )

    with pytest.raises(StoreError, match=message):
        store.get_operation(operation_id)
