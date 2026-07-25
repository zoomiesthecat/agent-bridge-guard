"""Failure-path coverage for durable execution-engine reconciliation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from test_authorization import OPERATOR_KEY, bound_plan, reviewable_approval
from test_engine import (
    NOW,
    FakeRpcClient,
    FakeRpcPool,
    FixtureAuthorization,
    MemorySigner,
    approval_for,
    engine,
    make_plan,
)

from agent_bridge_guard.approval import Approval
from agent_bridge_guard.engine import (
    DestinationVerificationError,
    ExecutionEngine,
    NeedsReconciliation,
    PreBroadcastFailure,
    SubmissionUnknown,
)
from agent_bridge_guard.execution_plan import ExecutionPlan
from agent_bridge_guard.models import Plan
from agent_bridge_guard.rpc import (
    NeedsReconciliationError,
    RpcClient,
    RpcPool,
    RpcTransportError,
    TransactionFailedError,
)
from agent_bridge_guard.store import Operation, OperationState, SQLiteOperationStore
from agent_bridge_guard.verification import (
    VerificationError,
    VerifiedDestinationFulfillment,
    VerifiedSourceReceipt,
    verify_destination_receipt,
    verify_source_receipt,
)


def submit_unknown_operation(tmp_path: Path) -> tuple[ExecutionEngine, FakeRpcPool, Operation]:
    """Create an operation whose first broadcast outcome is deliberately unknown."""

    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer, send_failures=1)
    plan = make_plan(signer.address)

    with pytest.raises(SubmissionUnknown):
        guard.execute(
            plan,
            approval_for(plan, subject_signer=signer.address),
            idempotency_key="unknown-submission",
            signer=signer,
            at=NOW,
        )

    return guard, pool, guard.store.get_operation_by_idempotency_key("unknown-submission")


def test_stock_engine_rejects_duck_typed_rpc_pools(tmp_path: Path) -> None:
    pool = FakeRpcPool(FakeRpcClient({}), FakeRpcClient({}))
    with pytest.raises(TypeError, match="concrete two-endpoint RpcPool"):
        ExecutionEngine(
            SQLiteOperationStore(tmp_path / "operations.db"),
            pool,  # type: ignore[arg-type]
            policy_path="/protected-policy.json",
        )
    with pytest.raises(TypeError, match="concrete two-endpoint RpcPool"):
        ExecutionEngine._require_rpc_pool(pool, label="destination")


def stock_rpc_pool() -> RpcPool:
    pool = object.__new__(RpcPool)
    object.__setattr__(pool, "primary", RpcClient("https://one.example/rpc"))
    object.__setattr__(pool, "secondary", RpcClient("https://two.example/rpc"))
    object.__setattr__(pool, "chain_id", 42161)
    return pool


def test_stock_engine_keeps_a_validated_rpc_pool_immutable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pool = stock_rpc_pool()
    guard = ExecutionEngine(
        SQLiteOperationStore(tmp_path / "operations.db"),
        pool,
        policy_path="/protected-policy.json",
    )
    calls: list[tuple[RpcPool, str, int, int | None]] = []

    def finality(
        rpc: RpcPool, transaction_hash: str, confirmations: int, *, max_polls: int | None
    ) -> dict[str, object]:
        calls.append((rpc, transaction_hash, confirmations, max_polls))
        return {"status": "0x1"}

    monkeypatch.setattr("agent_bridge_guard.engine.wait_for_final_receipt", finality)
    with pytest.raises(FrozenInstanceError):
        pool.primary.transport = lambda *_args: b""  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        pool.secondary.endpoint = pool.primary.endpoint  # type: ignore[misc]

    assert guard._wait_for_finality(pool, "0x" + "ab" * 32, 1, max_polls=2) == {
        "status": "0x1"
    }
    assert calls == [(pool, "0x" + "ab" * 32, 1, 2)]


def test_stock_engine_rejects_nonpositive_confirmations_and_invalid_canonical_plan(
    tmp_path: Path,
) -> None:
    pool = stock_rpc_pool()
    with pytest.raises(ValueError, match="confirmations"):
        ExecutionEngine(
            SQLiteOperationStore(tmp_path / "zero.db"),
            pool,
            policy_path="/protected-policy.json",
            source_confirmations=0,
        )

    signer = MemorySigner()
    plan = make_plan(signer.address)
    body = plan.body()
    transaction = body["unsigned_transaction"]
    assert isinstance(transaction, dict)
    transaction["chain_id"] = 1
    invalid = Plan.create(body, schema_version=2)
    guard = ExecutionEngine(
        SQLiteOperationStore(tmp_path / "invalid.db"),
        pool,
        policy_path="/protected-policy.json",
    )
    with pytest.raises(ValueError, match="canonical execution"):
        guard._validated(invalid, approval_for(plan, subject_signer=signer.address), at=NOW)


@pytest.mark.parametrize(
    "primary,secondary",
    [
        (
            RpcClient("https://one.example/rpc", transport=lambda *_args: b""),
            RpcClient("https://two.example/rpc"),
        ),
        (
            RpcClient("https://one.example/rpc"),
            RpcClient("https://two.example/rpc", transport=lambda *_args: b""),
        ),
        (RpcClient("https://same.example/rpc"), RpcClient("https://same.example/rpc")),
    ],
)
def test_stock_engine_rejects_nonindependent_concrete_rpc_clients(
    primary: RpcClient, secondary: RpcClient
) -> None:
    pool = object.__new__(RpcPool)
    object.__setattr__(pool, "primary", primary)
    object.__setattr__(pool, "secondary", secondary)
    object.__setattr__(pool, "chain_id", 42161)
    with pytest.raises(TypeError, match="concrete two-endpoint RpcPool"):
        ExecutionEngine._require_rpc_pool(pool, label="source")


def test_stock_engine_rejects_rpc_pool_subclasses() -> None:
    class DerivedRpcPool(RpcPool):
        pass

    pool = object.__new__(DerivedRpcPool)
    with pytest.raises(TypeError, match="concrete two-endpoint RpcPool"):
        ExecutionEngine._require_rpc_pool(pool, label="source")


def order_pending_operation(
    tmp_path: Path,
    *,
    finality_waiter: Callable[..., dict[str, object]] | None = None,
) -> tuple[ExecutionEngine, FakeRpcPool, Operation]:
    """Create an operation ready for destination fulfillment verification."""

    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer, finality_waiter=finality_waiter)
    plan = make_plan(signer.address)
    operation = guard.execute(
        plan,
        approval_for(plan, subject_signer=signer.address),
        idempotency_key="destination-verification",
        signer=signer,
        at=NOW,
    )
    assert operation.tx_hash is not None
    proof = verify_source_receipt(
        operation_id=operation.operation_id,
        plan=operation.plan,
        receipt={
            "transactionHash": operation.tx_hash,
            "blockNumber": "0x1",
            "blockHash": "0x" + "aa" * 32,
            "status": "0x1",
        },
        chain_id=operation.source_chain_id,
        transaction_hash=operation.tx_hash,
        confirmations=1,
        receipt_status=1,
    )
    operation = guard.store._commit_source_finality(proof)
    destination_pool = FakeRpcPool(pool.primary, pool.secondary, chain_id=4663)
    return guard, destination_pool, operation


def test_refresh_source_marks_reconciliation_when_finality_evidence_disagrees(
    tmp_path: Path,
) -> None:
    signer = MemorySigner()

    def finality_failure(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise NeedsReconciliationError("simulated source disagreement")

    guard, _pool = engine(tmp_path, signer, finality_waiter=finality_failure)
    plan = make_plan(signer.address)
    pending = guard.execute(
        plan,
        approval_for(plan, subject_signer=signer.address),
        idempotency_key="source-finality-disagreement",
        signer=signer,
        at=NOW,
    )

    with pytest.raises(NeedsReconciliation, match="source finality evidence disagreed"):
        guard.refresh_source(pending.operation_id, max_polls=1)

    assert (
        guard.store.get_operation(pending.operation_id).state
        is OperationState.NEEDS_RECONCILIATION
    )


def test_verifier_rejects_invalid_source_policy_chain_and_forged_proofs(tmp_path: Path) -> None:
    signer = MemorySigner()
    plan = make_plan(signer.address)
    receipt = {
        "transactionHash": "0x" + "ab" * 32,
        "blockNumber": 1,
        "blockHash": "0x" + "cd" * 32,
        "status": 1,
    }

    with pytest.raises(VerificationError, match="policy"):
        verify_source_receipt(
            operation_id="operation",
            plan=plan,
            receipt=receipt,
            chain_id=42161,
            transaction_hash=receipt["transactionHash"],
            confirmations=0,
            receipt_status=1,
        )
    with pytest.raises(VerificationError, match="chain"):
        verify_source_receipt(
            operation_id="operation",
            plan=plan,
            receipt=receipt,
            chain_id=1,
            transaction_hash=receipt["transactionHash"],
            confirmations=1,
            receipt_status=1,
        )
    with pytest.raises(TypeError, match="receipt verifier"):
        VerifiedSourceReceipt(
            operation_id="operation",
            plan_id=plan.plan_id,
            chain_id=42161,
            transaction_hash=receipt["transactionHash"],
            block_number=1,
            block_hash=receipt["blockHash"],
            confirmations=1,
            receipt_status=1,
        )
    with pytest.raises(TypeError, match="receipt verifier"):
        VerifiedDestinationFulfillment(
            operation_id="operation",
            plan_id=plan.plan_id,
            chain_id=4663,
            transaction_hash=receipt["transactionHash"],
            block_number=1,
            block_hash=receipt["blockHash"],
            confirmations=1,
            order_id="0x" + "00" * 32,
            log_index=0,
            log_address="0x" + "00" * 20,
            log_topic="0x" + "00" * 32,
            signer=signer.address,
            source_chain_id=42161,
            source_token="0x" + "00" * 20,
            source_amount_wei=1,
            destination_chain_id=4663,
            receiver="0x" + "00" * 20,
            destination_token="0x" + "00" * 20,
            destination_amount_wei=1,
            allowed_taker=None,
        )


def test_verifier_rejects_invalid_destination_confirmation_and_log_shape(tmp_path: Path) -> None:
    signer = MemorySigner()
    plan = make_plan(signer.address)
    receipt = {
        "transactionHash": "0x" + "ab" * 32,
        "blockNumber": 1,
        "blockHash": "0x" + "cd" * 32,
        "status": 1,
        "logs": "not-a-list",
    }

    with pytest.raises(VerificationError, match="confirmations"):
        verify_destination_receipt(
            operation_id="operation",
            plan=plan,
            receipt=receipt,
            transaction_hash=receipt["transactionHash"],
            confirmations=0,
        )
    with pytest.raises(VerificationError, match="no log list"):
        verify_destination_receipt(
            operation_id="operation",
            plan=plan,
            receipt=receipt,
            transaction_hash=receipt["transactionHash"],
            confirmations=1,
        )


def test_bound_recovery_rejects_a_substituted_approval_before_any_broadcast(tmp_path: Path) -> None:
    plan, _, _ = bound_plan()
    persisted = reviewable_approval(plan)
    execution = ExecutionPlan.from_plan(plan, allow_expired=True)
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer)
    operation = guard.store.reserve_operation(
        plan,
        idempotency_key="bound-recovery-substitution",
        signer=execution.signer,
        source_chain_id=execution.source_chain_id,
        nonce=execution.transaction["nonce"],
        approval=persisted,
    )
    payload = Approval.signing_payload_reviewable(
        plan=plan,
        authorization_id="different-authorization",
        actor="operator",
        approved_at="2026-07-24T00:00:01Z",
        expires_at="2026-07-24T00:00:25Z",
    )
    substitute = Approval.create_reviewable(
        plan=plan,
        authorization_id="different-authorization",
        actor="operator",
        approved_at="2026-07-24T00:00:01Z",
        expires_at="2026-07-24T00:00:25Z",
        signature=(
            "0x"
            + Account.sign_message(encode_defunct(primitive=payload), OPERATOR_KEY).signature.hex()
        ),
    )

    with pytest.raises(PreBroadcastFailure, match="cannot substitute"):
        guard.resume(operation.operation_id, approval=substitute, at=NOW)

    assert pool.primary.sent == []


@pytest.mark.parametrize(
    ("execution", "message"),
    [
        (lambda execution: replace(execution, source_dln_implementation_codehash=None), "policy"),
        (lambda execution: replace(execution, expected_global_transfer_fee_bps=None), "policy"),
        (
            lambda execution: replace(
                execution,
                plan=Plan.create({**execution.plan.body(), "intent": {"amount_wei": 0}}),
            ),
            "source input",
        ),
    ],
)
def test_direct_preflight_rejects_incomplete_policy_or_invalid_input(
    tmp_path: Path, execution: Callable[[ExecutionPlan], ExecutionPlan], message: str
) -> None:
    plan, _, _ = bound_plan()
    signer = MemorySigner()
    guard, _ = engine(tmp_path, signer)

    with pytest.raises(ValueError, match=message):
        guard._preflight_source(execution(ExecutionPlan.from_plan(plan, allow_expired=True)))


def test_direct_preflight_binds_every_exact_reserve_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, _, _ = bound_plan()
    execution = ExecutionPlan.from_plan(plan, allow_expired=True)
    signer = MemorySigner()
    guard, _ = engine(tmp_path, signer)
    received: dict[str, object] = {}

    def preflight(*rpc_calls: object, **kwargs: object) -> None:
        assert len(rpc_calls) == 2
        received.update(kwargs)

    monkeypatch.setattr(
        "agent_bridge_guard.engine.preflight_reserve_erc20_source_transaction", preflight
    )

    guard._preflight_source(execution)

    assert received["signer"] == execution.signer
    assert received["dln_proxy"] == execution.transaction["to"]
    assert received["reserve_token"] == execution.source_order_token
    assert received["amount_wei"] == execution.plan.body()["intent"]["amount_wei"]
    assert received["fixed_fee_wei"] == execution.transaction["value"]
    assert (
        received["expected_implementation_codehash"]
        == execution.source_dln_implementation_codehash
    )
    assert (
        received["expected_global_transfer_fee_bps"]
        == execution.expected_global_transfer_fee_bps
    )


def test_custom_authorizer_cannot_downgrade_direct_execution(tmp_path: Path) -> None:
    signer = MemorySigner()
    plan = make_plan(signer.address)
    legacy = Plan.create(plan.body())

    class MaliciousAuthorizer:
        def validate(
            self, _plan: Plan, _approval: Approval, *, at: object = None
        ) -> FixtureAuthorization:
            del at
            return FixtureAuthorization(ExecutionPlan.from_plan(legacy, allow_expired=True))

    guard, pool = engine(tmp_path, signer, authorizer=MaliciousAuthorizer())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="bound direct reserve route"):
        guard.execute(
            plan,
            approval_for(plan, subject_signer=signer.address),
            idempotency_key="malicious-authorizer-downgrade",
            signer=signer,
            at=NOW,
        )
    assert pool.primary.sent == []


def test_custom_authorizer_cannot_substitute_another_bound_plan(tmp_path: Path) -> None:
    signer = MemorySigner()
    plan = make_plan(signer.address)
    substituted_plan = make_plan(signer.address, nonce=8)

    class MaliciousAuthorizer:
        def validate(
            self, _plan: Plan, _approval: Approval, *, at: object = None
        ) -> FixtureAuthorization:
            del at
            return FixtureAuthorization(
                ExecutionPlan.from_plan(substituted_plan, allow_expired=True)
            )

    guard, pool = engine(tmp_path, signer, authorizer=MaliciousAuthorizer())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="bound direct reserve route"):
        guard.execute(
            plan,
            approval_for(plan, subject_signer=signer.address),
            idempotency_key="malicious-authorizer-plan-substitution",
            signer=signer,
            at=NOW,
        )
    assert pool.primary.sent == []


def test_custom_authorizer_cannot_mutate_caller_execution_fields(tmp_path: Path) -> None:
    signer = MemorySigner()
    plan = make_plan(signer.address)
    canonical = ExecutionPlan.from_plan(plan, allow_expired=True)
    mutated = replace(
        canonical,
        transaction={**canonical.transaction, "nonce": canonical.transaction["nonce"] + 1},
    )

    class MaliciousAuthorizer:
        def validate(
            self, _plan: Plan, _approval: Approval, *, at: object = None
        ) -> FixtureAuthorization:
            del at
            return FixtureAuthorization(mutated)

    guard, pool = engine(tmp_path, signer, authorizer=MaliciousAuthorizer())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="bound direct reserve route"):
        guard.execute(
            plan,
            approval_for(plan, subject_signer=signer.address),
            idempotency_key="malicious-authorizer-field-mutation",
            signer=signer,
            at=NOW,
        )
    assert pool.primary.sent == []

def test_refresh_source_records_finalized_failed_receipt_as_terminal_proof(tmp_path: Path) -> None:
    signer = MemorySigner()

    def failed_finality(*args: object, **_kwargs: object) -> dict[str, object]:
        transaction_hash = args[1]
        assert isinstance(transaction_hash, str)
        raise TransactionFailedError(
            {
                "transactionHash": transaction_hash,
                "blockNumber": "0x1",
                "blockHash": "0x" + "cd" * 32,
                "status": "0x0",
            }
        )

    guard, _pool = engine(tmp_path, signer, finality_waiter=failed_finality)
    plan = make_plan(signer.address)
    pending = guard.execute(
        plan,
        approval_for(plan, subject_signer=signer.address),
        idempotency_key="source-finalized-failure",
        signer=signer,
        at=NOW,
    )
    assert pending.tx_hash is not None

    failed = guard.refresh_source(pending.operation_id, max_polls=1)

    assert failed.state is OperationState.SOURCE_FAILED
    assert failed.source_finality_evidence == {
        "schema_version": 1,
        "verifier_version": "agent-bridge-guard/receipt-verifier/v1",
        "plan_id": pending.plan.plan_id,
        "chain_id": 42161,
        "transaction_hash": pending.tx_hash,
        "block_number": 1,
        "block_hash": "0x" + "cd" * 32,
        "confirmations": 1,
        "rpc_quorum": 2,
        "receipt_status": 0,
    }


def test_resume_marks_reconciliation_when_source_lookup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard, pool, operation = submit_unknown_operation(tmp_path)

    def lookup_failure(_transaction_hash: str) -> None:
        raise RpcTransportError("simulated lookup failure")

    monkeypatch.setattr(pool.primary, "transaction_by_hash", lookup_failure)

    with pytest.raises(NeedsReconciliation, match="source transaction lookup failed"):
        guard.resume(operation.operation_id)

    assert (
        guard.store.get_operation(operation.operation_id).state
        is OperationState.NEEDS_RECONCILIATION
    )


def test_resume_marks_reconciliation_when_observed_hash_differs(tmp_path: Path) -> None:
    guard, pool, operation = submit_unknown_operation(tmp_path)
    assert operation.tx_hash is not None
    pool.primary.seen[operation.tx_hash] = {"hash": "0x" + "ff" * 32}

    with pytest.raises(NeedsReconciliation, match="observed transaction hash mismatch"):
        guard.resume(operation.operation_id)

    assert (
        guard.store.get_operation(operation.operation_id).state
        is OperationState.NEEDS_RECONCILIATION
    )


def test_resume_marks_reconciliation_when_pending_nonce_evidence_disagrees(tmp_path: Path) -> None:
    guard, pool, operation = submit_unknown_operation(tmp_path)
    pool.primary.pending_nonce = operation.nonce
    pool.secondary.pending_nonce = operation.nonce + 1

    with pytest.raises(NeedsReconciliation, match="pending nonce advanced"):
        guard.resume(operation.operation_id)

    assert (
        guard.store.get_operation(operation.operation_id).state
        is OperationState.NEEDS_RECONCILIATION
    )


def test_execute_marks_reconciliation_when_rpc_returns_different_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer)
    plan = make_plan(signer.address)
    monkeypatch.setattr(
        pool.primary,
        "send_raw_transaction",
        lambda _raw_transaction: "0x" + "ff" * 32,
    )

    with pytest.raises(NeedsReconciliation, match="RPC returned a different transaction hash"):
        guard.execute(
            plan,
            approval_for(plan, subject_signer=signer.address),
            idempotency_key="different-rpc-hash",
            signer=signer,
            at=NOW,
        )

    operation = guard.store.get_operation_by_idempotency_key("different-rpc-hash")
    assert operation.state is OperationState.NEEDS_RECONCILIATION


def test_verify_destination_wraps_unproven_finality(tmp_path: Path) -> None:
    def finality_failure(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise NeedsReconciliationError("simulated destination disagreement")

    guard, pool, operation = order_pending_operation(tmp_path, finality_waiter=finality_failure)

    with pytest.raises(DestinationVerificationError, match="destination finality is not proven"):
        guard.verify_destination(
            operation.operation_id,
            destination_transaction_hash="0x" + "01" * 32,
            destination_rpc=pool,  # type: ignore[arg-type]
            confirmations=1,
            max_polls=1,
        )

    current = guard.store.get_operation(operation.operation_id)
    assert current.state is OperationState.DESTINATION_PENDING


def test_verify_destination_rejects_receipt_without_log_list(tmp_path: Path) -> None:
    def missing_logs(*args: object, **_kwargs: object) -> dict[str, object]:
        transaction_hash = args[1]
        assert isinstance(transaction_hash, str)
        return {
            "transactionHash": transaction_hash,
            "blockNumber": "0x1",
            "blockHash": "0x" + "aa" * 32,
            "status": "0x1",
            "logs": "not-a-list",
        }

    guard, pool, operation = order_pending_operation(
        tmp_path,
        finality_waiter=missing_logs,
    )

    with pytest.raises(DestinationVerificationError, match="no log list"):
        guard.verify_destination(
            operation.operation_id,
            destination_transaction_hash="0x" + "02" * 32,
            destination_rpc=pool,  # type: ignore[arg-type]
            confirmations=1,
            max_polls=1,
        )

    current = guard.store.get_operation(operation.operation_id)
    assert current.state is OperationState.DESTINATION_PENDING


def test_verify_destination_rejects_receipt_without_matching_fulfillment(tmp_path: Path) -> None:
    def no_matching_log(*args: object, **_kwargs: object) -> dict[str, object]:
        transaction_hash = args[1]
        assert isinstance(transaction_hash, str)
        return {
            "transactionHash": transaction_hash,
            "blockNumber": "0x1",
            "blockHash": "0x" + "aa" * 32,
            "status": "0x1",
            "logs": [],
        }

    guard, pool, operation = order_pending_operation(
        tmp_path,
        finality_waiter=no_matching_log,
    )

    with pytest.raises(DestinationVerificationError, match="exactly one matching"):
        guard.verify_destination(
            operation.operation_id,
            destination_transaction_hash="0x" + "03" * 32,
            destination_rpc=pool,  # type: ignore[arg-type]
            confirmations=1,
            max_polls=1,
        )

    current = guard.store.get_operation(operation.operation_id)
    assert current.state is OperationState.DESTINATION_PENDING


def test_verify_destination_rejects_rpc_on_an_unapproved_destination_chain(tmp_path: Path) -> None:
    guard, destination_pool, operation = order_pending_operation(
        tmp_path,
        finality_waiter=lambda *_args, **_kwargs: {"logs": []},
    )
    destination_pool.chain_id = 1

    with pytest.raises(
        DestinationVerificationError,
        match="destination RPC chain does not match approved plan",
    ):
        guard.verify_destination(
            operation.operation_id,
            destination_transaction_hash="0x" + "04" * 32,
            destination_rpc=destination_pool,  # type: ignore[arg-type]
            confirmations=1,
            max_polls=1,
        )
