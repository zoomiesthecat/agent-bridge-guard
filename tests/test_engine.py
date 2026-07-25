from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Lock

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak  # type: ignore[attr-defined]
from test_authorization import bound_plan, reviewable_approval

from agent_bridge_guard.approval import Approval
from agent_bridge_guard.engine import (
    ExecutionEngine,
    NeedsReconciliation,
    PreBroadcastFailure,
    SubmissionUnknown,
)
from agent_bridge_guard.execution_plan import ExecutionPlan
from agent_bridge_guard.models import Plan
from agent_bridge_guard.rpc import RpcTransportError
from agent_bridge_guard.signers.base import (
    SignedTransaction,
    eth_account_transaction,
    normalize_transaction,
)
from agent_bridge_guard.signers.detached import DetachedSigner
from agent_bridge_guard.store import OperationState, SQLiteOperationStore
from agent_bridge_guard.verification import verify_source_receipt

ROUTER = "0x2222222222222222222222222222222222222222"
RECIPIENT = "0x3333333333333333333333333333333333333333"
DESTINATION_PROXY = "0x4444444444444444444444444444444444444444"
ORDER_ID = "0x" + "ab" * 32
NOW = datetime(2026, 7, 24, 21, 5, tzinfo=UTC)
OPERATOR = Account.from_key(bytes(range(33, 65)))
APPROVAL_ISSUERS = frozenset({OPERATOR.address})


class MemorySigner:
    def __init__(self) -> None:
        self._account = Account.from_key(bytes(range(1, 33)))
        self.sign_calls = 0

    @property
    def address(self) -> str:
        return self._account.address

    def sign_transaction(self, transaction: Mapping[str, object]) -> SignedTransaction:
        self.sign_calls += 1
        normalized = normalize_transaction(transaction)
        signed = self._account.sign_transaction(eth_account_transaction(normalized))
        return SignedTransaction(
            raw_transaction=bytes(signed.raw_transaction),
            transaction_hash="0x" + signed.hash.hex(),
            signer_address=self.address,
        )


@dataclass
class FixtureAuthorizer:
    """Minimal execution-plan authorizer for direct-route lifecycle fixtures."""

    fail_at_call: int | None = None
    calls: list[Approval] = field(default_factory=list)

    def validate(
        self, plan: Plan, approval: Approval, *, at: datetime | None = None
    ) -> FixtureAuthorization:
        del at
        self.calls.append(approval)
        if self.fail_at_call == len(self.calls):
            raise ValueError("test authorization rejected")
        return FixtureAuthorization(ExecutionPlan.from_plan(plan, allow_expired=True))


@dataclass(frozen=True)
class FixtureAuthorization:
    execution: ExecutionPlan


class FixtureExecutionEngine(ExecutionEngine):
    """Test-only protected-boundary overrides; stock engine has no injectable seams."""

    def __init__(
        self,
        store: SQLiteOperationStore,
        source_rpc: FakeRpcPool,
        *,
        authorizer: FixtureAuthorizer,
        finality_waiter: Callable[..., dict[str, object]] | None = None,
    ) -> None:
        self.store = store
        self._source_rpc = source_rpc
        self._source_confirmations = 1
        self._fixture_authorizer = authorizer
        self._fixture_finality_waiter = finality_waiter

    @staticmethod
    def _require_rpc_pool(_rpc: object, *, label: str) -> None:
        del label

    def _authorize(
        self, plan: Plan, approval: Approval, *, at: datetime | None
    ) -> FixtureAuthorization:  # type: ignore[override]
        return self._fixture_authorizer.validate(plan, approval, at=at)

    def _wait_for_finality(
        self,
        rpc: object,
        transaction_hash: str,
        confirmations: int,
        *,
        max_polls: int | None,
    ) -> dict[str, object]:  # type: ignore[override]
        if self._fixture_finality_waiter is None:
            return super()._wait_for_finality(
                rpc, transaction_hash, confirmations, max_polls=max_polls
            )
        return self._fixture_finality_waiter(
            rpc,
            transaction_hash,
            confirmations,
            max_polls=max_polls,
        )


@dataclass
class FakeRpcClient:
    seen: dict[str, dict[str, object]]
    pending_nonce: int = 7
    send_failures: int = 0
    sent: list[str] = field(default_factory=list)

    def send_raw_transaction(self, raw_transaction: str) -> str:
        self.sent.append(raw_transaction)
        transaction_hash = "0x" + keccak(bytes.fromhex(raw_transaction[2:])).hex()
        if self.send_failures:
            self.send_failures -= 1
            raise RpcTransportError("simulated transport loss")
        self.seen[transaction_hash] = {"hash": transaction_hash}
        return transaction_hash

    def transaction_by_hash(self, transaction_hash: str) -> dict[str, object] | None:
        return self.seen.get(transaction_hash)

    def transaction_count(self, _address: str, block: str = "pending") -> int:
        assert block == "pending"
        return self.pending_nonce

    def call(self, method: str, params: list[object]) -> str:
        if method == "eth_call":
            transaction = params[0]
            assert isinstance(transaction, dict)
            if "from" in transaction:
                return "0x"
            data = transaction.get("data")
            assert isinstance(data, str)
            if data.startswith("0x70a08231") or data.startswith("0xdd62ed3e"):
                return hex(1_000)
            if data == "0x" + keccak(b"globalFixedNativeFee()")[:4].hex():
                return hex(5)
            if data == "0x" + keccak(b"globalTransferFeeBps()")[:4].hex():
                return hex(100)
            raise AssertionError(f"unexpected eth_call data: {data}")
        if method == "eth_estimateGas":
            return hex(100)
        if method == "eth_getTransactionCount":
            assert params[0]
            assert params[1] in {"latest", "pending"}
            return hex(self.pending_nonce)
        if method == "eth_getBalance":
            return hex(10**18)
        if method == "eth_getStorageAt":
            return "0x" + "00" * 12 + "12" * 20
        if method == "eth_getCode":
            return "0x00"
        raise AssertionError(f"unexpected RPC method: {method}")


@dataclass
class FakeRpcPool:
    primary: FakeRpcClient
    secondary: FakeRpcClient
    chain_id: int = 42161


def make_plan(signer: str, *, nonce: int = 7, amount: int = 1_000) -> Plan:
    if amount != 1_000:
        raise ValueError("engine fixture only supports the exact direct reserve amount")
    plan, _, _ = bound_plan()
    body = plan.body()
    intent = body["intent"]
    transaction = body["unsigned_transaction"]
    provider = body["provider"]
    assert isinstance(intent, dict)
    assert isinstance(transaction, dict)
    assert isinstance(provider, dict)
    intent["expected_signer"] = signer
    transaction["nonce"] = nonce
    provider["source_dln_implementation_codehash"] = "0x" + keccak(b"\0").hex()
    return Plan.create(body, schema_version=2)


def approval_for(plan: Plan, *, subject_signer: str) -> Approval:
    execution = ExecutionPlan.from_plan(plan, allow_expired=True)
    assert subject_signer.lower() == execution.signer.lower()
    return reviewable_approval(plan)


def engine(
    tmp_path: Path,
    signer: MemorySigner,
    *,
    send_failures: int = 0,
    finality_waiter: Callable[..., dict[str, object]] | None = None,
    authorizer: FixtureAuthorizer | None = None,
) -> tuple[ExecutionEngine, FakeRpcPool]:
    seen: dict[str, dict[str, object]] = {}
    pool = FakeRpcPool(
        primary=FakeRpcClient(seen, send_failures=send_failures),
        secondary=FakeRpcClient(seen),
    )
    store = SQLiteOperationStore(tmp_path / "private" / "operations.db")
    return (
        FixtureExecutionEngine(
            store,
            pool,
            authorizer=authorizer or FixtureAuthorizer(),
            finality_waiter=finality_waiter,
        ),
        pool,
    )


def test_execute_is_idempotent_and_signs_and_sends_only_once(tmp_path: Path) -> None:
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer)
    plan = make_plan(signer.address)

    first = guard.execute(
        plan,
        approval_for(plan, subject_signer=signer.address),
        idempotency_key="request-1",
        signer=signer,
        at=NOW,
    )
    second = guard.execute(
        plan,
        approval_for(plan, subject_signer=signer.address),
        idempotency_key="request-1",
        signer=signer,
        at=NOW,
    )

    assert first.operation_id == second.operation_id
    assert second.state is OperationState.SOURCE_PENDING
    assert signer.sign_calls == 1
    assert len(pool.primary.sent) == 1


def test_authorizer_gates_reserve_signing_and_first_broadcast(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorizer = FixtureAuthorizer()

    class CheckedSigner(MemorySigner):
        def sign_transaction(self, transaction: Mapping[str, object]) -> SignedTransaction:
            assert len(authorizer.calls) == 3
            return super().sign_transaction(transaction)

    signer = CheckedSigner()
    guard, pool = engine(tmp_path, signer, authorizer=authorizer)
    plan = make_plan(signer.address)
    approval = approval_for(plan, subject_signer=signer.address)
    original_send = pool.primary.send_raw_transaction

    def checked_send(raw_transaction: str) -> str:
        assert len(authorizer.calls) == 4
        return original_send(raw_transaction)

    monkeypatch.setattr(pool.primary, "send_raw_transaction", checked_send)

    operation = guard.execute(
        plan,
        approval,
        idempotency_key="authorizer-boundaries",
        signer=signer,
        at=NOW,
    )

    assert operation.state is OperationState.SOURCE_PENDING
    assert authorizer.calls == [approval, approval, approval, approval]


def test_authorizer_gates_detached_import_before_preparation_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorizer = FixtureAuthorizer()
    signer = MemorySigner()
    guard, _ = engine(tmp_path, signer, authorizer=authorizer)
    plan = make_plan(signer.address)
    approval = approval_for(plan, subject_signer=signer.address)
    transaction = plan.body()["unsigned_transaction"]
    assert isinstance(transaction, dict)
    signed = signer.sign_transaction(transaction)
    original_import = DetachedSigner.import_signed_transaction

    def checked_import(
        self: DetachedSigner, transaction: Mapping[str, object], raw: bytes | str
    ) -> SignedTransaction:
        assert len(authorizer.calls) == 2
        return original_import(self, transaction, raw)

    monkeypatch.setattr(DetachedSigner, "import_signed_transaction", checked_import)

    prepared = guard.prepare_external(
        plan,
        approval,
        signed.raw_transaction,
        idempotency_key="authorizer-detached-import",
        at=NOW,
    )

    assert prepared.state is OperationState.BROADCAST_PREPARED
    assert authorizer.calls == [approval, approval, approval]


def test_recovery_resend_revalidates_authorizer_and_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorizer = FixtureAuthorizer()
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer, send_failures=1, authorizer=authorizer)
    plan = make_plan(signer.address)
    approval = approval_for(plan, subject_signer=signer.address)
    preflight_authorizer_calls: list[int] = []
    original_preflight = guard._preflight_source

    def checked_preflight(execution: ExecutionPlan) -> None:
        preflight_authorizer_calls.append(len(authorizer.calls))
        original_preflight(execution)

    monkeypatch.setattr(guard, "_preflight_source", checked_preflight)

    with pytest.raises(SubmissionUnknown):
        guard.execute(
            plan,
            approval,
            idempotency_key="authorizer-recovery-resend",
            signer=signer,
            at=NOW,
        )
    operation = guard.store.get_operation_by_idempotency_key("authorizer-recovery-resend")

    resumed = guard.resume(
        operation.operation_id, approval=approval, at=NOW, allow_broadcast=True
    )

    assert resumed.state is OperationState.SOURCE_PENDING
    assert authorizer.calls == [approval, approval, approval, approval, approval]
    assert preflight_authorizer_calls == [3, 4, 5]
    assert len(pool.primary.sent) == 2


def test_read_only_resume_never_sends_or_revalidates_recovery_authorization(tmp_path: Path) -> None:
    authorizer = FixtureAuthorizer()
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer, send_failures=1, authorizer=authorizer)
    plan = make_plan(signer.address)
    approval = approval_for(plan, subject_signer=signer.address)

    with pytest.raises(SubmissionUnknown):
        guard.execute(
            plan,
            approval,
            idempotency_key="read-only-recovery",
            signer=signer,
            at=NOW,
        )
    operation = guard.store.get_operation_by_idempotency_key("read-only-recovery")

    read_only = guard.resume(operation.operation_id, at=NOW)

    assert read_only.state is OperationState.SUBMISSION_UNKNOWN
    assert len(pool.primary.sent) == 1
    assert len(authorizer.calls) == 4


def test_recovery_authorization_failure_stops_before_resend(tmp_path: Path) -> None:
    authorizer = FixtureAuthorizer(fail_at_call=5)
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer, send_failures=1, authorizer=authorizer)
    plan = make_plan(signer.address)
    approval = approval_for(plan, subject_signer=signer.address)

    with pytest.raises(SubmissionUnknown):
        guard.execute(
            plan,
            approval,
            idempotency_key="recovery-authorization-failure",
            signer=signer,
            at=NOW,
        )
    operation = guard.store.get_operation_by_idempotency_key("recovery-authorization-failure")

    with pytest.raises(ValueError, match="validation failed"):
        guard.resume(operation.operation_id, approval=approval, at=NOW, allow_broadcast=True)

    assert len(authorizer.calls) == 5
    assert len(pool.primary.sent) == 1


def test_concurrent_execute_claims_one_local_signature_and_recovers_exact_bytes(
    tmp_path: Path
) -> None:
    class SlowSigner(MemorySigner):
        preparation_replay_safe = True

        def sign_transaction(self, transaction: Mapping[str, object]) -> SignedTransaction:
            entered.set()
            assert release.wait(timeout=5)
            return super().sign_transaction(transaction)

    entered = Event()
    release = Event()
    signer = SlowSigner()
    guard, pool = engine(tmp_path, signer)
    plan = make_plan(signer.address)
    approval = approval_for(plan, subject_signer=signer.address)

    def execute() -> OperationState:
        return guard.execute(
            plan,
            approval,
            idempotency_key="concurrent-local-prepare",
            signer=signer,
            at=NOW,
        ).state

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(execute)
        assert entered.wait(timeout=5)
        second = executor.submit(execute)
        time.sleep(0.05)
        release.set()
        states = [first.result()]
        with suppress(PreBroadcastFailure):
            states.append(second.result())

    operation = guard.store.get_operation_by_idempotency_key("concurrent-local-prepare")
    assert signer.sign_calls == 1
    assert operation.raw_signed_tx is not None
    assert operation.tx_hash == "0x" + keccak(operation.raw_signed_tx).hex()
    assert OperationState.SOURCE_PENDING in states
    assert len(pool.primary.sent) == 1


def test_concurrent_detached_prevalidates_each_input_then_reuses_exact_prepared_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer)
    plan = make_plan(signer.address)
    transaction = plan.body()["unsigned_transaction"]
    assert isinstance(transaction, dict)
    signed = signer.sign_transaction(transaction)
    approval = approval_for(plan, subject_signer=signer.address)
    imports = 0
    lock = Lock()
    original = DetachedSigner.import_signed_transaction

    def counted_import(
        self: DetachedSigner, transaction: Mapping[str, object], raw: bytes | str
    ) -> SignedTransaction:
        nonlocal imports
        with lock:
            imports += 1
        time.sleep(0.05)
        return original(self, transaction, raw)

    monkeypatch.setattr(DetachedSigner, "import_signed_transaction", counted_import)

    def prepare() -> bytes | None:
        return guard.prepare_external(
            plan,
            approval,
            signed.raw_transaction,
            idempotency_key="concurrent-detached-prepare",
            at=NOW,
        ).raw_signed_tx

    with ThreadPoolExecutor(max_workers=2) as executor:
        raw_transactions = list(executor.map(lambda _: prepare(), range(2)))

    assert imports == 2
    assert raw_transactions == [signed.raw_transaction, signed.raw_transaction]
    assert pool.primary.sent == []


def test_execute_rechecks_preflight_before_signing_and_first_broadcast(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer)
    plan = make_plan(signer.address)
    checkpoints: list[tuple[int, int, int]] = []

    def record_preflight(*_args: object, **_kwargs: object) -> dict[str, int]:
        nonce = _kwargs["nonce"]
        assert isinstance(nonce, int)
        checkpoints.append((signer.sign_calls, len(pool.primary.sent), nonce))
        return {"estimated_gas": 21_000, "balance_wei": 10**18}

    monkeypatch.setattr(
        "agent_bridge_guard.engine.preflight_reserve_erc20_source_transaction",
        record_preflight,
    )

    operation = guard.execute(
        plan,
        approval_for(plan, subject_signer=signer.address),
        idempotency_key="request-preflight-checkpoints",
        signer=signer,
        at=NOW,
    )

    assert operation.state is OperationState.SOURCE_PENDING
    assert checkpoints == [(0, 0, 7), (1, 0, 7)]
    assert len(pool.primary.sent) == 1


def test_preflight_disagreement_blocks_before_signing_or_broadcast(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer)
    plan = make_plan(signer.address)

    def reject_preflight(*_args: object, **_kwargs: object) -> dict[str, int]:
        raise ValueError("source RPC gas estimates disagree")

    monkeypatch.setattr(
        "agent_bridge_guard.engine.preflight_reserve_erc20_source_transaction",
        reject_preflight,
    )

    with pytest.raises(PreBroadcastFailure):
        guard.execute(
            plan,
            approval_for(plan, subject_signer=signer.address),
            idempotency_key="request-preflight-disagreement",
            signer=signer,
            at=NOW,
        )

    operation = guard.store.get_operation_by_idempotency_key(
        "request-preflight-disagreement"
    )
    assert operation.state is OperationState.FAILED_PRE_BROADCAST
    assert signer.sign_calls == 0
    assert pool.primary.sent == []


def test_nonce_drift_blocks_before_signing_or_broadcast(tmp_path: Path) -> None:
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer)
    pool.primary.pending_nonce = 8
    pool.secondary.pending_nonce = 8
    plan = make_plan(signer.address, nonce=7)

    with pytest.raises(PreBroadcastFailure):
        guard.execute(
            plan,
            approval_for(plan, subject_signer=signer.address),
            idempotency_key="request-nonce-drift",
            signer=signer,
            at=NOW,
        )

    operation = guard.store.get_operation_by_idempotency_key("request-nonce-drift")
    assert operation.state is OperationState.FAILED_PRE_BROADCAST
    assert signer.sign_calls == 0
    assert pool.primary.sent == []


def test_external_signer_can_retry_transient_prebroadcast_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer)
    plan = make_plan(signer.address)
    transaction = plan.body()["unsigned_transaction"]
    assert isinstance(transaction, dict)
    signed = signer.sign_transaction(transaction)
    attempts = 0

    def intermittent_preflight(*_args: object, **_kwargs: object) -> dict[str, int]:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ValueError("source RPC transport unavailable")
        return {"estimated_gas": 21_000, "balance_wei": 10**18}

    monkeypatch.setattr(
        "agent_bridge_guard.engine.preflight_reserve_erc20_source_transaction",
        intermittent_preflight,
    )
    approval = approval_for(plan, subject_signer=signer.address)

    with pytest.raises(PreBroadcastFailure):
        guard.prepare_external(
            plan,
            approval,
            signed.raw_transaction,
            idempotency_key="request-external-preflight-retry",
            at=NOW,
        )

    prepared = guard.prepare_external(
        plan,
        approval,
        signed.raw_transaction,
        idempotency_key="request-external-preflight-retry",
        at=NOW,
    )

    assert attempts == 2
    assert prepared.state is OperationState.BROADCAST_PREPARED
    assert prepared.raw_signed_tx == signed.raw_transaction
    assert pool.primary.sent == []


def test_crash_after_send_resumes_from_observed_hash_without_resending(tmp_path: Path) -> None:
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer)
    plan = make_plan(signer.address)
    approval = approval_for(plan, subject_signer=signer.address)

    def crash(_transaction_hash: str) -> None:
        raise KeyboardInterrupt("simulated process crash")

    with pytest.raises(KeyboardInterrupt):
        guard.execute(
            plan,
            approval,
            idempotency_key="request-crash",
            signer=signer,
            at=NOW,
            after_broadcast=crash,
        )
    operation = guard.store.get_operation_by_idempotency_key("request-crash")
    assert operation.state is OperationState.BROADCAST_ATTEMPTED

    resumed = guard.resume(
        operation.operation_id, approval=approval, at=NOW, allow_broadcast=True
    )

    assert resumed.state is OperationState.SOURCE_PENDING
    assert len(pool.primary.sent) == 1


def test_unknown_submission_rebroadcasts_only_the_exact_persisted_bytes(
    tmp_path: Path,
) -> None:
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer, send_failures=1)
    plan = make_plan(signer.address)
    approval = approval_for(plan, subject_signer=signer.address)

    with pytest.raises(SubmissionUnknown):
        guard.execute(
            plan,
            approval,
            idempotency_key="request-unknown",
            signer=signer,
            at=NOW,
        )
    operation = guard.store.get_operation_by_idempotency_key("request-unknown")
    assert operation.state is OperationState.SUBMISSION_UNKNOWN

    resumed = guard.resume(
        operation.operation_id, approval=approval, at=NOW, allow_broadcast=True
    )

    assert resumed.state is OperationState.SOURCE_PENDING
    assert len(pool.primary.sent) == 2
    assert pool.primary.sent[0] == pool.primary.sent[1]
    assert signer.sign_calls == 1


def test_unknown_submission_with_advanced_nonce_stops_for_reconciliation(
    tmp_path: Path,
) -> None:
    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer, send_failures=1)
    plan = make_plan(signer.address)

    with pytest.raises(SubmissionUnknown):
        guard.execute(
            plan,
            approval_for(plan, subject_signer=signer.address),
            idempotency_key="request-advanced",
            signer=signer,
            at=NOW,
        )
    operation = guard.store.get_operation_by_idempotency_key("request-advanced")
    pool.primary.pending_nonce = 8
    pool.secondary.pending_nonce = 8

    with pytest.raises(NeedsReconciliation):
        guard.resume(operation.operation_id)

    current = guard.store.get_operation(operation.operation_id)
    assert current.state is OperationState.NEEDS_RECONCILIATION
    assert len(pool.primary.sent) == 1


def test_bad_signer_output_fails_before_any_broadcast(tmp_path: Path) -> None:
    expected = MemorySigner()
    wrong = MemorySigner()
    wrong._account = Account.create()
    guard, pool = engine(tmp_path, wrong)
    plan = make_plan(expected.address)

    with pytest.raises(PreBroadcastFailure) as error:
        guard.execute(
            plan,
            approval_for(plan, subject_signer=expected.address),
            idempotency_key="request-bad-signer",
            signer=wrong,
            at=NOW,
        )

    operation = guard.store.get_operation(error.value.operation_id)
    assert operation.state is OperationState.FAILED_PRE_BROADCAST
    assert pool.primary.sent == []


def test_source_finality_advances_to_order_pending(tmp_path: Path) -> None:
    signer = MemorySigner()
    finality_calls: list[str] = []

    def finality(
        _pool: object,
        transaction_hash: str,
        _confirmations: int,
        **_options: object,
    ) -> dict[str, object]:
        finality_calls.append(transaction_hash)
        return {
            "transactionHash": transaction_hash,
            "blockNumber": "0x1",
            "blockHash": "0x" + "cd" * 32,
            "status": "0x1",
        }

    guard, _pool = engine(tmp_path, signer, finality_waiter=finality)
    plan = make_plan(signer.address)
    pending = guard.execute(
        plan,
        approval_for(plan, subject_signer=signer.address),
        idempotency_key="request-finality",
        signer=signer,
        at=NOW,
    )

    final = guard.refresh_source(pending.operation_id, max_polls=1)

    assert final.state is OperationState.ORDER_PENDING
    assert finality_calls == [pending.tx_hash]


def test_synthetic_fulfillment_fixture_can_complete_the_exact_operation(
    tmp_path: Path,
) -> None:
    fixture_path = Path(__file__).parent / "fixtures/debridge/fulfilled_order_synthetic.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    expected = fixture["expected"]
    assert isinstance(expected, dict)
    signer = str(expected["signer"])
    recipient = str(expected["receiver"])
    destination_amount = int(expected["amount_wei"])
    source_input_amount = int(expected["source_amount_wei"])
    plan = Plan.create(
        {
            "provider": {
                "name": "debridge",
                "version": "2",
                "route_id": "arb-rh-native-v2",
                "route_kind": "native_in_swap_dln_native_out",
                "destination_dln_proxy": fixture["address"],
                "destination_fulfillment_topic": fixture["topics"][0],
            },
            "intent": {
                "created_at": "2026-07-24T18:00:00Z",
                "expires_at": "2026-07-24T19:00:00Z",
                "source_chain_id": int(expected["source_chain_id"]),
                "destination_chain_id": int(expected["destination_chain_id"]),
                "amount_wei": source_input_amount,
                "minimum_output_wei": destination_amount,
                "recipient": recipient,
                "expected_signer": signer,
            },
            "unsigned_transaction": {
                "chain_id": int(expected["source_chain_id"]),
                "nonce": 1,
                "to": ROUTER,
                "value": source_input_amount,
                "data": "0x1234",
                "gas": 100_000,
                "max_fee_per_gas": 2,
                "max_priority_fee_per_gas": 1,
            },
            "decoded_semantics": {
                "source_order_token": expected["source_token"],
                "source_gross_amount_wei": source_input_amount,
                "protocol_fee_amount_wei": 0,
                "source_net_amount_wei": source_input_amount,
                "source_swap_router": "0x" + "55" * 20,
                "order_id": expected["order_id"],
                "destination_chain_id": int(expected["destination_chain_id"]),
                "destination_receiver": recipient,
                "destination_token": expected["destination_token"],
                "destination_amount_wei": destination_amount,
                "external_call": False,
                "allowed_taker": expected["allowed_taker"],
            },
        }
    )
    values = {
        "plan_id": plan.plan_id,
        "authorization_id": "live-fixture",
        "actor": "test-actor",
        "subject_signer": signer,
        "approved_at": "2026-07-24T18:01:00Z",
        "expires_at": "2026-07-24T18:59:00Z",
    }
    approval = Approval.create(
        **values,
        issuer=OPERATOR.address,
        signature=OPERATOR.sign_message(
            encode_defunct(primitive=Approval.signing_payload(**values))
        ).signature.to_0x_hex(),
    )
    store = SQLiteOperationStore(tmp_path / "private" / "operations.db")
    operation = store.reserve_operation(
        plan,
        idempotency_key="live-fixture",
        signer=signer,
        source_chain_id=int(expected["source_chain_id"]),
        nonce=1,
        approval_id=approval.approval_id,
    )
    claim = store.claim_preparation(
        operation.operation_id,
        kind="test-eip1559",
        fingerprint="live-fixture",
        replay_safe=True,
    )
    assert claim.token is not None
    operation = store.complete_preparation(operation.operation_id, claim.token, b"\x01")
    for state in (OperationState.BROADCAST_ATTEMPTED, OperationState.SOURCE_PENDING):
        operation = store.append_state_event(operation.operation_id, state)
    assert operation.tx_hash is not None
    proof = verify_source_receipt(
        operation_id=operation.operation_id,
        plan=operation.plan,
        receipt={
            "transactionHash": operation.tx_hash,
            "blockNumber": "0x1",
            "blockHash": "0x" + "cd" * 32,
            "status": "0x1",
        },
        chain_id=int(expected["source_chain_id"]),
        transaction_hash=operation.tx_hash,
        confirmations=1,
        receipt_status=1,
    )
    operation = store._commit_source_finality(proof)
    operation = store.append_state_event(
        operation.operation_id, OperationState.DESTINATION_PENDING
    )

    def finality(
        _pool: object,
        _transaction_hash: str,
        _confirmations: int,
        **_options: object,
    ) -> dict[str, object]:
        return {
            "transactionHash": str(fixture["transaction_hash"]),
            "blockHash": "0x" + "cd" * 32,
            "blockNumber": "0x1",
            "status": "0x1",
            "logs": [
                {
                        "address": fixture["address"],
                        "topics": fixture["topics"],
                        "data": fixture["data"],
                        "logIndex": "0x0",
                }
            ]
        }

    seen: dict[str, dict[str, object]] = {}
    source_pool = FakeRpcPool(FakeRpcClient(seen), FakeRpcClient(seen))
    guard = FixtureExecutionEngine(
        store,
        source_pool,  # type: ignore[arg-type]
        authorizer=FixtureAuthorizer(),
        finality_waiter=finality,
    )
    destination_pool = FakeRpcPool(
        FakeRpcClient(seen),
        FakeRpcClient(seen),
        chain_id=int(expected["destination_chain_id"]),
    )

    verified = guard.verify_destination(
        operation.operation_id,
        destination_transaction_hash=str(fixture["transaction_hash"]),
        destination_rpc=destination_pool,  # type: ignore[arg-type]
        confirmations=1,
        max_polls=1,
    )

    assert verified.state is OperationState.VERIFIED


def test_resume_never_invokes_unrelated_callbacks(tmp_path: Path) -> None:
    signer = MemorySigner()
    guard, _pool = engine(tmp_path, signer)
    plan = make_plan(signer.address)
    callbacks: list[Callable[[], None]] = []

    operation = guard.reserve(
        plan,
        approval_for(plan, subject_signer=signer.address),
        idempotency_key="request-reserved",
        at=NOW,
    )

    with pytest.raises(PreBroadcastFailure, match="signature"):
        guard.resume(operation.operation_id)
    assert callbacks == []
