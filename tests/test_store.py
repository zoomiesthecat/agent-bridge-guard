"""Durable operation-store behavior."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from stat import S_IMODE

import pytest

from agent_bridge_guard.models import Plan
from agent_bridge_guard.store import (
    IdempotencyConflict,
    NonceConflict,
    OperationState,
    PreparationClaimState,
    PrivateStoragePathError,
    SQLiteOperationStore,
    StateTransitionError,
)
from agent_bridge_guard.verification import VerifiedDestinationFulfillment, VerifiedSourceReceipt


def make_plan(amount: int = 1) -> Plan:
    return Plan.create(
        {
            "created_at": "2026-07-24T21:50:00Z",
            "intent": {"amount_wei": amount, "destination_chain_id": 4663},
            "decoded_semantics": {
                "source_order_token": "0x" + "55" * 20,
                "source_gross_amount_wei": amount + 1,
                "protocol_fee_amount_wei": 1,
                "source_net_amount_wei": amount,
                "source_swap_router": "0x" + "55" * 20,
                "order_id": "0x" + "ab" * 32,
            },
            "unsigned_transaction": {"chain_id": 42161, "nonce": 7},
        }
    )


def reserve(
    store: SQLiteOperationStore, *, key: str = "request-1", approval_id: str = "approval-1"
) -> str:
    return store.reserve_operation(
        make_plan(),
        idempotency_key=key,
        signer="0x1111111111111111111111111111111111111111",
        source_chain_id=42161,
        nonce=7,
        approval_id=approval_id,
    ).operation_id


def prepare(store: SQLiteOperationStore, operation_id: str, raw_signed_tx: bytes) -> object:
    claim = store.claim_preparation(
        operation_id,
        kind="test-eip1559",
        fingerprint="test-plan",
        replay_safe=True,
    )
    assert claim.state is PreparationClaimState.OWNED
    assert claim.token is not None
    return store.complete_preparation(operation_id, claim.token, raw_signed_tx)


def test_reservation_is_private_idempotent_and_persists_plan(tmp_path: Path) -> None:
    database = tmp_path / "private" / "operations.db"
    store = SQLiteOperationStore(database)

    operation_id = reserve(store)
    again = reserve(store)
    operation = store.get_operation(operation_id)
    by_key = store.get_operation_by_idempotency_key("request-1")

    assert S_IMODE(database.stat().st_mode) == 0o600
    assert again == operation_id
    assert by_key.operation_id == operation_id
    assert operation.plan == make_plan()
    assert operation.approval_id == "approval-1"
    assert operation.state is OperationState.RESERVED
    assert operation.events[0].sequence == 1
    assert operation.events[0].state is OperationState.RESERVED


def test_reservation_rejects_key_or_nonce_reuse_for_different_operation(tmp_path: Path) -> None:
    store = SQLiteOperationStore(tmp_path / "operations.db")
    reserve(store)

    with pytest.raises(IdempotencyConflict):
        store.reserve_operation(
            make_plan(2),
            idempotency_key="request-1",
            signer="0x1111111111111111111111111111111111111111",
            source_chain_id=42161,
            nonce=7,
            approval_id="approval-1",
        )
    with pytest.raises(IdempotencyConflict):
        reserve(store, approval_id="another-approval")
    with pytest.raises(NonceConflict):
        store.reserve_operation(
            make_plan(2),
            idempotency_key="request-2",
            signer="0x1111111111111111111111111111111111111111",
            source_chain_id=42161,
            nonce=7,
            approval_id="approval-2",
        )
    with pytest.raises(IdempotencyConflict, match="approval"):
        store.reserve_operation(
            make_plan(2),
            idempotency_key="request-2",
            signer="0x2222222222222222222222222222222222222222",
            source_chain_id=42161,
            nonce=8,
            approval_id="approval-1",
        )


def test_concurrent_reservations_create_one_operation(tmp_path: Path) -> None:
    database = tmp_path / "operations.db"

    def request() -> str:
        return reserve(SQLiteOperationStore(database))

    with ThreadPoolExecutor(max_workers=20) as executor:
        operation_ids = list(executor.map(lambda _: request(), range(100)))

    assert len(set(operation_ids)) == 1


def test_concurrent_initialization_is_safe(tmp_path: Path) -> None:
    database = tmp_path / "private" / "operations.db"

    def initialize() -> str:
        return reserve(SQLiteOperationStore(database))

    with ThreadPoolExecutor(max_workers=32) as executor:
        operation_ids = list(executor.map(lambda _: initialize(), range(100)))

    assert len(set(operation_ids)) == 1


def test_existing_broad_or_symlinked_private_root_is_rejected(tmp_path: Path) -> None:
    broad_root = tmp_path / "broad"
    broad_root.mkdir(mode=0o755)
    with pytest.raises(PrivateStoragePathError, match="private"):
        SQLiteOperationStore(broad_root / "operations.db")
    assert S_IMODE(broad_root.stat().st_mode) == 0o755

    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(target, target_is_directory=True)
    with pytest.raises(PrivateStoragePathError, match="symlink"):
        SQLiteOperationStore(linked_root / "operations.db")


def test_state_events_are_monotonic_and_broadcast_preparation_is_durable(tmp_path: Path) -> None:
    store = SQLiteOperationStore(tmp_path / "operations.db")
    operation_id = reserve(store)

    prepared = prepare(store, operation_id, b"\x01\x02")

    assert prepared.state is OperationState.BROADCAST_PREPARED
    assert prepared.raw_signed_tx == b"\x01\x02"
    assert prepared.tx_hash == "0x22ae6da6b482f9b1b19b0b897c3fd43884180a1c5ee361e1107a1bc635649dda"
    assert [event.sequence for event in prepared.events] == [1, 2]

    attempted = store.append_state_event(operation_id, OperationState.BROADCAST_ATTEMPTED)
    source_pending = store.append_state_event(attempted.operation_id, OperationState.SOURCE_PENDING)
    forged = {"chain_id": 42161, "transaction_hash": prepared.tx_hash}
    with pytest.raises(StateTransitionError, match="verifier-produced"):
        store.record_source_finality(source_pending.operation_id, forged)
    with pytest.raises(StateTransitionError, match="verifier-produced"):
        store.record_destination_fulfillment(source_pending.operation_id, forged)

    with pytest.raises(StateTransitionError):
        store.append_state_event(operation_id, OperationState.SOURCE_PENDING)


def test_unfenced_prepare_broadcast_path_is_rejected(tmp_path: Path) -> None:
    store = SQLiteOperationStore(tmp_path / "operations.db")

    with pytest.raises(StateTransitionError, match="fenced claim"):
        store.prepare_broadcast(reserve(store), b"\x01")


def test_generic_transition_rejects_proof_states_and_cancellation(tmp_path: Path) -> None:
    store = SQLiteOperationStore(tmp_path / "private" / "operations.db")
    operation_id = reserve(store)

    with pytest.raises(StateTransitionError):
        store.append_state_event(operation_id, OperationState.SOURCE_FINAL)
    with pytest.raises(StateTransitionError, match="unsupported"):
        store.append_state_event(operation_id, OperationState.CANCELLED_CONFIRMED)
    with pytest.raises(StateTransitionError, match="proof-bearing"):
        store.append_state_event(operation_id, OperationState.VERIFIED)
    with pytest.raises(StateTransitionError, match="proof-bearing"):
        store.append_state_event(operation_id, OperationState.SOURCE_FAILED)
    with pytest.raises(StateTransitionError, match="proof-bearing"):
        store.append_state_event(operation_id, OperationState.BROADCAST_PREPARED)
    with pytest.raises(StateTransitionError, match="proof-bearing"):
        store.append_state_event(operation_id, OperationState.FAILED_PRE_BROADCAST)


def test_stale_preparation_claim_cannot_fail_or_replace_prepared_winner(tmp_path: Path) -> None:
    now = [1_000]
    store = SQLiteOperationStore(
        tmp_path / "operations.db", clock_ns=lambda: now[0], preparation_lease_ns=10
    )
    operation_id = reserve(store)

    first = store.claim_preparation(
        operation_id, kind="local-eip1559", fingerprint="plan-1", replay_safe=True
    )
    assert first.state is PreparationClaimState.OWNED
    assert first.token is not None
    now[0] += 11
    winner = store.claim_preparation(
        operation_id, kind="local-eip1559", fingerprint="plan-1", replay_safe=True
    )
    assert winner.state is PreparationClaimState.OWNED
    assert winner.token is not None

    prepared = store.complete_preparation(operation_id, winner.token, b"exact-winner-bytes")
    stale_failure = store.fail_preparation(operation_id, first.token)
    stale_completion = store.complete_preparation(operation_id, first.token, b"stale-bytes")

    assert prepared.state is OperationState.BROADCAST_PREPARED
    assert stale_failure.state is OperationState.BROADCAST_PREPARED
    assert stale_completion.raw_signed_tx == b"exact-winner-bytes"
    assert store.get_operation(operation_id).raw_signed_tx == b"exact-winner-bytes"


def test_expired_non_replay_safe_preparation_claim_fails_closed(tmp_path: Path) -> None:
    now = [1_000]
    store = SQLiteOperationStore(
        tmp_path / "operations.db", clock_ns=lambda: now[0], preparation_lease_ns=10
    )
    operation_id = reserve(store)
    store.claim_preparation(
        operation_id, kind="remote-eip1559", fingerprint="plan-1", replay_safe=False
    )
    now[0] += 11

    claim = store.claim_preparation(
        operation_id, kind="remote-eip1559", fingerprint="plan-1", replay_safe=False
    )

    assert claim.state is PreparationClaimState.REPLAY_UNSAFE


def test_active_preparation_claim_rejects_a_different_signed_bytes_fingerprint(
    tmp_path: Path,
) -> None:
    store = SQLiteOperationStore(tmp_path / "operations.db")
    operation_id = reserve(store)
    store.claim_preparation(
        operation_id,
        kind="detached-eip1559",
        fingerprint="0x" + "01" * 32,
        replay_safe=True,
    )

    with pytest.raises(StateTransitionError, match="another request"):
        store.claim_preparation(
            operation_id,
            kind="detached-eip1559",
            fingerprint="0x" + "02" * 32,
            replay_safe=True,
        )


def test_public_source_finality_mapping_is_rejected(tmp_path: Path) -> None:
    store = SQLiteOperationStore(tmp_path / "operations.db")
    operation_id = reserve(store)
    prepared = prepare(store, operation_id, b"\x01")
    attempted = store.append_state_event(operation_id, OperationState.BROADCAST_ATTEMPTED)
    pending = store.append_state_event(attempted.operation_id, OperationState.SOURCE_PENDING)
    evidence = {
        "chain_id": 42161,
        "transaction_hash": prepared.tx_hash,
        "block_number": 10,
        "block_hash": "0x" + "cd" * 32,
        "confirmations": 1,
        "rpc_quorum": 2,
        "receipt_status": 1,
    }

    with pytest.raises(StateTransitionError, match="verifier-produced"):
        store.record_source_finality(pending.operation_id, evidence)


def test_public_source_failure_mapping_is_rejected(tmp_path: Path) -> None:
    store = SQLiteOperationStore(tmp_path / "operations.db")
    operation_id = reserve(store)
    prepared = prepare(store, operation_id, b"\x03")
    attempted = store.append_state_event(operation_id, OperationState.BROADCAST_ATTEMPTED)
    pending = store.append_state_event(attempted.operation_id, OperationState.SOURCE_PENDING)
    evidence = {
        "chain_id": 42161,
        "transaction_hash": prepared.tx_hash,
        "block_number": 10,
        "block_hash": "0x" + "cd" * 32,
        "confirmations": 1,
        "rpc_quorum": 2,
        "receipt_status": 0,
    }

    with pytest.raises(StateTransitionError, match="verifier-produced"):
        store.record_source_failure(pending.operation_id, evidence)


def test_verified_proofs_cannot_be_constructed_from_forged_fields() -> None:
    with pytest.raises(TypeError, match="receipt verifier"):
        VerifiedSourceReceipt(
            operation_id="other",
            plan_id="plan",
            chain_id=42161,
            transaction_hash="0x" + "ab" * 32,
            block_number=1,
            block_hash="0x" + "cd" * 32,
            confirmations=1,
            receipt_status=1,
        )
    with pytest.raises(TypeError, match="receipt verifier"):
        VerifiedDestinationFulfillment(
            operation_id="other",
            plan_id="plan",
            chain_id=4663,
            transaction_hash="0x" + "ab" * 32,
            block_number=1,
            block_hash="0x" + "cd" * 32,
            confirmations=1,
            order_id="0x" + "ab" * 32,
            log_index=0,
            log_address="0x" + "11" * 20,
            log_topic="0x" + "22" * 32,
            signer="0x" + "33" * 20,
            source_chain_id=42161,
            source_token="0x" + "44" * 20,
            source_amount_wei=1,
            destination_chain_id=4663,
            receiver="0x" + "55" * 20,
            destination_token="0x" + "00" * 20,
            destination_amount_wei=1,
            allowed_taker=None,
        )
