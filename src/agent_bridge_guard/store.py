"""Private SQLite storage for durable guarded bridge operations."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from pathlib import Path
from stat import S_IMODE, S_ISDIR, S_ISLNK, S_ISREG
from typing import cast

from eth_hash.auto import keccak

from agent_bridge_guard.approval import Approval
from agent_bridge_guard.execution_plan import ExecutionPlan
from agent_bridge_guard.models import Plan
from agent_bridge_guard.verification import (
    VerifiedDestinationFulfillment,
    VerifiedSourceFailure,
    VerifiedSourceReceipt,
)


class StoreError(RuntimeError):
    """Base error for durable operation storage."""


class IdempotencyConflict(StoreError):
    """The idempotency key already identifies a different plan."""


class NonceConflict(StoreError):
    """The signer, source chain, and nonce are already reserved."""


class OperationNotFound(StoreError):
    """The requested operation is absent."""


class StateTransitionError(StoreError):
    """The requested operation state change is not permitted."""


class PrivateStoragePathError(StoreError):
    """The database path is not a private, owned regular filesystem location."""


class OperationState(StrEnum):
    """Persisted lifecycle states for a guarded cross-chain operation."""

    RESERVED = "reserved"
    BROADCAST_PREPARED = "broadcast_prepared"
    BROADCAST_ATTEMPTED = "broadcast_attempted"
    SUBMISSION_UNKNOWN = "submission_unknown"
    SOURCE_PENDING = "source_pending"
    NEEDS_RECONCILIATION = "needs_reconciliation"
    SOURCE_FAILED = "source_failed"
    SOURCE_FINAL = "source_final"
    ORDER_PENDING = "order_pending"
    DESTINATION_PENDING = "destination_pending"
    VERIFIED = "verified"
    FAILED_PRE_BROADCAST = "failed_pre_broadcast"
    CANCELLED_CONFIRMED = "cancelled_confirmed"


class PreparationClaimState(StrEnum):
    """Outcome of an atomic attempt to own broadcast preparation."""

    OWNED = "owned"
    IN_PROGRESS = "in_progress"
    PREPARED = "prepared"
    FAILED = "failed"
    REPLAY_UNSAFE = "replay_unsafe"
    UNAVAILABLE = "unavailable"


_TRANSITIONS: dict[OperationState, frozenset[OperationState]] = {
    OperationState.RESERVED: frozenset(
        {
            OperationState.BROADCAST_PREPARED,
            OperationState.FAILED_PRE_BROADCAST,
            OperationState.CANCELLED_CONFIRMED,
        }
    ),
    OperationState.BROADCAST_PREPARED: frozenset(
        {
            OperationState.BROADCAST_ATTEMPTED,
            OperationState.FAILED_PRE_BROADCAST,
            OperationState.CANCELLED_CONFIRMED,
        }
    ),
    OperationState.BROADCAST_ATTEMPTED: frozenset(
        {
            OperationState.SOURCE_PENDING,
            OperationState.SUBMISSION_UNKNOWN,
            OperationState.NEEDS_RECONCILIATION,
        }
    ),
    OperationState.SUBMISSION_UNKNOWN: frozenset(
        {
            OperationState.SOURCE_PENDING,
            OperationState.NEEDS_RECONCILIATION,
            OperationState.CANCELLED_CONFIRMED,
        }
    ),
    OperationState.NEEDS_RECONCILIATION: frozenset(
        {OperationState.SOURCE_PENDING, OperationState.CANCELLED_CONFIRMED}
    ),
    OperationState.SOURCE_PENDING: frozenset(
        {
            OperationState.SOURCE_FAILED,
            OperationState.SOURCE_FINAL,
            OperationState.NEEDS_RECONCILIATION,
        }
    ),
    OperationState.SOURCE_FAILED: frozenset(),
    OperationState.SOURCE_FINAL: frozenset({OperationState.ORDER_PENDING}),
    OperationState.ORDER_PENDING: frozenset({OperationState.DESTINATION_PENDING}),
    OperationState.DESTINATION_PENDING: frozenset({OperationState.VERIFIED}),
    OperationState.VERIFIED: frozenset(),
    OperationState.FAILED_PRE_BROADCAST: frozenset({OperationState.RESERVED}),
    OperationState.CANCELLED_CONFIRMED: frozenset(),
}


def _evidence_json(evidence: Mapping[str, object]) -> str:
    return json.dumps(dict(evidence), sort_keys=True, separators=(",", ":"), allow_nan=False)


def _load_evidence(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    try:
        decoded = json.loads(str(value))
    except (TypeError, json.JSONDecodeError) as exc:
        raise StoreError("persisted evidence is invalid") from exc
    if not isinstance(decoded, dict):
        raise StoreError("persisted evidence is invalid")
    return decoded


def _validate_evidence(
    evidence: Mapping[str, object], label: str, *, require_log_identity: bool = False
) -> None:
    required = {
        "schema_version": int,
        "verifier_version": str,
        "plan_id": str,
        "chain_id": int,
        "transaction_hash": str,
        "block_number": int,
        "block_hash": str,
        "confirmations": int,
        "rpc_quorum": int,
    }
    if require_log_identity:
        required.update({"order_id": str, "log_index": int, "log_address": str, "log_topic": str})
    for key, expected_type in required.items():
        value = evidence.get(key)
        if type(value) is not expected_type:
            raise StateTransitionError(f"{label} evidence {key} is invalid")
    chain_id = cast(int, evidence["chain_id"])
    block_number = cast(int, evidence["block_number"])
    confirmations = cast(int, evidence["confirmations"])
    rpc_quorum = cast(int, evidence["rpc_quorum"])
    if (
        chain_id <= 0
        or block_number < 0
        or confirmations < 0
        or rpc_quorum < 2
        or evidence["schema_version"] != 1
        or evidence["verifier_version"]
        != "agent-bridge-guard/receipt-verifier/v1"
        or not str(evidence["transaction_hash"]).startswith("0x")
        or not str(evidence["block_hash"]).startswith("0x")
    ):
        raise StateTransitionError(f"{label} evidence is invalid")


def _plan_policy_binding(plan: Plan) -> tuple[str, int, str, str]:
    if plan.schema_version != 2:
        raise StateTransitionError("legacy unbound plan cannot reserve an execution")
    binding = plan.body().get("policy_binding")
    if not isinstance(binding, dict):
        raise StateTransitionError("plan policy binding is missing")
    policy_id = binding.get("policy_id")
    policy_version = binding.get("policy_version")
    policy_digest = binding.get("policy_digest")
    route_manifest_digest = binding.get("route_manifest_digest")
    if (
        not isinstance(policy_id, str)
        or isinstance(policy_version, bool)
        or not isinstance(policy_version, int)
        or policy_version <= 0
        or not isinstance(policy_digest, str)
        or not isinstance(route_manifest_digest, str)
    ):
        raise StateTransitionError("plan policy binding is invalid")
    return policy_id, policy_version, policy_digest, route_manifest_digest


@dataclass(frozen=True, slots=True)
class OperationEvent:
    """One append-only state event."""

    sequence: int
    state: OperationState
    occurred_at_ns: int
    cancellation_proof: str | None


@dataclass(frozen=True, slots=True)
class Operation:
    """Complete durable record for an immutable execution plan."""

    operation_id: str
    idempotency_key: str
    approval_id: str
    plan: Plan
    signer: str
    source_chain_id: int
    nonce: int
    state: OperationState
    created_at_ns: int
    raw_signed_tx: bytes | None = dataclass_field(repr=False)
    tx_hash: str | None
    source_finality_evidence: dict[str, object] | None
    destination_fulfillment_evidence: dict[str, object] | None
    events: tuple[OperationEvent, ...]
    approval: Approval | None = dataclass_field(default=None, repr=False)
    policy_id: str | None = None
    policy_version: int | None = None
    policy_digest: str | None = None
    route_manifest_digest: str | None = None


@dataclass(frozen=True, slots=True)
class OperationStatus:
    """Compact status view without duplicating the immutable plan."""

    operation_id: str
    state: OperationState
    tx_hash: str | None
    events: tuple[OperationEvent, ...]


@dataclass(frozen=True, slots=True)
class PreparationClaim:
    """A token-fenced preparation lease for exactly one operation."""

    operation: Operation = dataclass_field(repr=False)
    state: PreparationClaimState
    token: str | None = dataclass_field(default=None, repr=False)


class SQLiteOperationStore:
    """SQLite store with private paths, atomic locks, and durable state transitions."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        clock_ns: Callable[[], int] = time.time_ns,
        preparation_lease_ns: int = 30_000_000_000,
    ) -> None:
        if preparation_lease_ns <= 0:
            raise ValueError("preparation lease must be positive")
        self._path = Path(database_path)
        self._clock_ns = clock_ns
        self._preparation_lease_ns = preparation_lease_ns
        self._prepare_private_path()
        self._initialize()

    def reserve_operation(
        self,
        plan: Plan,
        idempotency_key: str,
        signer: str,
        source_chain_id: int,
        nonce: int,
        approval_id: str | None = None,
        *,
        approval: Approval | None = None,
    ) -> Operation:
        """Atomically reserve a nonce or return the matching idempotent operation."""

        bound_policy: tuple[str | None, int | None, str | None, str | None]
        if plan.schema_version == 2:
            if approval is None or approval.schema_version != 3:
                raise StateTransitionError(
                    "bound execution requires its exact reviewable approval"
                )
            if approval.plan_id != plan.plan_id:
                raise StateTransitionError("approval does not match plan")
            bound_policy = _plan_policy_binding(plan)
            effective_approval_id = approval.approval_id
            approval_json = approval._document_json
        else:
            if approval is not None:
                effective_approval_id = approval.approval_id
            elif approval_id:
                effective_approval_id = approval_id
            else:
                raise StateTransitionError("approval_id is required")
            bound_policy = (None, None, None, None)
            approval_json = None
        with self._transaction() as connection:
            by_key = connection.execute(
                """SELECT operation_id, plan_id, approval_id FROM operations
                WHERE idempotency_key = ?""",
                (idempotency_key,),
            ).fetchone()
            if by_key is not None:
                if (
                    str(by_key["plan_id"]) != plan.plan_id
                    or str(by_key["approval_id"]) != effective_approval_id
                ):
                    raise IdempotencyConflict("idempotency key is bound to another plan")
                return self._load_operation(connection, str(by_key["operation_id"]))
            by_nonce = connection.execute(
                """SELECT operation_id FROM operations
                WHERE signer = ? AND source_chain_id = ? AND nonce = ?""",
                (signer, source_chain_id, nonce),
            ).fetchone()
            if by_nonce is not None:
                raise NonceConflict("signer, source chain, and nonce are already reserved")
            by_approval = connection.execute(
                "SELECT operation_id FROM operations WHERE approval_id = ?",
                (effective_approval_id,),
            ).fetchone()
            if by_approval is not None:
                raise IdempotencyConflict("approval is already bound to another operation")

            operation_id = str(uuid.uuid4())
            created_at_ns = self._clock_ns()
            connection.execute(
                """INSERT INTO operations (
                operation_id, idempotency_key, approval_id, approval_json,
                policy_id, policy_version, policy_digest, route_manifest_digest,
                plan_id, plan_json, signer, source_chain_id, nonce, state, created_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    operation_id,
                    idempotency_key,
                    effective_approval_id,
                    approval_json,
                    *bound_policy,
                    plan.plan_id,
                    plan._document_json,
                    signer,
                    source_chain_id,
                    nonce,
                    OperationState.RESERVED.value,
                    created_at_ns,
                ),
            )
            self._append_event(
                connection, operation_id, OperationState.RESERVED, created_at_ns, None
            )
            return self._load_operation(connection, operation_id)

    def append_state_event(
        self,
        operation_id: str,
        state: OperationState,
        *,
        cancellation_proof: str | None = None,
    ) -> Operation:
        """Append one ordinary permitted state transition.

        Finality and fulfillment states deliberately have dedicated methods below:
        callers must not be able to manufacture proof-bearing lifecycle history.
        Cancellation is unsupported in 0.1 and therefore fail-closed here.
        """

        with self._transaction() as connection:
            operation = self._load_operation(connection, operation_id)
            if state in {
                OperationState.BROADCAST_PREPARED,
                OperationState.FAILED_PRE_BROADCAST,
                OperationState.SOURCE_FINAL,
                OperationState.SOURCE_FAILED,
                OperationState.ORDER_PENDING,
                OperationState.VERIFIED,
            }:
                raise StateTransitionError("proof-bearing state requires durable evidence")
            if state is OperationState.CANCELLED_CONFIRMED:
                raise StateTransitionError("cancellation is unsupported in 0.1")
            self._require_transition(operation.state, state, cancellation_proof)
            occurred_at_ns = self._clock_ns()
            connection.execute(
                "UPDATE operations SET state = ? WHERE operation_id = ?",
                (state.value, operation_id),
            )
            self._append_event(connection, operation_id, state, occurred_at_ns, cancellation_proof)
            return self._load_operation(connection, operation_id)

    def record_source_finality(
        self, operation_id: str, evidence: Mapping[str, object]
    ) -> Operation:
        """Reject obsolete caller-supplied proof mappings."""

        del operation_id, evidence
        raise StateTransitionError("source proof requires a verifier-produced capability")

    def _commit_source_finality(self, proof: VerifiedSourceReceipt) -> Operation:
        """Persist a verifier-produced source success proof atomically."""

        with self._transaction() as connection:
            operation = self._load_operation(connection, proof.operation_id)
            evidence = proof.to_dict()
            self._validate_source_evidence(operation, evidence, receipt_status=1)
            occurred_at_ns = self._clock_ns()
            if operation.state is OperationState.SOURCE_PENDING:
                connection.execute(
                    """UPDATE operations SET state = ?, source_finality_evidence = ?
                    WHERE operation_id = ?""",
                    (
                        OperationState.ORDER_PENDING.value,
                        _evidence_json(evidence),
                        proof.operation_id,
                    ),
                )
                self._append_event(
                    connection,
                    proof.operation_id,
                    OperationState.SOURCE_FINAL,
                    occurred_at_ns,
                    None,
                )
                self._append_event(
                    connection,
                    proof.operation_id,
                    OperationState.ORDER_PENDING,
                    occurred_at_ns,
                    None,
                )
            elif operation.state is OperationState.SOURCE_FINAL:
                connection.execute(
                    """UPDATE operations SET state = ?, source_finality_evidence = ?
                    WHERE operation_id = ?""",
                    (
                        OperationState.ORDER_PENDING.value,
                        _evidence_json(evidence),
                        proof.operation_id,
                    ),
                )
                self._append_event(
                    connection,
                    proof.operation_id,
                    OperationState.ORDER_PENDING,
                    occurred_at_ns,
                    None,
                )
            else:
                raise StateTransitionError("source finality is not expected in the current state")
            return self._load_operation(connection, proof.operation_id)

    def record_source_failure(
        self, operation_id: str, evidence: Mapping[str, object]
    ) -> Operation:
        """Reject obsolete caller-supplied failure mappings."""

        del operation_id, evidence
        raise StateTransitionError("source failure proof requires a verifier-produced capability")

    def _commit_source_failure(self, proof: VerifiedSourceFailure) -> Operation:
        """Persist a verifier-produced source failure proof atomically."""

        with self._transaction() as connection:
            operation = self._load_operation(connection, proof.operation_id)
            if operation.state is not OperationState.SOURCE_PENDING:
                raise StateTransitionError("source failure is not expected in the current state")
            evidence = proof.to_dict()
            self._validate_source_failure_evidence(operation, evidence)
            occurred_at_ns = self._clock_ns()
            connection.execute(
                """UPDATE operations SET state = ?, source_finality_evidence = ?
                WHERE operation_id = ?""",
                (
                    OperationState.SOURCE_FAILED.value,
                    _evidence_json(evidence),
                    proof.operation_id,
                ),
            )
            self._append_event(
                connection,
                proof.operation_id,
                OperationState.SOURCE_FAILED,
                occurred_at_ns,
                None,
            )
            return self._load_operation(connection, proof.operation_id)

    def record_destination_fulfillment(
        self, operation_id: str, evidence: Mapping[str, object]
    ) -> Operation:
        """Reject obsolete caller-supplied fulfillment mappings."""

        del operation_id, evidence
        raise StateTransitionError(
            "destination proof requires a verifier-produced capability"
        )

    def _commit_destination_fulfillment(
        self,
        proof: VerifiedDestinationFulfillment,
    ) -> Operation:
        """Persist a verifier-produced exact fulfillment proof atomically."""

        with self._transaction() as connection:
            operation = self._load_operation(connection, proof.operation_id)
            if operation.state is not OperationState.DESTINATION_PENDING:
                raise StateTransitionError(
                    "destination fulfillment is not expected in the current state"
                )
            evidence = proof.to_dict()
            self._validate_destination_evidence(operation, evidence)
            occurred_at_ns = self._clock_ns()
            connection.execute(
                """UPDATE operations SET state = ?, destination_fulfillment_evidence = ?
                WHERE operation_id = ?""",
                (
                    OperationState.VERIFIED.value,
                    _evidence_json(evidence),
                    proof.operation_id,
                ),
            )
            self._append_event(
                connection,
                proof.operation_id,
                OperationState.VERIFIED,
                occurred_at_ns,
                None,
            )
            return self._load_operation(connection, proof.operation_id)

    def prepare_broadcast(self, operation_id: str, raw_signed_tx: bytes) -> Operation:
        """Reject the obsolete unfenced preparation API."""

        del operation_id, raw_signed_tx
        raise StateTransitionError("broadcast preparation requires a fenced claim token")

    def claim_preparation(
        self,
        operation_id: str,
        *,
        kind: str,
        fingerprint: str,
        replay_safe: bool,
    ) -> PreparationClaim:
        """Atomically acquire a fenced lease to create one signed transaction.

        A stale claimant may be replaced only when repeating the adapter is known to
        recreate exact bytes for this stable operation preparation.  Completion and
        failure are separately token-fenced, so an old claimant cannot overwrite a
        newer result.
        """

        if not kind or not fingerprint:
            raise ValueError("preparation kind and fingerprint are required")
        with self._transaction() as connection:
            operation = self._load_operation(connection, operation_id)
            if operation.state is OperationState.BROADCAST_PREPARED:
                return PreparationClaim(operation, PreparationClaimState.PREPARED)
            if operation.state is OperationState.FAILED_PRE_BROADCAST:
                return PreparationClaim(operation, PreparationClaimState.FAILED)
            if operation.state is not OperationState.RESERVED:
                return PreparationClaim(operation, PreparationClaimState.UNAVAILABLE)
            row = connection.execute(
                """SELECT preparation_token, preparation_kind, preparation_fingerprint,
                preparation_phase, preparation_lease_until_ns FROM operations
                WHERE operation_id = ?""",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise OperationNotFound("operation does not exist")
            existing_token = row["preparation_token"]
            existing_kind = row["preparation_kind"]
            existing_fingerprint = row["preparation_fingerprint"]
            phase = row["preparation_phase"]
            lease_until = row["preparation_lease_until_ns"]
            if existing_token is not None:
                if str(existing_kind) != kind or str(existing_fingerprint) != fingerprint:
                    raise StateTransitionError("preparation is bound to another request")
                if (
                    phase == "claimed"
                    and lease_until is not None
                    and int(lease_until) > self._clock_ns()
                ):
                    return PreparationClaim(operation, PreparationClaimState.IN_PROGRESS)
                if phase == "claimed" and not replay_safe:
                    return PreparationClaim(operation, PreparationClaimState.REPLAY_UNSAFE)
            token = str(uuid.uuid4())
            connection.execute(
                """UPDATE operations SET preparation_token = ?, preparation_kind = ?,
                preparation_fingerprint = ?, preparation_phase = ?, preparation_lease_until_ns = ?
                WHERE operation_id = ?""",
                (
                    token,
                    kind,
                    fingerprint,
                    "claimed",
                    self._clock_ns() + self._preparation_lease_ns,
                    operation_id,
                ),
            )
            return PreparationClaim(operation, PreparationClaimState.OWNED, token)

    def complete_preparation(
        self, operation_id: str, token: str, raw_signed_tx: bytes
    ) -> Operation:
        """Persist exact signed bytes only for the active preparation claimant."""

        if not isinstance(raw_signed_tx, bytes) or not raw_signed_tx:
            raise ValueError("raw signed transaction must be non-empty bytes")
        tx_hash = "0x" + keccak(raw_signed_tx).hex()
        with self._transaction() as connection:
            operation = self._load_operation(connection, operation_id)
            if (
                operation.state is not OperationState.RESERVED
                or connection.execute(
                    """SELECT 1 FROM operations WHERE operation_id = ? AND preparation_token = ?
                    AND preparation_phase = 'claimed'""",
                    (operation_id, token),
                ).fetchone()
                is None
            ):
                return operation
            occurred_at_ns = self._clock_ns()
            connection.execute(
                """UPDATE operations SET state = ?, raw_signed_tx = ?, tx_hash = ?,
                preparation_phase = ?, preparation_lease_until_ns = NULL WHERE operation_id = ?
                AND preparation_token = ? AND preparation_phase = 'claimed'""",
                (
                    OperationState.BROADCAST_PREPARED.value,
                    sqlite3.Binary(raw_signed_tx),
                    tx_hash,
                    "prepared",
                    operation_id,
                    token,
                ),
            )
            self._append_event(
                connection, operation_id, OperationState.BROADCAST_PREPARED, occurred_at_ns, None
            )
            return self._load_operation(connection, operation_id)

    def fail_preparation(self, operation_id: str, token: str) -> Operation:
        """Record a pre-broadcast failure only for the active preparation claimant."""

        with self._transaction() as connection:
            operation = self._load_operation(connection, operation_id)
            if (
                operation.state is not OperationState.RESERVED
                or connection.execute(
                    """SELECT 1 FROM operations WHERE operation_id = ? AND preparation_token = ?
                    AND preparation_phase = 'claimed'""",
                    (operation_id, token),
                ).fetchone()
                is None
            ):
                return operation
            occurred_at_ns = self._clock_ns()
            connection.execute(
                """UPDATE operations SET state = ?, preparation_phase = ?,
                preparation_lease_until_ns = NULL WHERE operation_id = ? AND preparation_token = ?
                AND preparation_phase = 'claimed'""",
                (OperationState.FAILED_PRE_BROADCAST.value, "failed", operation_id, token),
            )
            self._append_event(
                connection, operation_id, OperationState.FAILED_PRE_BROADCAST, occurred_at_ns, None
            )
            return self._load_operation(connection, operation_id)

    def retry_pre_broadcast(self, operation_id: str) -> Operation:
        """Reopen a signing-only failure when no transaction was ever persisted."""

        with self._transaction() as connection:
            operation = self._load_operation(connection, operation_id)
            if operation.state is not OperationState.FAILED_PRE_BROADCAST:
                return operation
            if operation.raw_signed_tx is not None or operation.tx_hash is not None:
                raise StateTransitionError(
                    "broadcasted operation cannot retry pre-broadcast signing"
                )
            occurred_at_ns = self._clock_ns()
            connection.execute(
                "UPDATE operations SET state = ? WHERE operation_id = ?",
                (OperationState.RESERVED.value, operation_id),
            )
            self._append_event(
                connection, operation_id, OperationState.RESERVED, occurred_at_ns, None
            )
            return self._load_operation(connection, operation_id)

    def get_operation(self, operation_id: str) -> Operation:
        """Return the full immutable operation record and its event history."""

        connection = self._connection()
        try:
            return self._load_operation(connection, operation_id)
        finally:
            connection.close()

    def get_operation_by_idempotency_key(self, idempotency_key: str) -> Operation:
        """Resolve the immutable operation bound to a caller idempotency key."""

        connection = self._connection()
        try:
            row = connection.execute(
                "SELECT operation_id FROM operations WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if row is None:
                raise OperationNotFound("operation does not exist")
            return self._load_operation(connection, str(row["operation_id"]))
        finally:
            connection.close()

    def get_status(self, operation_id: str) -> OperationStatus:
        """Return current state, transaction hash, and append-only event history."""

        operation = self.get_operation(operation_id)
        return OperationStatus(
            operation.operation_id, operation.state, operation.tx_hash, operation.events
        )

    def _prepare_private_path(self) -> None:
        self._create_or_validate_private_directory(self._path.parent)
        while True:
            try:
                status = os.lstat(self._path)
            except FileNotFoundError:
                try:
                    descriptor = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                except FileExistsError:
                    continue
                else:
                    os.close(descriptor)
                    return
            self._validate_private_file(status)
            return

    @staticmethod
    def _create_or_validate_private_directory(directory: Path) -> None:
        missing: list[Path] = []
        current = directory
        while True:
            try:
                status = os.lstat(current)
            except FileNotFoundError:
                missing.append(current)
                current = current.parent
                continue
            SQLiteOperationStore._validate_private_directory(status)
            break
        for path in reversed(missing):
            with suppress(FileExistsError):
                path.mkdir(mode=0o700)
            SQLiteOperationStore._validate_private_directory(os.lstat(path))

    @staticmethod
    def _validate_private_directory(status: os.stat_result) -> None:
        if S_ISLNK(status.st_mode):
            raise PrivateStoragePathError("private storage directory must not be a symlink")
        if not S_ISDIR(status.st_mode):
            raise PrivateStoragePathError("private storage root must be a directory")
        if status.st_uid != os.getuid() or S_IMODE(status.st_mode) != 0o700:
            raise PrivateStoragePathError("private storage directory must be owned and mode 0700")

    @staticmethod
    def _validate_private_file(status: os.stat_result) -> None:
        if S_ISLNK(status.st_mode):
            raise PrivateStoragePathError("operation database must not be a symlink")
        if not S_ISREG(status.st_mode):
            raise PrivateStoragePathError("operation database must be a regular file")
        if status.st_uid != os.getuid() or S_IMODE(status.st_mode) != 0o600:
            raise PrivateStoragePathError("operation database must be owned and mode 0600")

    def _initialize(self) -> None:
        deadline = time.monotonic() + 30.0
        delay = 0.01
        while True:
            connection = self._connection()
            try:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = FULL")
                connection.execute("PRAGMA foreign_keys = ON")
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS operations (
                        operation_id TEXT PRIMARY KEY,
                        idempotency_key TEXT NOT NULL UNIQUE,
                        approval_id TEXT NOT NULL,
                        approval_json TEXT,
                        policy_id TEXT,
                        policy_version INTEGER,
                        policy_digest TEXT,
                        route_manifest_digest TEXT,
                        plan_id TEXT NOT NULL,
                        plan_json TEXT NOT NULL,
                        signer TEXT NOT NULL,
                        source_chain_id INTEGER NOT NULL,
                        nonce INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        created_at_ns INTEGER NOT NULL,
                        raw_signed_tx BLOB,
                        tx_hash TEXT,
                        preparation_token TEXT,
                        preparation_kind TEXT,
                        preparation_fingerprint TEXT,
                        preparation_phase TEXT,
                        preparation_lease_until_ns INTEGER,
                        source_finality_evidence TEXT,
                        destination_fulfillment_evidence TEXT,
                        UNIQUE(signer, source_chain_id, nonce),
                        UNIQUE(approval_id)
                    );
                    CREATE TABLE IF NOT EXISTS operation_events (
                        operation_id TEXT NOT NULL REFERENCES operations(operation_id),
                        sequence INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        occurred_at_ns INTEGER NOT NULL,
                        cancellation_proof TEXT,
                        PRIMARY KEY(operation_id, sequence)
                    );
                    """
                )
                self._add_operation_columns(connection)
                connection.execute("PRAGMA user_version = 2")
                connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS operations_approval_id_unique "
                    "ON operations(approval_id)"
                )
                return
            except sqlite3.OperationalError as error:
                if not _is_busy(error) or time.monotonic() >= deadline:
                    raise StoreError("could not initialize operation database") from error
                time.sleep(delay)
                delay = min(delay * 2, 0.2)
            finally:
                connection.close()

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, isolation_level=None, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _transaction(self) -> _Transaction:
        return _Transaction(self._connection())

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        operation_id: str,
        state: OperationState,
        occurred_at_ns: int,
        cancellation_proof: str | None,
    ) -> None:
        next_sequence = int(
            connection.execute(
                """SELECT COALESCE(MAX(sequence), 0) + 1
                FROM operation_events WHERE operation_id = ?""",
                (operation_id,),
            ).fetchone()[0]
        )
        connection.execute(
            """INSERT INTO operation_events
            (operation_id, sequence, state, occurred_at_ns, cancellation_proof)
            VALUES (?, ?, ?, ?, ?)""",
            (operation_id, next_sequence, state.value, occurred_at_ns, cancellation_proof),
        )

    @staticmethod
    def _require_transition(
        current: OperationState, requested: OperationState, cancellation_proof: str | None
    ) -> None:
        if requested not in _TRANSITIONS[current]:
            raise StateTransitionError("operation state transition is not permitted")
        if requested is OperationState.CANCELLED_CONFIRMED:
            raise StateTransitionError("cancellation is unsupported in 0.1")

    @staticmethod
    def _validate_source_evidence(
        operation: Operation,
        evidence: Mapping[str, object],
        *,
        receipt_status: int,
    ) -> None:
        _validate_evidence(evidence, "source finality")
        if evidence.get("receipt_status") != receipt_status:
            raise StateTransitionError("source finality evidence receipt status is invalid")
        if evidence["chain_id"] != operation.source_chain_id:
            raise StateTransitionError("source finality evidence chain does not match operation")
        if evidence["plan_id"] != operation.plan.plan_id:
            raise StateTransitionError("source finality evidence plan does not match operation")
        if evidence["transaction_hash"] != operation.tx_hash:
            raise StateTransitionError(
                "source finality evidence transaction does not match operation"
            )

    @staticmethod
    def _validate_source_failure_evidence(
        operation: Operation, evidence: Mapping[str, object]
    ) -> None:
        SQLiteOperationStore._validate_source_evidence(
            operation,
            evidence,
            receipt_status=0,
        )

    @staticmethod
    def _validate_destination_evidence(
        operation: Operation, evidence: Mapping[str, object]
    ) -> None:
        _validate_evidence(evidence, "destination fulfillment", require_log_identity=True)
        if evidence.get("receipt_status") != 1:
            raise StateTransitionError(
                "destination fulfillment evidence receipt status is invalid"
            )
        body = operation.plan.body()
        intent = body.get("intent")
        semantics = body.get("decoded_semantics")
        if not isinstance(intent, dict) or not isinstance(semantics, dict):
            raise StoreError("operation plan is missing destination evidence bindings")
        destination_chain_id = intent.get("destination_chain_id")
        order_id = semantics.get("order_id")
        if evidence["chain_id"] != destination_chain_id:
            raise StateTransitionError("destination evidence chain does not match operation")
        if evidence["order_id"] != order_id:
            raise StateTransitionError("destination evidence order does not match operation")
        if evidence["plan_id"] != operation.plan.plan_id:
            raise StateTransitionError("destination evidence plan does not match operation")
        execution = ExecutionPlan.from_plan(operation.plan, allow_expired=True)
        expected: dict[str, object] = {
            "log_address": execution.destination_dln_proxy.lower(),
            "log_topic": execution.destination_fulfillment_topic,
            "signer": execution.signer,
            "source_chain_id": execution.source_chain_id,
            "source_token": execution.source_order_token,
            "source_amount_wei": execution.source_order_amount_wei,
            "destination_chain_id": execution.destination_chain_id,
            "receiver": execution.recipient,
            "destination_token": execution.destination_token,
            "destination_amount_wei": execution.destination_amount_wei,
            "allowed_taker": execution.allowed_taker,
            "external_call": False,
        }
        for field, expected_value in expected.items():
            if evidence.get(field) != expected_value:
                raise StateTransitionError(
                    f"destination evidence {field} does not match operation"
                )

    @staticmethod
    def _add_operation_columns(connection: sqlite3.Connection) -> None:
        columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(operations)")}
        required = {
            "approval_json": "TEXT",
            "policy_id": "TEXT",
            "policy_version": "INTEGER",
            "policy_digest": "TEXT",
            "route_manifest_digest": "TEXT",
            "source_finality_evidence": "TEXT",
            "destination_fulfillment_evidence": "TEXT",
            "preparation_token": "TEXT",
            "preparation_kind": "TEXT",
            "preparation_fingerprint": "TEXT",
            "preparation_phase": "TEXT",
            "preparation_lease_until_ns": "INTEGER",
        }
        for name, column_type in required.items():
            if name not in columns:
                connection.execute(f"ALTER TABLE operations ADD COLUMN {name} {column_type}")

    @staticmethod
    def _load_operation(connection: sqlite3.Connection, operation_id: str) -> Operation:
        row = connection.execute(
            "SELECT * FROM operations WHERE operation_id = ?", (operation_id,)
        ).fetchone()
        if row is None:
            raise OperationNotFound("operation does not exist")
        try:
            plan_document = json.loads(str(row["plan_json"]))
        except json.JSONDecodeError as exc:
            raise StoreError("persisted plan is invalid") from exc
        if not isinstance(plan_document, dict):
            raise StoreError("persisted plan is invalid")
        plan = Plan.parse(plan_document)
        approval: Approval | None = None
        if row["approval_json"] is not None:
            try:
                approval_document = json.loads(str(row["approval_json"]))
            except json.JSONDecodeError as exc:
                raise StoreError("persisted approval is invalid") from exc
            if not isinstance(approval_document, dict):
                raise StoreError("persisted approval is invalid")
            approval = Approval.parse(approval_document)
        policy_values = (
            str(row["policy_id"]) if row["policy_id"] is not None else None,
            int(row["policy_version"]) if row["policy_version"] is not None else None,
            str(row["policy_digest"]) if row["policy_digest"] is not None else None,
            (
                str(row["route_manifest_digest"])
                if row["route_manifest_digest"] is not None
                else None
            ),
        )
        if plan.schema_version == 2:
            if approval is None or any(value is None for value in policy_values):
                raise StoreError("bound operation is missing approval or policy evidence")
            if (
                approval.approval_id != str(row["approval_id"])
                or approval.plan_id != plan.plan_id
                or policy_values != _plan_policy_binding(plan)
            ):
                raise StoreError("operation approval or policy binding is inconsistent")
        elif approval is not None or any(value is not None for value in policy_values):
            raise StoreError("legacy operation contains unexpected policy evidence")
        events = tuple(
            OperationEvent(
                sequence=int(event["sequence"]),
                state=OperationState(str(event["state"])),
                occurred_at_ns=int(event["occurred_at_ns"]),
                cancellation_proof=(
                    str(event["cancellation_proof"])
                    if event["cancellation_proof"] is not None
                    else None
                ),
            )
            for event in connection.execute(
                """SELECT sequence, state, occurred_at_ns, cancellation_proof FROM operation_events
                WHERE operation_id = ? ORDER BY sequence""",
                (operation_id,),
            )
        )
        operation = Operation(
            operation_id=str(row["operation_id"]),
            idempotency_key=str(row["idempotency_key"]),
            approval_id=str(row["approval_id"]),
            plan=plan,
            signer=str(row["signer"]),
            source_chain_id=int(row["source_chain_id"]),
            nonce=int(row["nonce"]),
            state=OperationState(str(row["state"])),
            created_at_ns=int(row["created_at_ns"]),
            raw_signed_tx=bytes(row["raw_signed_tx"]) if row["raw_signed_tx"] is not None else None,
            tx_hash=str(row["tx_hash"]) if row["tx_hash"] is not None else None,
            source_finality_evidence=_load_evidence(row["source_finality_evidence"]),
            destination_fulfillment_evidence=_load_evidence(
                row["destination_fulfillment_evidence"]
            ),
            events=events,
            approval=approval,
            policy_id=policy_values[0],
            policy_version=policy_values[1],
            policy_digest=policy_values[2],
            route_manifest_digest=policy_values[3],
        )
        SQLiteOperationStore._validate_loaded_operation(operation)
        return operation

    @staticmethod
    def _validate_loaded_operation(operation: Operation) -> None:
        if not operation.events:
            raise StoreError("operation event history is missing")
        if tuple(event.sequence for event in operation.events) != tuple(
            range(1, len(operation.events) + 1)
        ):
            raise StoreError("operation event history is not contiguous")
        if operation.events[-1].state is not operation.state:
            raise StoreError("operation state does not match final event")
        if (operation.raw_signed_tx is None) != (operation.tx_hash is None):
            raise StoreError("operation signed transaction identity is incomplete")
        signed_states = {
            OperationState.BROADCAST_PREPARED,
            OperationState.BROADCAST_ATTEMPTED,
            OperationState.SUBMISSION_UNKNOWN,
            OperationState.SOURCE_PENDING,
            OperationState.NEEDS_RECONCILIATION,
            OperationState.SOURCE_FAILED,
            OperationState.SOURCE_FINAL,
            OperationState.ORDER_PENDING,
            OperationState.DESTINATION_PENDING,
            OperationState.VERIFIED,
        }
        if operation.state in signed_states and operation.raw_signed_tx is None:
            raise StoreError("signed operation is missing exact transaction bytes")
        if operation.state in {OperationState.RESERVED, OperationState.FAILED_PRE_BROADCAST} and (
            operation.raw_signed_tx is not None
        ):
            raise StoreError("unsigned operation unexpectedly contains transaction bytes")
        if operation.source_finality_evidence is not None:
            status = operation.source_finality_evidence.get("receipt_status")
            SQLiteOperationStore._validate_source_evidence(
                operation,
                operation.source_finality_evidence,
                receipt_status=cast(int, status),
            )
        proof_required = {
            OperationState.SOURCE_FAILED,
            OperationState.SOURCE_FINAL,
            OperationState.ORDER_PENDING,
            OperationState.DESTINATION_PENDING,
            OperationState.VERIFIED,
        }
        if (
            operation.state in proof_required
            and operation.source_finality_evidence is None
        ):
            raise StoreError("operation state is missing source proof")
        if operation.state is OperationState.SOURCE_FAILED:
            if operation.source_finality_evidence is None or (
                operation.source_finality_evidence.get("receipt_status") != 0
            ):
                raise StoreError("source failure state has no failure proof")
        elif operation.state in proof_required and (
            operation.source_finality_evidence is None
            or operation.source_finality_evidence.get("receipt_status") != 1
        ):
            raise StoreError("source-complete state has no success proof")
        if operation.destination_fulfillment_evidence is not None:
            SQLiteOperationStore._validate_destination_evidence(
                operation,
                operation.destination_fulfillment_evidence,
            )
        if (
            operation.state is OperationState.VERIFIED
            and operation.destination_fulfillment_evidence is None
        ):
            raise StoreError("verified state is missing destination proof")
        if (
            operation.state is not OperationState.VERIFIED
            and operation.destination_fulfillment_evidence is not None
        ):
            raise StoreError("non-verified state contains destination proof")


class _Transaction:
    """A writer transaction that acquires SQLite's writer lock before checks."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def __enter__(self) -> sqlite3.Connection:
        self._connection.execute("BEGIN IMMEDIATE")
        return self._connection

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        if exception_type is None:
            self._connection.commit()
        else:
            self._connection.rollback()
        self._connection.close()


def _is_busy(error: sqlite3.OperationalError) -> bool:
    return "locked" in str(error).lower() or "busy" in str(error).lower()
