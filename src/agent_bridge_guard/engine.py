"""Crash-safe signing, submission, and reconciliation for one approved plan."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import NoReturn, cast

from .approval import Approval
from .authorization import AuthorizationValidator, ValidatedAuthorization
from .execution_plan import ExecutionPlan
from .models import JSONObject, Plan
from .providers.debridge import (
    RESERVE_ERC20_DLN_NATIVE_OUT,
    preflight_reserve_erc20_source_transaction,
)
from .providers.debridge import (
    Rpc as ProviderRpc,
)
from .rpc import (
    NeedsReconciliationError,
    RpcClient,
    RpcError,
    RpcPool,
    TransactionFailedError,
    wait_for_final_receipt,
)
from .signers.base import Signer
from .signers.detached import DetachedSigner
from .store import (
    IdempotencyConflict,
    Operation,
    OperationNotFound,
    OperationState,
    PreparationClaim,
    PreparationClaimState,
    SQLiteOperationStore,
    StateTransitionError,
)
from .verification import (
    VerificationError,
    VerifiedSourceFailure,
    verify_destination_receipt,
    verify_source_receipt,
)

IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
AfterBroadcast = Callable[[str], None]


class EngineError(RuntimeError):
    """Base failure for guarded execution."""


class PreBroadcastFailure(EngineError):
    """No broadcast side effect occurred."""

    def __init__(self, operation_id: str, message: str = "pre-broadcast signature failed") -> None:
        super().__init__(message)
        self.operation_id = operation_id


class SubmissionUnknown(EngineError):
    """A submission attempt happened but its network outcome is not yet proven."""

    def __init__(self, operation_id: str) -> None:
        super().__init__("submission outcome is unknown; resume exact persisted transaction")
        self.operation_id = operation_id


class NeedsReconciliation(EngineError):
    """Independent evidence disagreed or a nonce advanced without the expected hash."""

    def __init__(self, operation_id: str, message: str = "operation needs reconciliation") -> None:
        super().__init__(message)
        self.operation_id = operation_id


class DestinationVerificationError(EngineError):
    """A destination receipt did not prove the exact approved fulfillment."""


class ExecutionEngine:
    """Own the durable boundary around signing and source-chain broadcast."""

    def __init__(
        self,
        store: SQLiteOperationStore,
        source_rpc: RpcPool,
        *,
        policy_path: str | Path,
        source_confirmations: int = 1,
    ) -> None:
        if source_confirmations <= 0:
            raise ValueError("source confirmations must be positive")
        self._require_rpc_pool(source_rpc, label="source")
        self.store = store
        self._source_rpc = source_rpc
        self._authorizer = AuthorizationValidator(policy_path)
        self._source_confirmations = source_confirmations

    def reserve(
        self,
        plan: Plan,
        approval: Approval,
        *,
        idempotency_key: str,
        at: datetime | None = None,
    ) -> Operation:
        """Validate and atomically reserve an approval, idempotency key, and nonce."""

        if not IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            raise ValueError("idempotency key must be an opaque identifier")
        try:
            existing = self.store.get_operation_by_idempotency_key(idempotency_key)
        except OperationNotFound:
            pass
        else:
            if (
                existing.plan.plan_id != plan.plan_id
                or existing.approval_id != approval.approval_id
                or (
                    plan.schema_version == 2
                    and (
                        existing.approval is None
                        or existing.approval.to_dict() != approval.to_dict()
                    )
                )
            ):
                raise IdempotencyConflict("idempotency key is bound to another approval or plan")
            return existing

        execution = self._validated(plan, approval, at=at)
        if self._source_rpc.chain_id != execution.source_chain_id:
            raise NeedsReconciliation("unreserved", "source RPC chain does not match plan")
        return self.store.reserve_operation(
            plan,
            idempotency_key=idempotency_key,
            signer=execution.signer,
            source_chain_id=execution.source_chain_id,
            nonce=execution.transaction["nonce"],
            approval=approval,
        )

    def execute(
        self,
        plan: Plan,
        approval: Approval,
        *,
        idempotency_key: str,
        signer: Signer,
        at: datetime | None = None,
        after_broadcast: AfterBroadcast | None = None,
    ) -> Operation:
        """Sign at most once, persist exact bytes, and submit or resume safely."""

        operation = self.reserve(
            plan,
            approval,
            idempotency_key=idempotency_key,
            at=at,
        )
        if operation.state is OperationState.FAILED_PRE_BROADCAST:
            operation = self.store.retry_pre_broadcast(operation.operation_id)
        if operation.state is OperationState.RESERVED:
            execution = self._validated(plan, approval, at=at)
            claim = self._await_preparation_claim(
                operation.operation_id,
                kind="local-eip1559",
                fingerprint=f"{plan.plan_id}:{execution.signer.lower()}",
                replay_safe=getattr(signer, "preparation_replay_safe", False),
            )
            if claim.state is PreparationClaimState.PREPARED:
                operation = claim.operation
            else:
                if claim.token is None:
                    raise PreBroadcastFailure(operation.operation_id, "preparation claim was lost")
                try:
                    execution = self._validated(plan, approval, at=at)
                    if signer.address.lower() != execution.signer.lower():
                        raise ValueError("signer does not match approved plan")
                    self._preflight_source(execution)
                    supplied = signer.sign_transaction(execution.transaction)
                    verified = DetachedSigner(execution.signer).import_signed_transaction(
                        execution.transaction,
                        supplied.raw_transaction,
                    )
                    if (
                        supplied.transaction_hash.lower() != verified.transaction_hash.lower()
                        or supplied.signer_address.lower() != verified.signer_address.lower()
                    ):
                        raise ValueError("signer result metadata mismatch")
                    operation = self.store.complete_preparation(
                        operation.operation_id, claim.token, verified.raw_transaction
                    )
                except Exception:
                    failed = self.store.fail_preparation(operation.operation_id, claim.token)
                    if failed.state is not OperationState.BROADCAST_PREPARED:
                        raise PreBroadcastFailure(operation.operation_id) from None
                    operation = failed
        return self.resume(
            operation.operation_id,
            approval=approval,
            at=at,
            after_broadcast=after_broadcast,
            allow_broadcast=True,
        )

    def prepare_external(
        self,
        plan: Plan,
        approval: Approval,
        raw_signed_transaction: bytes | str,
        *,
        idempotency_key: str,
        at: datetime | None = None,
    ) -> Operation:
        """Import an exact detached signature without broadcasting it."""

        operation = self.reserve(
            plan,
            approval,
            idempotency_key=idempotency_key,
            at=at,
        )
        if operation.state is OperationState.FAILED_PRE_BROADCAST:
            operation = self.store.retry_pre_broadcast(operation.operation_id)
        if operation.state is not OperationState.RESERVED:
            return operation
        execution = self._validated(plan, approval, at=at)
        try:
            signed = DetachedSigner(execution.signer).import_signed_transaction(
                execution.transaction,
                raw_signed_transaction,
            )
        except Exception:
            raise PreBroadcastFailure(operation.operation_id) from None
        claim = self._await_preparation_claim(
            operation.operation_id,
            kind="detached-eip1559",
            fingerprint=(
                f"{plan.plan_id}:{execution.signer.lower()}:{signed.transaction_hash.lower()}"
            ),
            replay_safe=True,
        )
        if claim.state is PreparationClaimState.PREPARED:
            return claim.operation
        if claim.token is None:
            raise PreBroadcastFailure(operation.operation_id, "preparation claim was lost")
        try:
            execution = self._validated(plan, approval, at=at)
            self._preflight_source(execution)
            return self.store.complete_preparation(
                operation.operation_id, claim.token, signed.raw_transaction
            )
        except Exception:
            failed = self.store.fail_preparation(operation.operation_id, claim.token)
            if failed.state is OperationState.BROADCAST_PREPARED:
                return failed
            raise PreBroadcastFailure(operation.operation_id) from None

    def resume(
        self,
        operation_id: str,
        *,
        approval: Approval | None = None,
        at: datetime | None = None,
        after_broadcast: AfterBroadcast | None = None,
        allow_broadcast: bool = False,
    ) -> Operation:
        """Reconcile prior evidence and only ever re-submit the exact persisted bytes."""

        operation = self.store.get_operation(operation_id)
        persisted_approval = operation.approval
        if operation.plan.schema_version == 2:
            if approval is not None and (
                persisted_approval is None
                or approval.to_dict() != persisted_approval.to_dict()
            ):
                raise PreBroadcastFailure(
                    operation_id,
                    "recovery cannot substitute the persisted approval",
                )
            effective_approval = persisted_approval
        else:
            effective_approval = approval
        if operation.state is OperationState.RESERVED:
            raise PreBroadcastFailure(operation_id, "operation is waiting for a signature")
        if operation.state is OperationState.BROADCAST_PREPARED:
            if not allow_broadcast:
                return operation
            if (
                effective_approval is None
                or effective_approval.approval_id != operation.approval_id
            ):
                raise PreBroadcastFailure(
                    operation_id,
                    "matching approval is required before first broadcast",
                )
            execution = self._validated(operation.plan, effective_approval, at=at)
            self._preflight_source(execution)
            return self._broadcast(operation, after_broadcast=after_broadcast)
        if operation.state in {
            OperationState.BROADCAST_ATTEMPTED,
            OperationState.SUBMISSION_UNKNOWN,
            OperationState.NEEDS_RECONCILIATION,
        }:
            return self._reconcile_submission(
                operation,
                approval=effective_approval,
                at=at,
                after_broadcast=after_broadcast,
                allow_broadcast=allow_broadcast,
            )
        return operation

    def refresh_source(
        self,
        operation_id: str,
        *,
        max_polls: int | None = None,
    ) -> Operation:
        """Prove source receipt finality with both configured RPC endpoints."""

        operation = self.store.get_operation(operation_id)
        if operation.state is not OperationState.SOURCE_PENDING:
            return operation
        if operation.tx_hash is None:
            return self._needs_reconciliation(operation, "source transaction hash is absent")
        try:
            receipt = self._wait_for_finality(
                self._source_rpc,
                operation.tx_hash,
                self._source_confirmations,
                max_polls=max_polls,
            )
        except TransactionFailedError as exc:
            try:
                proof = verify_source_receipt(
                    operation_id=operation.operation_id,
                    plan=operation.plan,
                    receipt=exc.receipt,
                    chain_id=operation.source_chain_id,
                    transaction_hash=operation.tx_hash,
                    confirmations=self._source_confirmations,
                    receipt_status=0,
                )
            except VerificationError:
                return self._needs_reconciliation(
                    operation, "source failure evidence is incomplete"
                )
            if not isinstance(proof, VerifiedSourceFailure):
                raise AssertionError(
                    "status=0 receipt must produce a failure proof"
                ) from None
            return self.store._commit_source_failure(proof)
        except (NeedsReconciliationError, RpcError):
            return self._needs_reconciliation(operation, "source finality evidence disagreed")
        try:
            proof = verify_source_receipt(
                operation_id=operation.operation_id,
                plan=operation.plan,
                receipt=receipt,
                chain_id=operation.source_chain_id,
                transaction_hash=operation.tx_hash,
                confirmations=self._source_confirmations,
                receipt_status=1,
            )
        except VerificationError:
            return self._needs_reconciliation(operation, "source finality evidence is incomplete")
        return self.store._commit_source_finality(proof)

    def verify_destination(
        self,
        operation_id: str,
        *,
        destination_transaction_hash: str,
        destination_rpc: RpcPool,
        confirmations: int,
        max_polls: int | None = None,
    ) -> Operation:
        """Finalize only when a canonical destination receipt contains the exact DLN event."""

        if confirmations <= 0:
            raise ValueError("destination confirmations must be positive")
        self._require_rpc_pool(destination_rpc, label="destination")
        operation = self.store.get_operation(operation_id)
        if operation.state is OperationState.ORDER_PENDING:
            operation = self.store.append_state_event(
                operation_id,
                OperationState.DESTINATION_PENDING,
            )
        if operation.state is not OperationState.DESTINATION_PENDING:
            return operation
        execution = ExecutionPlan.from_plan(operation.plan, allow_expired=True)
        if destination_rpc.chain_id != execution.destination_chain_id:
            raise DestinationVerificationError(
                "destination RPC chain does not match approved plan"
            )
        try:
            receipt = self._wait_for_finality(
                destination_rpc,
                destination_transaction_hash,
                confirmations,
                max_polls=max_polls,
            )
        except NeedsReconciliationError as exc:
            raise DestinationVerificationError("destination finality is not proven") from exc
        try:
            proof = verify_destination_receipt(
                operation_id=operation.operation_id,
                plan=operation.plan,
                receipt=receipt,
                transaction_hash=destination_transaction_hash,
                confirmations=confirmations,
            )
        except VerificationError as exc:
            raise DestinationVerificationError(str(exc)) from exc
        return self.store._commit_destination_fulfillment(proof)

    def _broadcast(
        self,
        operation: Operation,
        *,
        after_broadcast: AfterBroadcast | None,
    ) -> Operation:
        if operation.raw_signed_tx is None or operation.tx_hash is None:
            return self._needs_reconciliation(operation, "persisted signed transaction is absent")
        try:
            attempted = self.store.append_state_event(
                operation.operation_id,
                OperationState.BROADCAST_ATTEMPTED,
            )
        except StateTransitionError:
            return self.store.get_operation(operation.operation_id)
        return self._send_persisted(attempted, after_broadcast=after_broadcast)

    def _await_preparation_claim(
        self,
        operation_id: str,
        *,
        kind: str,
        fingerprint: str,
        replay_safe: bool,
    ) -> PreparationClaim:
        """Wait briefly for a concurrent claimant, or acquire a fenced lease."""

        for _ in range(300):
            claim = self.store.claim_preparation(
                operation_id,
                kind=kind,
                fingerprint=fingerprint,
                replay_safe=replay_safe,
            )
            if claim.state in {PreparationClaimState.OWNED, PreparationClaimState.PREPARED}:
                return claim
            if claim.state is PreparationClaimState.REPLAY_UNSAFE:
                raise PreBroadcastFailure(
                    operation_id, "preparation lease expired for a non-replay-safe signer"
                )
            if claim.state is not PreparationClaimState.IN_PROGRESS:
                raise PreBroadcastFailure(operation_id, "broadcast preparation is unavailable")
            time.sleep(0.01)
        raise PreBroadcastFailure(operation_id, "broadcast preparation is still in progress")

    def _reconcile_submission(
        self,
        operation: Operation,
        *,
        approval: Approval | None,
        at: datetime | None,
        after_broadcast: AfterBroadcast | None,
        allow_broadcast: bool,
    ) -> Operation:
        if operation.raw_signed_tx is None or operation.tx_hash is None:
            return self._needs_reconciliation(operation, "persisted signed transaction is absent")
        try:
            primary = self._source_rpc.primary.transaction_by_hash(operation.tx_hash)
            secondary = self._source_rpc.secondary.transaction_by_hash(operation.tx_hash)
        except RpcError:
            return self._needs_reconciliation(operation, "source transaction lookup failed")
        for observed in (primary, secondary):
            if observed is None:
                continue
            observed_hash = observed.get("hash")
            if not isinstance(observed_hash, str) or observed_hash.lower() != operation.tx_hash:
                return self._needs_reconciliation(operation, "observed transaction hash mismatch")
        if primary is not None or secondary is not None:
            return self.store.append_state_event(
                operation.operation_id,
                OperationState.SOURCE_PENDING,
            )

        try:
            primary_nonce = self._source_rpc.primary.transaction_count(
                operation.signer, "pending"
            )
            secondary_nonce = self._source_rpc.secondary.transaction_count(
                operation.signer, "pending"
            )
        except RpcError:
            return self._needs_reconciliation(operation, "pending nonce lookup failed")
        if primary_nonce != secondary_nonce or primary_nonce > operation.nonce:
            return self._needs_reconciliation(
                operation,
                "pending nonce advanced without expected transaction",
            )
        if not allow_broadcast:
            return operation
        if approval is None or approval.approval_id != operation.approval_id:
            raise PreBroadcastFailure(
                operation.operation_id,
                "matching approval is required before recovery broadcast",
            )
        execution = self._validated(operation.plan, approval, at=at)
        self._preflight_source(execution)
        return self._send_persisted(operation, after_broadcast=after_broadcast)

    def _send_persisted(
        self,
        operation: Operation,
        *,
        after_broadcast: AfterBroadcast | None,
    ) -> Operation:
        if operation.raw_signed_tx is None or operation.tx_hash is None:
            return self._needs_reconciliation(operation, "persisted signed transaction is absent")
        try:
            transaction_hash = self._source_rpc.primary.send_raw_transaction(
                "0x" + operation.raw_signed_tx.hex()
            )
        except RpcError:
            current = self.store.get_operation(operation.operation_id)
            if current.state is OperationState.BROADCAST_ATTEMPTED:
                self.store.append_state_event(
                    operation.operation_id,
                    OperationState.SUBMISSION_UNKNOWN,
                )
            raise SubmissionUnknown(operation.operation_id) from None
        if transaction_hash.lower() != operation.tx_hash:
            return self._needs_reconciliation(
                operation,
                "RPC returned a different transaction hash",
            )
        if after_broadcast is not None:
            after_broadcast(transaction_hash)
        return self.store.append_state_event(
            operation.operation_id,
            OperationState.SOURCE_PENDING,
        )

    def _needs_reconciliation(self, operation: Operation, message: str) -> NoReturn:
        if operation.state is not OperationState.NEEDS_RECONCILIATION:
            self.store.append_state_event(
                operation.operation_id,
                OperationState.NEEDS_RECONCILIATION,
            )
        raise NeedsReconciliation(operation.operation_id, message)

    def _preflight_source(self, execution: ExecutionPlan) -> None:
        transaction = execution.transaction
        if (
            execution.source_dln_implementation_codehash is None
            or execution.expected_global_transfer_fee_bps is None
        ):
            raise ValueError("direct route preflight policy is incomplete")
        intent = execution.plan.body().get("intent")
        if not isinstance(intent, dict):
            raise ValueError("direct route intent is missing")
        amount = intent.get("amount_wei")
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            raise ValueError("direct route source input amount is invalid")
        preflight_reserve_erc20_source_transaction(
            cast(ProviderRpc, self._source_rpc.primary.call),
            cast(ProviderRpc, self._source_rpc.secondary.call),
            signer=execution.signer,
            dln_proxy=transaction["to"],
            reserve_token=execution.source_order_token,
            amount_wei=amount,
            fixed_fee_wei=transaction["value"],
            data=transaction["data"],
            nonce=transaction["nonce"],
            maximum_gas=transaction["gas"],
            required_native_spend_wei=(
                transaction["value"] + transaction["gas"] * transaction["max_fee_per_gas"]
            ),
            expected_implementation_codehash=execution.source_dln_implementation_codehash,
            expected_global_transfer_fee_bps=execution.expected_global_transfer_fee_bps,
        )

    def _validated(
        self,
        plan: Plan,
        approval: Approval,
        *,
        at: datetime | None,
    ) -> ExecutionPlan:
        if plan.schema_version != 2:
            raise ValueError("legacy unbound plans cannot execute")
        if approval.schema_version != 3:
            raise ValueError("execution requires a reviewable approval")
        try:
            canonical = ExecutionPlan.from_plan(plan, allow_expired=True)
        except ValueError as exc:
            raise ValueError("plan cannot produce canonical execution") from exc
        try:
            validated = self._authorize(plan, approval, at=at)
        except ValueError as exc:
            raise ValueError("plan or approval validation failed") from exc
        execution = validated.execution
        if (
            execution != canonical
            or execution.plan.schema_version != 2
            or execution.route_kind != RESERVE_ERC20_DLN_NATIVE_OUT
        ):
            raise ValueError("execution must use the bound direct reserve route")
        return execution

    def _authorize(
        self,
        plan: Plan,
        approval: Approval,
        *,
        at: datetime | None,
    ) -> ValidatedAuthorization:
        return self._authorizer.validate(plan, approval, at=at)

    def _wait_for_finality(
        self,
        rpc: RpcPool,
        transaction_hash: str,
        confirmations: int,
        *,
        max_polls: int | None,
    ) -> JSONObject:
        return wait_for_final_receipt(
            rpc,
            transaction_hash,
            confirmations,
            max_polls=max_polls,
        )

    @staticmethod
    def _require_rpc_pool(rpc: object, *, label: str) -> None:
        if (
            type(rpc) is not RpcPool
            or type(rpc.primary) is not RpcClient
            or type(rpc.secondary) is not RpcClient
            or rpc.primary.transport is not None
            or rpc.secondary.transport is not None
            or rpc.primary.endpoint == rpc.secondary.endpoint
        ):
            raise TypeError(f"{label} RPC must be a concrete two-endpoint RpcPool")
