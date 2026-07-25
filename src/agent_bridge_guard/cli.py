"""JSON-first command line interface for guarded bridge operations."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from . import __version__
from .approval import Approval, ApprovalError, ApprovalSigningRequest
from .artifacts import (
    ArtifactError,
    PrivateArtifactStore,
    read_json_object,
    read_private_bytes,
)
from .authorization import (
    AuthorizationError,
    AuthorizationValidator,
    bind_plan,
    policy_binding,
    validate_bound_plan,
)
from .config import ChainConfig, ConfigError, Settings, load_config
from .engine import (
    DestinationVerificationError,
    EngineError,
    ExecutionEngine,
    NeedsReconciliation,
    SubmissionUnknown,
)
from .execution_plan import ExecutionPlan, ExecutionPlanError
from .http import HttpError, get_json
from .models import JSONObject, Plan, PlanIntegrityError
from .plan_request import PlanRequest, PlanRequestError
from .policy import PolicyError, ProtectedPolicyPathError, TrustedPolicy
from .providers.debridge import (
    RESERVE_ERC20_DLN_NATIVE_OUT,
    DeBridgeProvider,
    QuoteRequest,
    preflight_reserve_erc20_source_transaction,
)
from .providers.debridge import (
    Rpc as ProviderRpc,
)
from .route_manifest import RouteManifest, RouteManifestError
from .rpc import RpcClient, RpcError, RpcPool
from .signers.detached import DetachedSigner
from .signers.local_keystore import LocalKeystoreSigner
from .store import Operation, SQLiteOperationStore, StoreError
from .tracking import DeBridgeTrackingClient, TrackingError, TrackingPending

TX_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
Command = Callable[[argparse.Namespace], JSONObject]
SAFE_ERRORS = (
    ApprovalError,
    AuthorizationError,
    ArtifactError,
    ConfigError,
    DestinationVerificationError,
    EngineError,
    ExecutionPlanError,
    HttpError,
    PlanIntegrityError,
    PlanRequestError,
    PolicyError,
    ProtectedPolicyPathError,
    RouteManifestError,
    RpcError,
    StoreError,
    TrackingError,
    ValueError,
)


def _emit(value: object) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
    sys.stdout.write("\n")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _load_plan(path: str) -> Plan:
    return Plan.parse(read_json_object(Path(path)))


def _load_approval(path: str) -> Approval:
    return Approval.parse(read_json_object(Path(path)))


def _load_approval_request(path: str) -> ApprovalSigningRequest:
    return ApprovalSigningRequest.parse(read_json_object(Path(path)))


def _rpc_pool(chain: ChainConfig) -> RpcPool:
    return RpcPool(
        RpcClient(chain.primary_rpc.reveal()),
        RpcClient(chain.secondary_rpc.reveal()),
        chain.chain_id,
    )


def _chain_by_id(settings: Settings, chain_id: int) -> ChainConfig:
    matches = [chain for chain in settings.chains.values() if chain.chain_id == chain_id]
    if len(matches) != 1:
        raise ConfigError("configuration must contain exactly one matching chain")
    return matches[0]


def _operation_result(operation: Operation) -> JSONObject:
    value: JSONObject = {
        "operation_id": operation.operation_id,
        "plan_id": operation.plan.plan_id,
        "approval_id": operation.approval_id,
        "state": operation.state.value,
        "tx_hash": operation.tx_hash,
        "events": [
            {
                "sequence": event.sequence,
                "state": event.state.value,
                "occurred_at_ns": event.occurred_at_ns,
            }
            for event in operation.events
        ],
    }
    if operation.source_finality_evidence is not None:
        value["source_finality_evidence"] = cast(JSONObject, operation.source_finality_evidence)
    if operation.destination_fulfillment_evidence is not None:
        value["destination_fulfillment_evidence"] = cast(
            JSONObject, operation.destination_fulfillment_evidence
        )
    return value


def _engine_for_operation(
    settings: Settings,
    store: SQLiteOperationStore,
    operation: Operation,
    policy_path: str,
) -> ExecutionEngine:
    chain = _chain_by_id(settings, operation.source_chain_id)
    policy = TrustedPolicy.load(policy_path)
    execution = ExecutionPlan.from_plan(operation.plan, allow_expired=True)
    return ExecutionEngine(
        store,
        _rpc_pool(chain),
        policy_path=policy_path,
        source_confirmations=policy.confirmations_for(execution.source_chain_id),
    )


def _private_signed_bytes(path_text: str) -> bytes:
    path = Path(path_text)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("signed transaction file must be absolute and not a symlink")
    try:
        text = read_private_bytes(path, max_bytes=1_000_000).decode("utf-8").strip()
    except (ArtifactError, UnicodeDecodeError) as exc:
        raise ValueError("signed transaction file cannot be read") from exc
    if text.startswith("{"):
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("signed transaction file is invalid JSON") from exc
        if not isinstance(document, dict) or set(document) != {"raw_signed_transaction"}:
            raise ValueError("signed transaction JSON schema is invalid")
        text = cast(str, document["raw_signed_transaction"])
    if not isinstance(text, str) or not text.startswith("0x"):
        raise ValueError("signed transaction must be 0x-prefixed hex")
    try:
        raw = bytes.fromhex(text[2:])
    except ValueError as exc:
        raise ValueError("signed transaction must be complete hex bytes") from exc
    if not raw:
        raise ValueError("signed transaction must not be empty")
    return raw


def _private_signature(path_text: str) -> str:
    try:
        text = read_private_bytes(Path(path_text), max_bytes=2_048).decode("utf-8").strip()
    except (ArtifactError, UnicodeDecodeError) as exc:
        raise ValueError("approval signature file cannot be read") from exc
    if text.startswith("{"):
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("approval signature file is invalid JSON") from exc
        if not isinstance(document, dict) or set(document) != {"signature"}:
            raise ValueError("approval signature JSON schema is invalid")
        signature = document["signature"]
        if not isinstance(signature, str):
            raise ValueError("approval signature must be a string")
        text = signature
    if not re.fullmatch(r"0x[0-9a-fA-F]{130}", text):
        raise ValueError("approval signature must be a 65-byte 0x-prefixed hex value")
    return text


def _cmd_plan(args: argparse.Namespace) -> JSONObject:
    settings = load_config(args.config)
    trusted_policy = TrustedPolicy.load(args.policy)
    request = PlanRequest.load(args.request)
    route = RouteManifest.load(args.route)
    policy_binding(trusted_policy, route)
    if (
        request.route_id != route.route_id
        or request.source_chain_alias != route.source_chain_alias
        or request.destination_chain_alias != route.destination_chain_alias
    ):
        raise ValueError("plan request route identity does not match route manifest")
    try:
        source_chain = settings.chains[route.source_chain_alias]
        destination_chain = settings.chains[route.destination_chain_alias]
    except KeyError as exc:
        raise ConfigError("route chain alias is missing from configuration") from exc
    if (
        source_chain.chain_id != route.source_chain_id
        or destination_chain.chain_id != route.destination_chain_id
    ):
        raise ConfigError("route chain IDs do not match configuration")
    pool = _rpc_pool(source_chain)
    primary_nonce = pool.primary.transaction_count(request.signer, "pending")
    secondary_nonce = pool.secondary.transaction_count(request.signer, "pending")
    if primary_nonce != secondary_nonce:
        raise NeedsReconciliation("unreserved", "RPC pending nonce disagreement")
    provider_request = QuoteRequest(
        source_chain_id=route.source_chain_id,
        destination_chain_id=route.destination_chain_id,
        amount_wei=request.amount_wei,
        minimum_output_wei=request.minimum_output_wei,
        signer=request.signer,
        recipient=request.recipient,
        nonce=primary_nonce,
        created_at=_now(),
        expires_at=request.expires_at,
    )
    provider_plan = DeBridgeProvider(get_json).quote(
        settings.debridge.create_tx_url.reveal(),
        provider_request,
        route.to_policy(),
    )
    plan = bind_plan(provider_plan, trusted_policy, route)
    execution = ExecutionPlan.from_plan(plan)
    if execution.route_kind != RESERVE_ERC20_DLN_NATIVE_OUT:
        raise AuthorizationError("legacy source-aggregator routes are quarantined")
    preflight_reserve_erc20_source_transaction(
        cast(ProviderRpc, pool.primary.call),
        cast(ProviderRpc, pool.secondary.call),
        signer=execution.signer,
        dln_proxy=execution.transaction["to"],
        reserve_token=execution.source_order_token,
        amount_wei=request.amount_wei,
        fixed_fee_wei=execution.transaction["value"],
        data=execution.transaction["data"],
        nonce=execution.transaction["nonce"],
        maximum_gas=execution.transaction["gas"],
        required_native_spend_wei=execution.transaction["value"]
        + execution.transaction["gas"] * execution.transaction["max_fee_per_gas"],
        expected_implementation_codehash=cast(
            str, execution.source_dln_implementation_codehash
        ),
        expected_global_transfer_fee_bps=cast(int, execution.expected_global_transfer_fee_bps),
    )
    path = PrivateArtifactStore(args.artifacts).write_json(args.name, plan.to_dict())
    return {
        "plan_id": plan.plan_id,
        "request_id": request.request_id,
        "route_id": route.route_id,
        "policy_id": trusted_policy.policy_id,
        "policy_version": trusted_policy.policy_version,
        "policy_digest": trusted_policy.digest,
        "route_manifest_digest": route.digest,
        "artifact": str(path),
    }


def _cmd_approval_request(args: argparse.Namespace) -> JSONObject:
    trusted_policy = TrustedPolicy.load(args.policy)
    plan = _load_plan(args.plan)
    execution, _ = validate_bound_plan(plan, trusted_policy)
    request = ApprovalSigningRequest.create_reviewable(
        plan=plan,
        authorization_id=args.authorization_id,
        actor=args.actor,
        approved_at=args.approved_at or _now(),
        expires_at=args.expires_at,
    )
    path = PrivateArtifactStore(args.artifacts).write_json(args.name, request.to_dict())
    return {
        "plan_id": plan.plan_id,
        "expected_subject_signer": execution.signer,
        "intent": cast(JSONObject, request.intent),
        "eip191_message_hex": request.eip191_message_hex,
        "artifact": str(path),
    }


def _cmd_approve(args: argparse.Namespace) -> JSONObject:
    trusted_policy = TrustedPolicy.load(args.policy)
    plan = _load_plan(args.plan)
    execution, _ = validate_bound_plan(plan, trusted_policy)
    request = _load_approval_request(args.request)
    request.verify_for(
        plan,
        expected_subject_signer=execution.signer,
        require_reviewable=True,
    )
    approval = request.to_approval(
        signature=_private_signature(args.signature_file),
    )
    approval.verify_for(
        plan,
        allowed_issuers=trusted_policy.approval_issuers,
        expected_subject_signer=execution.signer,
        require_reviewable=True,
    )
    path = PrivateArtifactStore(args.artifacts).write_json(args.name, approval.to_dict())
    return {
        "approval_id": approval.approval_id,
        "plan_id": plan.plan_id,
        "issuer": approval.issuer,
        "artifact": str(path),
    }


def _cmd_export_detached(args: argparse.Namespace) -> JSONObject:
    plan = _load_plan(args.plan)
    approval = _load_approval(args.approval)
    validated = AuthorizationValidator(args.policy).validate(plan, approval)
    execution = validated.execution
    request = json.loads(
        DetachedSigner(execution.signer).export_unsigned_transaction(execution.transaction)
    )
    path = PrivateArtifactStore(args.artifacts).write_json(
        args.name,
        {
            "schema_version": 1,
            "artifact_type": "detached_signing_request",
            "plan_id": plan.plan_id,
            "expected_signer": execution.signer,
            "unsigned_transaction": request,
        },
    )
    return {"plan_id": plan.plan_id, "artifact": str(path)}


def _cmd_execute(args: argparse.Namespace) -> JSONObject:
    if not args.go:
        raise ValueError("execute requires --go")
    settings = load_config(args.config)
    plan = _load_plan(args.plan)
    approval = _load_approval(args.approval)
    execution = ExecutionPlan.from_plan(plan)
    chain = _chain_by_id(settings, execution.source_chain_id)
    trusted_policy = TrustedPolicy.load(args.policy)
    validated_execution, _ = validate_bound_plan(plan, trusted_policy)
    store = SQLiteOperationStore(settings.database_path)
    guard = ExecutionEngine(
        store,
        _rpc_pool(chain),
        policy_path=args.policy,
        source_confirmations=trusted_policy.confirmations_for(
            validated_execution.source_chain_id
        ),
    )
    signer = LocalKeystoreSigner(Path(args.keystore), Path(args.password_file))
    return _operation_result(
        guard.execute(
            plan,
            approval,
            idempotency_key=args.idempotency_key,
            signer=signer,
        )
    )


def _cmd_prepare_external(args: argparse.Namespace) -> JSONObject:
    settings = load_config(args.config)
    plan = _load_plan(args.plan)
    approval = _load_approval(args.approval)
    execution = ExecutionPlan.from_plan(plan)
    chain = _chain_by_id(settings, execution.source_chain_id)
    trusted_policy = TrustedPolicy.load(args.policy)
    validated_execution, _ = validate_bound_plan(plan, trusted_policy)
    store = SQLiteOperationStore(settings.database_path)
    guard = ExecutionEngine(
        store,
        _rpc_pool(chain),
        policy_path=args.policy,
        source_confirmations=trusted_policy.confirmations_for(
            validated_execution.source_chain_id
        ),
    )
    return _operation_result(
        guard.prepare_external(
            plan,
            approval,
            _private_signed_bytes(args.signed_file),
            idempotency_key=args.idempotency_key,
        )
    )


def _cmd_resume(args: argparse.Namespace) -> JSONObject:
    settings = load_config(args.config)
    store = SQLiteOperationStore(settings.database_path)
    operation = store.get_operation(args.operation)
    approval = _load_approval(args.approval) if args.approval else None
    guard = _engine_for_operation(settings, store, operation, args.policy)
    return _operation_result(
        guard.resume(
            operation.operation_id,
            approval=approval,
            allow_broadcast=args.go,
        )
    )


def _cmd_refresh_source(args: argparse.Namespace) -> JSONObject:
    settings = load_config(args.config)
    store = SQLiteOperationStore(settings.database_path)
    operation = store.get_operation(args.operation)
    guard = _engine_for_operation(settings, store, operation, args.policy)
    return _operation_result(guard.refresh_source(operation.operation_id, max_polls=args.max_polls))


def _cmd_verify_destination(args: argparse.Namespace) -> JSONObject:
    settings = load_config(args.config)
    store = SQLiteOperationStore(settings.database_path)
    operation = store.get_operation(args.operation)
    execution = ExecutionPlan.from_plan(operation.plan, allow_expired=True)
    destination_hash = args.destination_tx_hash
    if destination_hash is None:
        if operation.tx_hash is None:
            raise TrackingError("source transaction hash is unavailable")
        discovery = DeBridgeTrackingClient(
            settings.debridge.tracking_url.reveal(),
            get_json,
        ).discover_fulfillment(operation.plan, operation.tx_hash)
        destination_hash = discovery.destination_transaction_hash
    if not TX_HASH.fullmatch(destination_hash):
        raise ValueError("destination transaction hash is invalid")
    source_guard = _engine_for_operation(settings, store, operation, args.policy)
    destination_chain = _chain_by_id(settings, execution.destination_chain_id)
    trusted_policy = TrustedPolicy.load(args.policy)
    return _operation_result(
        source_guard.verify_destination(
            operation.operation_id,
            destination_transaction_hash=destination_hash,
            destination_rpc=_rpc_pool(destination_chain),
            confirmations=trusted_policy.confirmations_for(
                execution.destination_chain_id
            ),
            max_polls=args.max_polls,
        )
    )


def _cmd_status(args: argparse.Namespace) -> JSONObject:
    settings = load_config(args.config)
    store = SQLiteOperationStore(settings.database_path)
    return _operation_result(store.get_operation(args.operation))


def _cmd_receipt(args: argparse.Namespace) -> JSONObject:
    settings = load_config(args.config)
    operation = SQLiteOperationStore(settings.database_path).get_operation(args.operation)
    execution = ExecutionPlan.from_plan(operation.plan, allow_expired=True)
    value = _operation_result(operation)
    value["order_id"] = execution.order_id
    path = PrivateArtifactStore(args.artifacts).write_public_receipt(args.name, value)
    return {"operation_id": operation.operation_id, "artifact": str(path)}


def _add_config_operation(
    parser: argparse.ArgumentParser,
    *,
    require_policy: bool = False,
) -> None:
    parser.add_argument("--config", required=True)
    parser.add_argument("--operation", required=True)
    if require_policy:
        parser.add_argument("--policy", required=True)


def _cmd_policy_check(args: argparse.Namespace) -> JSONObject:
    trusted_policy = TrustedPolicy.load(args.policy)
    route = RouteManifest.load(args.route)
    policy_binding(trusted_policy, route)
    return {
        "policy_id": trusted_policy.policy_id,
        "policy_version": trusted_policy.policy_version,
        "policy_digest": trusted_policy.digest,
        "route_id": route.route_id,
        "route_manifest_digest": route.digest,
        "source_confirmations": trusted_policy.confirmations_for(
            route.source_chain_id
        ),
        "destination_confirmations": trusted_policy.confirmations_for(
            route.destination_chain_id
        ),
    }


def _cmd_route_digest(args: argparse.Namespace) -> JSONObject:
    route = RouteManifest.load(args.route)
    return {
        "route_id": route.route_id,
        "route_kind": route.route_kind,
        "route_manifest_digest": route.digest,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-bridge-guard",
        description="Guarded cross-chain execution for autonomous agents",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    route_digest = commands.add_parser(
        "route-digest",
        help="print the canonical digest used by a trusted policy",
    )
    route_digest.add_argument("--route", required=True)
    route_digest.set_defaults(handler=_cmd_route_digest)

    policy_check = commands.add_parser(
        "policy-check",
        help="verify a protected policy and authorized route manifest",
    )
    policy_check.add_argument("--policy", required=True)
    policy_check.add_argument("--route", required=True)
    policy_check.set_defaults(handler=_cmd_policy_check)

    plan = commands.add_parser("plan", help="create an immutable provider-validated plan")
    plan.add_argument("--config", required=True)
    plan.add_argument("--policy", required=True)
    plan.add_argument("--request", required=True)
    plan.add_argument("--route", required=True)
    plan.add_argument("--artifacts", required=True)
    plan.add_argument("--name", default="plan.json")
    plan.set_defaults(handler=_cmd_plan)

    approval_request = commands.add_parser(
        "approval-request",
        help="export an exact EIP-191 operator approval request",
    )
    approval_request.add_argument("--policy", required=True)
    approval_request.add_argument("--plan", required=True)
    approval_request.add_argument("--artifacts", required=True)
    approval_request.add_argument("--name", default="approval-request.json")
    approval_request.add_argument("--authorization-id", required=True)
    approval_request.add_argument("--actor", required=True)
    approval_request.add_argument("--approved-at")
    approval_request.add_argument("--expires-at", required=True)
    approval_request.set_defaults(handler=_cmd_approval_request)

    approve = commands.add_parser("approve", help="import an off-box operator signature")
    approve.add_argument("--policy", required=True)
    approve.add_argument("--plan", required=True)
    approve.add_argument("--request", required=True)
    approve.add_argument("--signature-file", required=True)
    approve.add_argument("--artifacts", required=True)
    approve.add_argument("--name", default="approval.json")
    approve.set_defaults(handler=_cmd_approve)

    detached = commands.add_parser(
        "export-detached",
        help="export one exact offline signing request",
    )
    detached.add_argument("--plan", required=True)
    detached.add_argument("--policy", required=True)
    detached.add_argument("--approval", required=True)
    detached.add_argument("--artifacts", required=True)
    detached.add_argument("--name", default="signing-request.json")
    detached.set_defaults(handler=_cmd_export_detached)

    execute = commands.add_parser("execute", help="sign locally and submit an approved plan")
    execute.add_argument("--config", required=True)
    execute.add_argument("--policy", required=True)
    execute.add_argument("--plan", required=True)
    execute.add_argument("--approval", required=True)
    execute.add_argument("--keystore", required=True)
    execute.add_argument("--password-file", required=True)
    execute.add_argument("--idempotency-key", required=True)
    execute.add_argument("--go", action="store_true")
    execute.set_defaults(handler=_cmd_execute)

    external = commands.add_parser(
        "prepare-external",
        help="verify and persist a detached signed transaction",
    )
    external.add_argument("--config", required=True)
    external.add_argument("--policy", required=True)
    external.add_argument("--plan", required=True)
    external.add_argument("--approval", required=True)
    external.add_argument("--signed-file", required=True)
    external.add_argument("--idempotency-key", required=True)
    external.set_defaults(handler=_cmd_prepare_external)

    resume = commands.add_parser("resume", help="reconcile or submit exact persisted bytes")
    _add_config_operation(resume, require_policy=True)
    resume.add_argument("--approval")
    resume.add_argument("--go", action="store_true")
    resume.set_defaults(handler=_cmd_resume)

    refresh = commands.add_parser("refresh-source", help="prove source-chain finality")
    _add_config_operation(refresh, require_policy=True)
    refresh.add_argument("--max-polls", type=int)
    refresh.set_defaults(handler=_cmd_refresh_source)

    destination = commands.add_parser(
        "verify-destination",
        help="discover and prove exact destination fulfillment",
    )
    _add_config_operation(destination, require_policy=True)
    destination.add_argument("--destination-tx-hash")
    destination.add_argument("--max-polls", type=int)
    destination.set_defaults(handler=_cmd_verify_destination)

    status = commands.add_parser("status", help="read durable local operation state")
    _add_config_operation(status)
    status.set_defaults(handler=_cmd_status)

    receipt = commands.add_parser("receipt", help="write a redacted public receipt")
    _add_config_operation(receipt)
    receipt.add_argument("--artifacts", required=True)
    receipt.add_argument("--name", default="receipt.public.json")
    receipt.set_defaults(handler=_cmd_receipt)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    handler = cast(Command, args.handler)
    try:
        result = handler(args)
    except SubmissionUnknown as exc:
        _emit(
            {
                "ok": False,
                "error": {
                    "code": "SUBMISSION_UNKNOWN",
                    "message": str(exc),
                    "operation_id": exc.operation_id,
                },
            }
        )
        return 20
    except NeedsReconciliation as exc:
        _emit(
            {
                "ok": False,
                "error": {
                    "code": "NEEDS_RECONCILIATION",
                    "message": str(exc),
                    "operation_id": exc.operation_id,
                },
            }
        )
        return 21
    except TrackingPending as exc:
        _emit(
            {
                "ok": False,
                "error": {
                    "code": "TRACKING_PENDING",
                    "message": str(exc),
                    "state": exc.state,
                },
            }
        )
        return 22
    except SAFE_ERRORS as exc:
        _emit(
            {
                "ok": False,
                "error": {
                    "code": type(exc).__name__.upper(),
                    "message": str(exc),
                },
            }
        )
        return 2
    except Exception:
        _emit(
            {
                "ok": False,
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "command failed without a safe diagnostic",
                },
            }
        )
        return 1
    _emit({"ok": True, "command": args.command, "result": result})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
