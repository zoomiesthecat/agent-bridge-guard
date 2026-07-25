from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from test_authorization import bound_plan, direct_route_document, reviewable_approval

from agent_bridge_guard import cli
from agent_bridge_guard.approval import Approval, ApprovalSigningRequest
from agent_bridge_guard.cli import main
from agent_bridge_guard.execution_plan import ExecutionPlan
from agent_bridge_guard.models import Plan
from agent_bridge_guard.providers.debridge import (
    FULFILLED_ORDER_TOPIC,
    DeBridgeProvider,
)
from agent_bridge_guard.store import SQLiteOperationStore
from agent_bridge_guard.tracking import TrackingPending

SIGNER = "0x1111111111111111111111111111111111111111"
RECIPIENT = "0x2222222222222222222222222222222222222222"
OPERATOR_KEY = "0x" + "22" * 32
OPERATOR = Account.from_key(OPERATOR_KEY).address


@pytest.fixture(autouse=True)
def policy_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    class Policy:
        policy_id = "test-policy"
        policy_version = 1
        digest = "sha256:" + "aa" * 32
        approval_issuers = frozenset({OPERATOR})

        def confirmations_for(self, _chain_id: int) -> int:
            return 1

        def authorizes_manifest(self, _route_id: str, _digest: str) -> bool:
            return True

    class Validator:
        def __init__(self, _path: str) -> None:
            pass

        def validate(self, candidate: Plan, approval: Approval) -> object:
            return type(
                "Validated",
                (),
                {"execution": ExecutionPlan.from_plan(candidate, allow_expired=True)},
            )()

    monkeypatch.setattr(cli.TrustedPolicy, "load", lambda _path: Policy())
    monkeypatch.setattr(
        cli,
        "validate_bound_plan",
        lambda candidate, _policy, **_kwargs: (
            ExecutionPlan.from_plan(candidate, allow_expired=True),
            None,
        ),
    )
    monkeypatch.setattr(cli, "AuthorizationValidator", Validator)


def write_json(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps(value), encoding="utf-8")
    os.chmod(path, 0o600)
    return path.resolve()


def write_text(path: Path, value: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(value, encoding="utf-8")
    os.chmod(path, 0o600)
    return path.resolve()


def approval_for(candidate: Plan) -> Approval:
    if candidate.schema_version == 2:
        return reviewable_approval(candidate)
    payload = Approval.signing_payload(
        plan_id=candidate.plan_id,
        authorization_id="ticket-123",
        actor="operator-1",
        subject_signer=SIGNER,
        approved_at="2026-07-24T20:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
    )
    signature = (
        "0x"
        + Account.sign_message(
            encode_defunct(primitive=payload),
            OPERATOR_KEY,
        ).signature.hex()
    )
    return Approval.create(
        plan_id=candidate.plan_id,
        authorization_id="ticket-123",
        actor="operator-1",
        subject_signer=SIGNER,
        approved_at="2026-07-24T20:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
        issuer=OPERATOR,
        signature=signature,
    )


def plan() -> Plan:
    return Plan.create(
        {
            "provider": {
                "name": "debridge",
                "version": "2",
                "route_id": "arb-rh-native-v2",
                "route_kind": "native_in_swap_dln_native_out",
                "destination_dln_proxy": "0x" + "33" * 20,
                "destination_fulfillment_topic": FULFILLED_ORDER_TOPIC,
            },
            "intent": {
                "created_at": "2026-07-24T20:00:00Z",
                "expires_at": "2030-01-01T00:05:00Z",
                "source_chain_id": 42161,
                "destination_chain_id": 4663,
                "amount_wei": 1,
                "minimum_output_wei": 1,
                "recipient": RECIPIENT,
                "expected_signer": SIGNER,
            },
            "unsigned_transaction": {
                "chain_id": 42161,
                "nonce": 1,
                "to": "0x" + "44" * 20,
                "value": 1,
                "data": "0x12",
                "gas": 1,
                "max_fee_per_gas": 1,
                "max_priority_fee_per_gas": 0,
            },
            "decoded_semantics": {
                "source_order_token": "0x" + "55" * 20,
                "source_gross_amount_wei": 2,
                "protocol_fee_amount_wei": 1,
                "source_net_amount_wei": 1,
                "source_swap_router": "0x" + "55" * 20,
                "order_id": "0x" + "ab" * 32,
                "destination_chain_id": 4663,
                "destination_receiver": RECIPIENT,
                "destination_token": "0x" + "00" * 20,
                "destination_amount_wei": 1,
                "external_call": False,
                "allowed_taker": None,
            },
        }
    )


def direct_unbound_plan() -> Plan:
    candidate, _, _ = bound_plan()
    body = candidate.body()
    body.pop("policy_binding")
    intent = body["intent"]
    assert isinstance(intent, dict)
    intent["created_at"] = "2026-01-01T00:00:00Z"
    intent["expires_at"] = "2030-01-01T00:00:00Z"
    return Plan.create(body)


def legacy_route_document() -> dict[str, object]:
    return {
        "schema_version": 2,
        "route_id": "arb-rh-native-v2",
        "route_kind": "native_in_swap_dln_native_out",
        "source_chain_alias": "arbitrum",
        "destination_chain_alias": "robinhood",
        "source_chain_id": 42161,
        "destination_chain_id": 4663,
        "allowed_bridge_routers": ["0x" + "44" * 20],
        "allowed_source_swap_routers": ["0x" + "55" * 20],
        "allowed_source_swap_selectors": ["0x12345678"],
        "allowed_intermediary_give_tokens": ["0x" + "66" * 20],
        "allowed_dln_sources": ["0x" + "66" * 20],
        "allowed_refund_recipients": ["0x" + "77" * 20],
        "destination_dln_proxy": "0x" + "33" * 20,
        "destination_fulfillment_topic": FULFILLED_ORDER_TOPIC,
        "maximum_total_spend_wei": 2,
        "maximum_value_overhead_wei": 1,
        "maximum_price_impact_bps": 100,
        "maximum_swap_calldata_bytes": 1,
        "maximum_metadata_bytes": 0,
        "maximum_quote_age_seconds": 30,
        "maximum_plan_lifetime_seconds": 120,
    }


def direct_request_document(
    *,
    route_id: str = "test-direct-reserve-route",
    source_chain_alias: str = "arbitrum",
    destination_chain_alias: str = "robinhood",
) -> dict[str, object]:
    return {
        "schema_version": 2,
        "request_id": "ticket-123",
        "route_id": route_id,
        "source_chain_alias": source_chain_alias,
        "destination_chain_alias": destination_chain_alias,
        "amount_wei": "1000",
        "minimum_output_wei": "900",
        "signer": SIGNER,
        "recipient": RECIPIENT,
        "expires_at": "2030-01-01T00:05:00Z",
    }


def long_lived_bound_plan() -> Plan:
    candidate, _, _ = bound_plan()
    body = candidate.body()
    intent = body["intent"]
    assert isinstance(intent, dict)
    intent["created_at"] = "2026-01-01T00:00:00Z"
    intent["expires_at"] = "2030-01-01T00:00:00Z"
    return Plan.create(body, schema_version=2)


def config(tmp_path: Path) -> Path:
    database = tmp_path / "runtime" / "operations.db"
    path = tmp_path / "config.toml"
    path.write_text(
        f"""
[database]
path = "{database}"

[provider.debridge]
create_tx_url = "https://quote.example/api"
tracking_url = "https://tracking.example/api"

[chains.arbitrum]
chain_id = 42161
primary_rpc = "https://arb-primary.example/rpc"
secondary_rpc = "https://arb-secondary.example/rpc"

[chains.robinhood]
chain_id = 4663
primary_rpc = "https://rh-primary.example/rpc"
secondary_rpc = "https://rh-secondary.example/rpc"
""".strip(),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return path.resolve()


def test_route_digest_bootstraps_protected_policy(
    tmp_path: Path,
    capsys: object,
) -> None:
    route_path = write_json(tmp_path / "route.json", direct_route_document())

    assert main(["route-digest", "--route", str(route_path)]) == 0

    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    _, _, route = bound_plan()
    assert output["result"] == {
        "route_id": route.route_id,
        "route_kind": "reserve_erc20_dln_native_out",
        "route_manifest_digest": route.digest,
    }


def test_off_box_approval_workflow_writes_canonical_owner_only_artifact(
    tmp_path: Path,
    capsys: object,
) -> None:
    candidate = long_lived_bound_plan()
    plan_path = write_json(tmp_path / "plan.json", candidate.to_dict())
    artifacts = (tmp_path / "artifacts").resolve()

    assert (
        main(
            [
                "approval-request",
                "--policy",
                "/test-policy.json",
                "--plan",
                str(plan_path),
                "--artifacts",
                str(artifacts),
                "--name",
                "approval-request.json",
                "--authorization-id",
                "ticket-123",
                "--actor",
                "operator-1",
                "--approved-at",
                "2026-01-02T00:00:00Z",
                "--expires-at",
                "2029-01-01T00:00:00Z",
            ]
        )
        == 0
    )
    request_output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    request_path = artifacts / "approval-request.json"
    request = ApprovalSigningRequest.parse(json.loads(request_path.read_text(encoding="utf-8")))
    assert request_output["result"]["eip191_message_hex"] == request.eip191_message_hex
    signature = (
        "0x"
        + Account.sign_message(
            encode_defunct(primitive=bytes.fromhex(request.eip191_message_hex[2:])),
            OPERATOR_KEY,
        ).signature.hex()
    )
    signature_path = write_text(tmp_path / "operator-signature.txt", signature)

    result = main(
        [
            "approve",
            "--policy",
            "/test-policy.json",
            "--plan",
            str(plan_path),
            "--request",
            str(request_path),
            "--signature-file",
            str(signature_path),
            "--artifacts",
            str(artifacts),
            "--name",
            "approval.json",
        ]
    )
    assert result == 0
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["ok"] is True
    approval = json.loads((artifacts / "approval.json").read_text(encoding="utf-8"))
    assert approval["plan_id"] == candidate.plan_id
    assert oct((artifacts / "approval.json").stat().st_mode & 0o777) == "0o600"


def test_plan_command_uses_both_nonce_views_and_operator_route_manifest(
    tmp_path: Path,
    capsys: object,
    monkeypatch: object,
) -> None:
    request = write_json(
        tmp_path / "request.json",
        direct_request_document(),
    )
    route = write_json(
        tmp_path / "route.json",
        direct_route_document(),
    )

    class Client:
        def transaction_count(self, _address: str, _block: str) -> int:
            return 1

        def call(self, method: str, params: list[object]) -> str:
            if method == "eth_call":
                transaction = params[0]
                if isinstance(transaction, dict) and "from" in transaction:
                    return "0x00"
                return "0x01"
            if method == "eth_estimateGas":
                return "0x1"
            if method == "eth_getTransactionCount":
                assert params[1] in {"latest", "pending"}
                return "0x1"
            if method == "eth_getBalance":
                return hex(10**18)
            raise AssertionError(f"unexpected RPC method: {method}")

    class Pool:
        primary = Client()
        secondary = Client()
        chain_id = 42161

    monkeypatch.setattr(  # type: ignore[attr-defined]
        "agent_bridge_guard.cli._rpc_pool",
        lambda _chain: Pool(),
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        DeBridgeProvider,
        "quote",
        lambda *_args, **_kwargs: direct_unbound_plan(),
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "agent_bridge_guard.cli.preflight_reserve_erc20_source_transaction",
        lambda *_args, **_kwargs: None,
    )
    artifacts = (tmp_path / "artifacts").resolve()

    result = main(
        [
            "plan",
            "--policy",
            "/test-policy.json",
            "--config",
            str(config(tmp_path)),
            "--request",
            str(request),
            "--route",
            str(route),
            "--artifacts",
            str(artifacts),
            "--name",
            "plan.json",
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    written = json.loads((artifacts / "plan.json").read_text())
    assert payload["result"]["plan_id"] == written["plan_id"]
    assert written["schema_version"] == 2
    assert written["plan_id"] != direct_unbound_plan().plan_id


def test_policy_check_rejects_quarantined_legacy_route(
    tmp_path: Path,
    capsys: object,
) -> None:
    route = write_json(tmp_path / "route.json", legacy_route_document())

    assert (
        main(
            [
                "policy-check",
                "--policy",
                "/test-policy.json",
                "--route",
                str(route),
            ]
        )
        == 2
    )

    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["error"]["message"] == "legacy source-aggregator routes are quarantined"


def test_cli_builds_rpc_pool_and_operation_engine_without_signing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = cli.load_config(config(tmp_path))
    endpoints: list[str] = []

    class Client:
        def __init__(self, endpoint: str) -> None:
            endpoints.append(endpoint)

        def chain_id(self) -> int:
            return 42161

    monkeypatch.setattr(cli, "RpcClient", Client)
    pool = cli._rpc_pool(settings.chains["arbitrum"])
    assert pool.chain_id == 42161
    assert endpoints == [
        "https://arb-primary.example/rpc",
        "https://arb-secondary.example/rpc",
    ]

    store = SQLiteOperationStore(tmp_path / "runtime" / "operations.db")
    candidate = long_lived_bound_plan()
    approval = reviewable_approval(candidate)
    operation = store.reserve_operation(
        candidate,
        idempotency_key="engine-construction",
        signer=SIGNER,
        source_chain_id=42161,
        nonce=7,
        approval_id=approval.approval_id,
        approval=approval,
    )
    seen: dict[str, object] = {}

    class Guard:
        def __init__(
            self,
            received_store: object,
            received_pool: object,
            *,
            policy_path: str,
            source_confirmations: int,
        ) -> None:
            seen.update(
                store=received_store,
                pool=received_pool,
                policy_path=policy_path,
                confirmations=source_confirmations,
            )

    sentinel_pool = object()
    monkeypatch.setattr(cli, "_rpc_pool", lambda _chain: sentinel_pool)
    monkeypatch.setattr(cli, "ExecutionEngine", Guard)
    result = cli._engine_for_operation(settings, store, operation, "/test-policy.json")

    assert isinstance(result, Guard)
    assert seen["store"] is store
    assert seen["pool"] is sentinel_pool
    assert seen["confirmations"] == 1


def test_private_signature_accepts_exact_json_string(tmp_path: Path) -> None:
    signature = "0x" + "11" * 65
    path = write_text(tmp_path / "signature.json", json.dumps({"signature": signature}))

    assert cli._private_signature(str(path)) == signature


def test_policy_check_accepts_authorized_direct_route(
    tmp_path: Path,
    capsys: object,
) -> None:
    route = write_json(tmp_path / "route.json", direct_route_document())

    assert (
        main(
            [
                "policy-check",
                "--policy",
                "/test-policy.json",
                "--route",
                str(route),
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["result"]["route_id"] == "test-direct-reserve-route"


def test_plan_fails_before_provider_for_identity_alias_chain_and_nonce_errors(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings_path = config(tmp_path)
    artifacts = (tmp_path / "artifacts").resolve()
    route_path = write_json(tmp_path / "route.json", direct_route_document())

    def invoke(request_document: dict[str, object], route_document: dict[str, object]) -> int:
        request_path = write_json(tmp_path / "request.json", request_document)
        write_json(route_path, route_document)
        return main(
            [
                "plan",
                "--policy",
                "/test-policy.json",
                "--config",
                str(settings_path),
                "--request",
                str(request_path),
                "--route",
                str(route_path),
                "--artifacts",
                str(artifacts),
            ]
        )

    assert invoke(direct_request_document(route_id="wrong"), direct_route_document()) == 2
    assert "route identity" in capsys.readouterr().out  # type: ignore[attr-defined]

    missing_alias_route = direct_route_document()
    missing_alias_route["source_chain_alias"] = "missing"
    assert (
        invoke(
            direct_request_document(source_chain_alias="missing"),
            missing_alias_route,
        )
        == 2
    )
    assert "chain alias is missing" in capsys.readouterr().out  # type: ignore[attr-defined]

    wrong_chain_route = direct_route_document()
    wrong_chain_route["source_chain_id"] = 1
    assert invoke(direct_request_document(), wrong_chain_route) == 2
    assert "chain IDs do not match" in capsys.readouterr().out  # type: ignore[attr-defined]

    class Client:
        def __init__(self, nonce: int) -> None:
            self.nonce = nonce

        def transaction_count(self, _address: str, _block: str) -> int:
            return self.nonce

    class Pool:
        primary = Client(1)
        secondary = Client(2)

    monkeypatch.setattr(cli, "_rpc_pool", lambda _chain: Pool())
    assert invoke(direct_request_document(), direct_route_document()) == 21
    assert "nonce disagreement" in capsys.readouterr().out  # type: ignore[attr-defined]


def test_plan_rejects_legacy_provider_result_before_preflight(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_path = write_json(tmp_path / "request.json", direct_request_document())
    route_path = write_json(tmp_path / "route.json", direct_route_document())

    class Client:
        def transaction_count(self, _address: str, _block: str) -> int:
            return 1

    class Pool:
        primary = Client()
        secondary = Client()

    monkeypatch.setattr(cli, "_rpc_pool", lambda _chain: Pool())
    monkeypatch.setattr(DeBridgeProvider, "quote", lambda *_args, **_kwargs: plan())
    monkeypatch.setattr(
        cli,
        "preflight_reserve_erc20_source_transaction",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("preflight touched")),
    )

    assert (
        main(
            [
                "plan",
                "--policy",
                "/test-policy.json",
                "--config",
                str(config(tmp_path)),
                "--request",
                str(request_path),
                "--route",
                str(route_path),
                "--artifacts",
                str((tmp_path / "artifacts").resolve()),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["error"]["message"] == "legacy source-aggregator routes are quarantined"


def test_plan_rejects_quarantined_legacy_route_before_network(
    tmp_path: Path,
    capsys: object,
    monkeypatch: object,
) -> None:
    request = write_json(
        tmp_path / "request.json",
        {
            "schema_version": 2,
            "request_id": "ticket-123",
            "route_id": "arb-rh-native-v2",
            "source_chain_alias": "arbitrum",
            "destination_chain_alias": "robinhood",
            "amount_wei": "1",
            "minimum_output_wei": "1",
            "signer": SIGNER,
            "recipient": RECIPIENT,
            "expires_at": "2030-01-01T00:05:00Z",
        },
    )
    route = write_json(tmp_path / "route.json", legacy_route_document())
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "agent_bridge_guard.cli._rpc_pool",
        lambda _chain: (_ for _ in ()).throw(AssertionError("network touched")),
    )

    assert (
        main(
            [
                "plan",
                "--policy",
                "/test-policy.json",
                "--config",
                str(config(tmp_path)),
                "--request",
                str(request),
                "--route",
                str(route),
                "--artifacts",
                str((tmp_path / "artifacts").resolve()),
            ]
        )
        == 2
    )

    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["error"]["message"] == "legacy source-aggregator routes are quarantined"


def test_status_output_never_includes_private_fields(
    tmp_path: Path,
    capsys: object,
) -> None:
    settings_path = config(tmp_path)
    database = tmp_path / "runtime" / "operations.db"
    store = SQLiteOperationStore(database)
    operation = store.reserve_operation(
        plan(),
        idempotency_key="DO_NOT_PRINT_IDEMPOTENCY_KEY",
        signer=SIGNER,
        source_chain_id=42161,
        nonce=1,
        approval_id="sha256:" + "cd" * 32,
    )

    assert (
        main(
            [
                "status",
                "--config",
                str(settings_path),
                "--operation",
                operation.operation_id,
            ]
        )
        == 0
    )
    status = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "DO_NOT_PRINT_IDEMPOTENCY_KEY" not in status


def test_export_detached_writes_only_exact_unsigned_request(
    tmp_path: Path,
    capsys: object,
) -> None:
    candidate = long_lived_bound_plan()
    plan_path = write_json(tmp_path / "plan.json", candidate.to_dict())
    approval_path = write_json(
        tmp_path / "approval.json",
        reviewable_approval(candidate).to_dict(),
    )
    artifacts = (tmp_path / "artifacts").resolve()

    assert (
        main(
            [
                "export-detached",
                "--policy",
                "/test-policy.json",
                "--plan",
                str(plan_path),
                "--approval",
                str(approval_path),
                "--artifacts",
                str(artifacts),
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    request = json.loads((artifacts / "signing-request.json").read_text(encoding="utf-8"))
    assert output["result"]["plan_id"] == candidate.plan_id
    assert request["artifact_type"] == "detached_signing_request"
    assert request["expected_signer"].lower() == SIGNER.lower()
    assert request["unsigned_transaction"]["nonce"] == 7
    assert "raw_signed_transaction" not in request


def test_execute_without_go_returns_safe_error_before_loading_credentials(
    capsys: object,
) -> None:
    canary = "DO_NOT_EXPOSE_KEYSTORE_PASSWORD"

    assert (
        main(
            [
                "execute",
                "--policy",
                "/test-policy.json",
                "--config",
                "/not/read.toml",
                "--plan",
                "/not/read-plan.json",
                "--approval",
                "/not/read-approval.json",
                "--keystore",
                canary,
                "--password-file",
                canary,
                "--idempotency-key",
                "request-1",
            ]
        )
        == 2
    )

    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert output == {
        "ok": False,
        "error": {"code": "VALUEERROR", "message": "execute requires --go"},
    }
    assert canary not in json.dumps(output)


def test_resume_without_go_still_requires_valid_runtime_configuration(
    capsys: object,
) -> None:
    assert (
        main(
            [
                "resume",
                "--policy",
                "/test-policy.json",
                "--config",
                "/not/read.toml",
                "--operation",
                "op-1",
            ]
        )
        == 2
    )

    assert json.loads(capsys.readouterr().out) == {  # type: ignore[attr-defined]
        "ok": False,
        "error": {"code": "CONFIGERROR", "message": "configuration file is unavailable"},
    }


def test_receipt_command_redacts_store_only_secrets(
    tmp_path: Path,
    capsys: object,
) -> None:
    settings_path = config(tmp_path)
    store = SQLiteOperationStore(tmp_path / "runtime" / "operations.db")
    operation = store.reserve_operation(
        plan(),
        idempotency_key="DO_NOT_PUBLISH_IDEMPOTENCY",
        signer=SIGNER,
        source_chain_id=42161,
        nonce=1,
        approval_id="sha256:" + "cd" * 32,
    )
    artifacts = (tmp_path / "receipts").resolve()

    assert (
        main(
            [
                "receipt",
                "--config",
                str(settings_path),
                "--operation",
                operation.operation_id,
                "--artifacts",
                str(artifacts),
            ]
        )
        == 0
    )

    encoded = (artifacts / "receipt.public.json").read_text(encoding="utf-8")
    assert "DO_NOT_PUBLISH_IDEMPOTENCY" not in encoded
    assert SIGNER.lower() not in encoded.lower()
    receipt = json.loads(encoded)
    assert receipt["operation_id"] == operation.operation_id
    assert receipt["order_id"] == "0x" + "ab" * 32


def test_prepare_external_imports_only_owner_only_signed_bytes(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings_path = config(tmp_path)
    candidate = plan()
    plan_path = write_json(tmp_path / "plan.json", candidate.to_dict())
    approval = approval_for(candidate)
    approval_path = write_json(tmp_path / "approval.json", approval.to_dict())
    signed_file = write_text(tmp_path / "signed.tx", "0x0102")
    store = SQLiteOperationStore(tmp_path / "runtime" / "operations.db")
    seen: dict[str, object] = {}

    class Pool:
        chain_id = 42161

    def prepare(
        _self: object,
        loaded_plan: Plan,
        loaded_approval: Approval,
        raw: bytes,
        *,
        idempotency_key: str,
    ) -> object:
        seen["raw"] = raw
        return store.reserve_operation(
            loaded_plan,
            idempotency_key=idempotency_key,
            signer=SIGNER,
            source_chain_id=42161,
            nonce=1,
            approval_id=loaded_approval.approval_id,
        )

    monkeypatch.setattr("agent_bridge_guard.cli._rpc_pool", lambda _chain: Pool())

    class Guard:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        prepare_external = prepare

    monkeypatch.setattr("agent_bridge_guard.cli.ExecutionEngine", Guard)
    assert (
        main(
            [
                "prepare-external",
                "--policy",
                "/test-policy.json",
                "--config",
                str(settings_path),
                "--plan",
                str(plan_path),
                "--approval",
                str(approval_path),
                "--signed-file",
                str(signed_file),
                "--idempotency-key",
                "request-external",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert seen["raw"] == b"\x01\x02"
    assert output["result"]["state"] == "reserved"


def test_refresh_and_tracking_pending_keep_machine_safe_exit_codes(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings_path = config(tmp_path)
    store = SQLiteOperationStore(tmp_path / "runtime" / "operations.db")
    operation = store.reserve_operation(
        plan(),
        idempotency_key="request-refresh",
        signer=SIGNER,
        source_chain_id=42161,
        nonce=1,
        approval_id="sha256:" + "cd" * 32,
    )

    class ReconciliationGuard:
        def refresh_source(self, _operation_id: str, *, max_polls: int | None) -> object:
            from agent_bridge_guard.engine import NeedsReconciliation

            raise NeedsReconciliation(operation.operation_id, "two RPCs disagree")

    monkeypatch.setattr(
        "agent_bridge_guard.cli._engine_for_operation",
        lambda *_: ReconciliationGuard(),
    )
    assert (
        main(
            [
                "refresh-source",
                "--policy",
                "/test-policy.json",
                "--config",
                str(settings_path),
                "--operation",
                operation.operation_id,
            ]
        )
        == 21
    )
    reconciliation = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert reconciliation["error"]["code"] == "NEEDS_RECONCILIATION"
    assert reconciliation["error"]["operation_id"] == operation.operation_id

    claim = store.claim_preparation(
        operation.operation_id,
        kind="test-eip1559",
        fingerprint="signed-bytes",
        replay_safe=True,
    )
    assert claim.token is not None
    prepared = store.complete_preparation(operation.operation_id, claim.token, b"signed-bytes")
    assert prepared.tx_hash is not None

    def pending(*_args: object, **_kwargs: object) -> object:
        raise TrackingPending("Created")

    monkeypatch.setattr(
        "agent_bridge_guard.cli.DeBridgeTrackingClient.discover_fulfillment", pending
    )
    assert (
        main(
            [
                "verify-destination",
                "--policy",
                "/test-policy.json",
                "--config",
                str(settings_path),
                "--operation",
                operation.operation_id,
            ]
        )
        == 22
    )
    tracking = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert tracking["error"] == {
        "code": "TRACKING_PENDING",
        "message": "deBridge order is not yet fulfilled",
        "state": "Created",
    }


def test_help_version_and_unexpected_exception_do_not_emit_secret_canary(
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(SystemExit, match="0"):
        main(["--version"])
    assert capsys.readouterr().out.strip() == "0.1.0"  # type: ignore[attr-defined]

    with pytest.raises(SystemExit, match="0"):
        main(["--help"])
    assert "Guarded cross-chain execution" in capsys.readouterr().out  # type: ignore[attr-defined]

    canary = "DO_NOT_LEAK_INTERNAL_EXCEPTION_SECRET"

    def explode(_path: str) -> object:
        raise RuntimeError(canary)

    monkeypatch.setattr("agent_bridge_guard.cli._load_plan", explode)
    assert (
        main(
            [
                "export-detached",
                "--policy",
                "/test-policy.json",
                "--plan",
                "/ignored",
                "--approval",
                "/ignored",
                "--artifacts",
                "/ignored",
            ]
        )
        == 1
    )
    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert output["error"]["code"] == "INTERNAL_ERROR"
    assert canary not in json.dumps(output)
