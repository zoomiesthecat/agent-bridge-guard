from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from eth_account import Account

from agent_bridge_guard import cli
from agent_bridge_guard.config import (
    ChainConfig,
    ConfigError,
    DebridgeConfig,
    SecretUrl,
    Settings,
    load_config,
)
from agent_bridge_guard.execution_plan import ExecutionPlan
from agent_bridge_guard.models import Plan
from agent_bridge_guard.providers.debridge import FULFILLED_ORDER_TOPIC
from agent_bridge_guard.store import Operation, OperationEvent, OperationState
from agent_bridge_guard.tracking import DeBridgeTrackingClient, TrackingError, TrackingPending

SIGNER = "0x1111111111111111111111111111111111111111"
RECIPIENT = "0x2222222222222222222222222222222222222222"
ORDER_ID = "0x" + "ab" * 32
SOURCE_TX = "0x" + "cd" * 32
DESTINATION_TX = "0x" + "ef" * 32


@pytest.fixture(autouse=True)
def policy_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    class Policy:
        policy_id = "test-policy"
        policy_version = 1
        digest = "sha256:" + "aa" * 32
        approval_issuers = frozenset({Account.from_key("0x" + "11" * 32).address})

        def confirmations_for(self, _chain_id: int) -> int:
            return 1

        def authorizes_manifest(self, _route_id: str, _digest: str) -> bool:
            return True

    monkeypatch.setattr(cli.TrustedPolicy, "load", lambda _path: Policy())
    monkeypatch.setattr(
        cli,
        "validate_bound_plan",
        lambda plan, _policy, **_kwargs: (ExecutionPlan.from_plan(plan, allow_expired=True), None),
    )


def _write_config(path: Path, provider_url: str = "https://quote.example/api") -> None:
    path.write_text(
        f'''[database]
path = "{path.parent / "operations.sqlite3"}"

[provider.debridge]
create_tx_url = "{provider_url}"
tracking_url = "https://tracking.example/api"

[chains.arbitrum]
chain_id = 42161
primary_rpc = "https://arb-primary.example/rpc"
secondary_rpc = "https://arb-secondary.example/rpc"
''',
        encoding="utf-8",
    )
    path.chmod(0o600)


def _plan() -> Plan:
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
                "minimum_output_wei": 900,
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
                "order_id": ORDER_ID,
                "destination_chain_id": 4663,
                "destination_receiver": RECIPIENT,
                "destination_token": "0x" + "00" * 20,
                "destination_amount_wei": 950,
                "external_call": False,
                "allowed_taker": None,
            },
        }
    )


def _value(text: str) -> dict[str, str]:
    return {"stringValue": text}


def _fulfilled_status() -> dict[str, object]:
    return {
        "orderId": _value(ORDER_ID),
        "state": "Fulfilled",
        "externalCallState": "NoExtCall",
        "receiverDst": _value(RECIPIENT),
        "givePatchAuthoritySrc": _value(SIGNER),
        "orderAuthorityAddressDst": _value(RECIPIENT),
        "createdSrcEventMetadata": {
            "transactionHash": _value(SOURCE_TX),
            "initiator": _value(SIGNER),
        },
        "giveOfferWithMetadata": {"chainId": _value("42161")},
        "takeOfferWithMetadata": {
            "chainId": _value("4663"),
            "tokenAddress": _value("0x" + "00" * 20),
            "finalAmount": _value("950"),
        },
        "fulfilledDstEventMetadata": {"transactionHash": _value(DESTINATION_TX)},
    }


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_path=tmp_path / "operations.sqlite3",
        debridge=DebridgeConfig(
            create_tx_url=SecretUrl("https://quote.example/api"),
            tracking_url=SecretUrl("https://tracking.example/api"),
        ),
        chains={
            "source": ChainConfig(
                chain_id=42161,
                primary_rpc=SecretUrl("https://source-primary.example"),
                secondary_rpc=SecretUrl("https://source-secondary.example"),
            ),
            "destination": ChainConfig(
                chain_id=4663,
                primary_rpc=SecretUrl("https://destination-primary.example"),
                secondary_rpc=SecretUrl("https://destination-secondary.example"),
            ),
        },
    )


def _operation(*, tx_hash: str | None = SOURCE_TX) -> Operation:
    return Operation(
        operation_id="operation-1",
        idempotency_key="private-key",
        approval_id="approval-1",
        plan=_plan(),
        signer=SIGNER,
        source_chain_id=42161,
        nonce=1,
        state=OperationState.SOURCE_FINAL,
        created_at_ns=1,
        raw_signed_tx=None,
        tx_hash=tx_hash,
        source_finality_evidence=(
            {
                "chain_id": 42161,
                "transaction_hash": tx_hash,
                "block_number": 1,
                "block_hash": "0x" + "aa" * 32,
                "confirmations": 12,
                "rpc_quorum": 2,
                "receipt_status": 1,
            }
            if tx_hash is not None
            else None
        ),
        destination_fulfillment_evidence=None,
        events=(
            OperationEvent(
                sequence=1,
                state=OperationState.SOURCE_FINAL,
                occurred_at_ns=1,
                cancellation_proof=None,
            ),
        ),
    )


def test_load_config_redacts_provider_url_credentials_in_errors(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    secret = "DO_NOT_LEAK_PROVIDER" + "_SECRET"  # noqa: S105
    _write_config(path, f"https://user:{secret}@quote.example/api")

    with pytest.raises(ConfigError) as error:
        load_config(path)

    assert secret not in str(error.value)


def test_load_config_redacts_malformed_document_contents(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    secret = "DO_NOT_LEAK_MALFORMED" + "_CONFIG"  # noqa: S105
    path.write_text(f'private = "{secret}', encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(ConfigError) as error:
        load_config(path)

    assert secret not in str(error.value)


def test_load_config_rejects_relative_configuration_path() -> None:
    with pytest.raises(ConfigError, match="must be absolute"):
        load_config("config.toml")


def test_load_config_hides_unavailable_path(tmp_path: Path) -> None:
    missing = tmp_path / "DO_NOT_LEAK_MISSING_CONFIG"

    with pytest.raises(ConfigError) as error:
        load_config(missing)

    assert str(missing) not in str(error.value)


def test_load_config_rejects_relative_database_path(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    _write_config(path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            str(path.parent / "operations.sqlite3"), "operations.sqlite3"
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="database.path must be absolute"):
        load_config(path)


def test_load_config_rejects_confirmation_policy_in_mutable_runtime_config(
    tmp_path: Path,
) -> None:
    path = tmp_path / "config.toml"
    _write_config(path)
    path.write_text(
        path.read_text(encoding="utf-8") + "\nconfirmations = true\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="fields do not match schema"):
        load_config(path)


def test_load_config_rejects_provider_endpoint_without_https(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    _write_config(path, "http://quote.example/api")

    with pytest.raises(ConfigError, match="must be an HTTPS URL"):
        load_config(path)


def test_execute_without_go_returns_safe_error_before_reading_input(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = cli.main(
        [
            "execute",
            "--policy",
            "/test-policy.json",
            "--config",
            "/DO_NOT_READ_CONFIG",
            "--plan",
            "/DO_NOT_READ_PLAN",
            "--approval",
            "/DO_NOT_READ_APPROVAL",
            "--keystore",
            "/DO_NOT_READ_KEYSTORE",
            "--password-file",
            "/DO_NOT_READ_PASSWORD",
            "--idempotency-key",
            "DO_NOT_LEAK_KEY",
        ]
    )

    assert result == 2
    output = json.loads(capsys.readouterr().out)
    assert output["error"]["code"] == "VALUEERROR"
    assert output["error"]["message"] == "execute requires --go"
    assert "DO_NOT_LEAK_KEY" not in json.dumps(output)


def test_main_redacts_unexpected_wallet_adapter_error(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(_path: object) -> object:
        raise RuntimeError("DO_NOT_LEAK")

    monkeypatch.setattr(cli, "load_config", fail)

    result = cli.main(["status", "--config", "/config.toml", "--operation", "operation-1"])

    assert result == 1
    assert json.loads(capsys.readouterr().out) == {
        "ok": False,
        "error": {
            "code": "INTERNAL_ERROR",
            "message": "command failed without a safe diagnostic",
        },
    }


def test_main_returns_tracking_pending_exit_contract(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def pending(_path: object) -> object:
        raise TrackingPending("Created")

    monkeypatch.setattr(cli, "load_config", pending)

    result = cli.main(["status", "--config", "/config.toml", "--operation", "operation-1"])

    assert result == 22
    assert json.loads(capsys.readouterr().out)["error"] == {
        "code": "TRACKING_PENDING",
        "message": "deBridge order is not yet fulfilled",
        "state": "Created",
    }


def test_main_returns_submission_unknown_exit_contract(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def unknown(_path: object) -> object:
        raise cli.SubmissionUnknown("operation-1")

    monkeypatch.setattr(cli, "load_config", unknown)

    result = cli.main(["status", "--config", "/config.toml", "--operation", "operation-1"])

    assert result == 20
    assert json.loads(capsys.readouterr().out)["error"] == {
        "code": "SUBMISSION_UNKNOWN",
        "message": "submission outcome is unknown; resume exact persisted transaction",
        "operation_id": "operation-1",
    }


def test_main_returns_reconciliation_exit_contract(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def needs_reconciliation(_path: object) -> object:
        raise cli.NeedsReconciliation("operation-1", "independent nonce disagreement")

    monkeypatch.setattr(cli, "load_config", needs_reconciliation)

    result = cli.main(["status", "--config", "/config.toml", "--operation", "operation-1"])

    assert result == 21
    assert json.loads(capsys.readouterr().out)["error"] == {
        "code": "NEEDS_RECONCILIATION",
        "message": "independent nonce disagreement",
        "operation_id": "operation-1",
    }


def test_execute_dispatches_only_approved_plan_to_engine(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    operation = _operation()
    calls: dict[str, object] = {}

    class Guard:
        def __init__(
            self,
            store: object,
            rpc: object,
            *,
            policy_path: str,
            source_confirmations: int,
        ) -> None:
            calls["store"] = store
            calls["rpc"] = rpc
            calls["policy_path"] = policy_path
            calls["confirmations"] = source_confirmations

        def execute(
            self, plan: Plan, approval: object, *, idempotency_key: str, signer: object
        ) -> Operation:
            calls.update(
                plan=plan,
                approval=approval,
                idempotency_key=idempotency_key,
                signer=signer,
            )
            return operation

    store = object()
    approval = object()
    signer = object()
    monkeypatch.setattr(cli, "load_config", lambda _path: settings)
    monkeypatch.setattr(cli, "_load_plan", lambda _path: _plan())
    monkeypatch.setattr(cli, "_load_approval", lambda _path: approval)
    monkeypatch.setattr(cli, "SQLiteOperationStore", lambda _path: store)
    monkeypatch.setattr(cli, "_rpc_pool", lambda _chain: "source-rpc")
    monkeypatch.setattr(cli, "ExecutionEngine", Guard)
    monkeypatch.setattr(cli, "LocalKeystoreSigner", lambda _key, _password: signer)

    result = cli.main(
        [
            "execute",
            "--policy",
            "/test-policy.json",
            "--config",
            "/config.toml",
            "--plan",
            "/plan.json",
            "--approval",
            "/approval.json",
            "--keystore",
            "/keystore.json",
            "--password-file",
            "/password.txt",
            "--idempotency-key",
            "request-1",
            "--go",
        ]
    )

    assert result == 0
    assert calls["plan"].plan_id == _plan().plan_id  # type: ignore[union-attr]
    assert calls["approval"] is approval
    assert calls["idempotency_key"] == "request-1"
    assert calls["signer"] is signer
    assert calls["policy_path"] == "/test-policy.json"
    assert calls["confirmations"] == 1
    assert json.loads(capsys.readouterr().out)["result"]["operation_id"] == "operation-1"


def test_resume_loads_optional_approval_and_dispatches_to_operation_guard(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    operation = _operation()
    approval = object()
    calls: dict[str, object] = {}

    class Store:
        def get_operation(self, operation_id: str) -> Operation:
            calls["lookup"] = operation_id
            return operation

    class Guard:
        def resume(
            self,
            operation_id: str,
            *,
            approval: object,
            allow_broadcast: bool,
        ) -> Operation:
            calls["resumed"] = operation_id
            calls["approval"] = approval
            calls["allow_broadcast"] = allow_broadcast
            return operation

    monkeypatch.setattr(cli, "load_config", lambda _path: _settings(tmp_path))
    monkeypatch.setattr(cli, "SQLiteOperationStore", lambda _path: Store())
    monkeypatch.setattr(cli, "_load_approval", lambda _path: approval)
    monkeypatch.setattr(cli, "_engine_for_operation", lambda *_args: Guard())

    result = cli.main(
        [
            "resume",
            "--policy",
            "/test-policy.json",
            "--config",
            "/config.toml",
            "--operation",
            operation.operation_id,
            "--approval",
            "/approval.json",
            "--go",
        ]
    )

    assert result == 0
    assert calls == {
        "lookup": operation.operation_id,
        "resumed": operation.operation_id,
        "approval": approval,
        "allow_broadcast": True,
    }
    assert json.loads(capsys.readouterr().out)["result"]["state"] == "source_final"


def test_verify_destination_uses_explicit_hash_with_destination_rpc(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    operation = _operation()
    calls: dict[str, object] = {}

    class Store:
        def get_operation(self, _operation_id: str) -> Operation:
            return operation

    class Guard:
        def verify_destination(self, operation_id: str, **kwargs: object) -> Operation:
            calls["operation_id"] = operation_id
            calls.update(kwargs)
            return operation

    monkeypatch.setattr(cli, "load_config", lambda _path: _settings(tmp_path))
    monkeypatch.setattr(cli, "SQLiteOperationStore", lambda _path: Store())
    monkeypatch.setattr(cli, "_engine_for_operation", lambda *_args: Guard())
    monkeypatch.setattr(cli, "_rpc_pool", lambda chain: f"rpc-{chain.chain_id}")

    result = cli.main(
        [
            "verify-destination",
            "--policy",
            "/test-policy.json",
            "--config",
            "/config.toml",
            "--operation",
            operation.operation_id,
            "--destination-tx-hash",
            DESTINATION_TX,
            "--max-polls",
            "3",
        ]
    )

    assert result == 0
    assert calls == {
        "operation_id": operation.operation_id,
        "destination_transaction_hash": DESTINATION_TX,
        "destination_rpc": "rpc-4663",
        "confirmations": 1,
        "max_polls": 3,
    }
    assert json.loads(capsys.readouterr().out)["result"]["operation_id"] == operation.operation_id


def test_verify_destination_discovers_hash_only_from_bound_source_transaction(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    operation = _operation()
    calls: dict[str, object] = {}

    class Store:
        def get_operation(self, _operation_id: str) -> Operation:
            return operation

    class Tracking:
        def __init__(self, url: str, http_json: object) -> None:
            calls["tracking_url"] = url
            calls["tracking_http"] = http_json

        def discover_fulfillment(self, plan: Plan, source_hash: str) -> SimpleNamespace:
            calls["tracking_plan"] = plan
            calls["source_hash"] = source_hash
            return SimpleNamespace(destination_transaction_hash=DESTINATION_TX)

    class Guard:
        def verify_destination(self, _operation_id: str, **kwargs: object) -> Operation:
            calls.update(kwargs)
            return operation

    monkeypatch.setattr(cli, "load_config", lambda _path: _settings(tmp_path))
    monkeypatch.setattr(cli, "SQLiteOperationStore", lambda _path: Store())
    monkeypatch.setattr(cli, "DeBridgeTrackingClient", Tracking)
    monkeypatch.setattr(cli, "_engine_for_operation", lambda *_args: Guard())
    monkeypatch.setattr(cli, "_rpc_pool", lambda chain: f"rpc-{chain.chain_id}")

    result = cli.main(
        [
            "verify-destination",
            "--policy",
            "/test-policy.json",
            "--config",
            "/config.toml",
            "--operation",
            operation.operation_id,
        ]
    )

    assert result == 0
    assert calls["tracking_url"] == "https://tracking.example/api"
    assert calls["source_hash"] == SOURCE_TX
    assert calls["destination_transaction_hash"] == DESTINATION_TX
    assert json.loads(capsys.readouterr().out)["result"]["operation_id"] == operation.operation_id


def test_verify_destination_requires_source_hash_for_advisory_discovery(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    operation = _operation(tx_hash=None)

    class Store:
        def get_operation(self, _operation_id: str) -> Operation:
            return operation

    monkeypatch.setattr(cli, "load_config", lambda _path: _settings(tmp_path))
    monkeypatch.setattr(cli, "SQLiteOperationStore", lambda _path: Store())

    result = cli.main(
        [
            "verify-destination",
            "--policy",
            "/test-policy.json",
            "--config",
            "/config.toml",
            "--operation",
            operation.operation_id,
        ]
    )

    assert result == 2
    assert json.loads(capsys.readouterr().out)["error"] == {
        "code": "TRACKINGERROR",
        "message": "source transaction hash is unavailable",
    }


def test_tracking_rejects_source_transaction_with_multiple_order_ids() -> None:
    client = DeBridgeTrackingClient(
        "https://tracking.example/api",
        lambda _url: {"orderIds": [ORDER_ID, "0x" + "cd" * 32]},
    )

    with pytest.raises(TrackingError, match="exact planned order"):
        client.discover_fulfillment(_plan(), SOURCE_TX)


def test_tracking_rejects_fulfillment_with_external_call() -> None:
    status = _fulfilled_status()
    status["externalCallState"] = "Executed"

    def get(url: str) -> object:
        if "/Transaction/" in url:
            return {"orderIds": [ORDER_ID]}
        return status

    with pytest.raises(TrackingError, match="destination external call"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_invalid_source_transaction_hash_before_request() -> None:
    client = DeBridgeTrackingClient(
        "https://tracking.example/api", lambda _url: pytest.fail("request was made")
    )

    with pytest.raises(ValueError, match="source transaction hash is invalid"):
        client.discover_fulfillment(_plan(), "0xnot-a-transaction")


def test_tracking_rejects_status_for_a_different_order() -> None:
    status = _fulfilled_status()
    status["orderId"] = _value("0x" + "ee" * 32)

    def get(url: str) -> object:
        if "/Transaction/" in url:
            return {"orderIds": [ORDER_ID]}
        return status

    with pytest.raises(TrackingError, match="order ID mismatch"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_status_with_mismatched_source_transaction() -> None:
    status = _fulfilled_status()
    status["createdSrcEventMetadata"] = {
        "transactionHash": _value("0x" + "ee" * 32),
        "initiator": _value(SIGNER),
    }

    def get(url: str) -> object:
        if "/Transaction/" in url:
            return {"orderIds": [ORDER_ID]}
        return status

    with pytest.raises(TrackingError, match="source transaction mismatch"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_status_with_wrong_destination_recipient() -> None:
    status = _fulfilled_status()
    status["receiverDst"] = _value("0x" + "ee" * 20)

    def get(url: str) -> object:
        if "/Transaction/" in url:
            return {"orderIds": [ORDER_ID]}
        return status

    with pytest.raises(TrackingError, match="destination receiver mismatch"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_destination_amount_below_approved_minimum() -> None:
    status = _fulfilled_status()
    status["takeOfferWithMetadata"] = {
        "chainId": _value("4663"),
        "tokenAddress": _value("0x" + "00" * 20),
        "finalAmount": _value("899"),
    }

    def get(url: str) -> object:
        if "/Transaction/" in url:
            return {"orderIds": [ORDER_ID]}
        return status

    with pytest.raises(TrackingError, match="amount is below minimum"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_endpoint_with_query_parameters() -> None:
    with pytest.raises(ValueError, match="absolute HTTPS base URL"):
        DeBridgeTrackingClient("https://tracking.example/api?secret=value", lambda _url: {})


def test_tracking_rejects_non_object_order_index() -> None:
    client = DeBridgeTrackingClient("https://tracking.example/api", lambda _url: [])

    with pytest.raises(TrackingError, match="order index must be an object"):
        client.discover_fulfillment(_plan(), SOURCE_TX)


def test_tracking_rejects_order_index_without_order_ids() -> None:
    client = DeBridgeTrackingClient("https://tracking.example/api", lambda _url: {})

    with pytest.raises(TrackingError, match="missing order IDs"):
        client.discover_fulfillment(_plan(), SOURCE_TX)


def test_tracking_rejects_missing_order_state() -> None:
    status = _fulfilled_status()
    status.pop("state")

    def get(url: str) -> object:
        return {"orderIds": [ORDER_ID]} if "/Transaction/" in url else status

    with pytest.raises(TrackingError, match="order state is missing"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_reports_created_order_as_pending() -> None:
    status = _fulfilled_status()
    status["state"] = "Created"

    def get(url: str) -> object:
        return {"orderIds": [ORDER_ID]} if "/Transaction/" in url else status

    with pytest.raises(TrackingPending) as error:
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )

    assert error.value.state == "Created"


def test_tracking_rejects_wrong_source_initiator() -> None:
    status = _fulfilled_status()
    status["createdSrcEventMetadata"] = {
        "transactionHash": _value(SOURCE_TX),
        "initiator": _value("0x" + "ee" * 20),
    }

    def get(url: str) -> object:
        return {"orderIds": [ORDER_ID]} if "/Transaction/" in url else status

    with pytest.raises(TrackingError, match="source initiator mismatch"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_non_numeric_source_chain() -> None:
    status = _fulfilled_status()
    status["giveOfferWithMetadata"] = {"chainId": _value("not-a-chain")}

    def get(url: str) -> object:
        return {"orderIds": [ORDER_ID]} if "/Transaction/" in url else status

    with pytest.raises(TrackingError, match="source chain is invalid"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_zero_destination_amount() -> None:
    status = _fulfilled_status()
    status["takeOfferWithMetadata"] = {
        "chainId": _value("4663"),
        "tokenAddress": _value("0x" + "00" * 20),
        "finalAmount": _value("0"),
    }

    def get(url: str) -> object:
        return {"orderIds": [ORDER_ID]} if "/Transaction/" in url else status

    with pytest.raises(TrackingError, match="destination amount is invalid"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_wrong_source_authority() -> None:
    status = _fulfilled_status()
    status["givePatchAuthoritySrc"] = _value("0x" + "ee" * 20)

    def get(url: str) -> object:
        return {"orderIds": [ORDER_ID]} if "/Transaction/" in url else status

    with pytest.raises(TrackingError, match="source authority mismatch"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_wrong_destination_authority() -> None:
    status = _fulfilled_status()
    status["orderAuthorityAddressDst"] = _value("0x" + "ee" * 20)

    def get(url: str) -> object:
        return {"orderIds": [ORDER_ID]} if "/Transaction/" in url else status

    with pytest.raises(TrackingError, match="destination authority mismatch"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_wrong_source_chain() -> None:
    status = _fulfilled_status()
    status["giveOfferWithMetadata"] = {"chainId": _value("1")}

    def get(url: str) -> object:
        return {"orderIds": [ORDER_ID]} if "/Transaction/" in url else status

    with pytest.raises(TrackingError, match="source chain mismatch"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_wrong_destination_chain() -> None:
    status = _fulfilled_status()
    status["takeOfferWithMetadata"] = {
        "chainId": _value("1"),
        "tokenAddress": _value("0x" + "00" * 20),
        "finalAmount": _value("950"),
    }

    def get(url: str) -> object:
        return {"orderIds": [ORDER_ID]} if "/Transaction/" in url else status

    with pytest.raises(TrackingError, match="destination chain mismatch"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_wrong_destination_token() -> None:
    status = _fulfilled_status()
    status["takeOfferWithMetadata"] = {
        "chainId": _value("4663"),
        "tokenAddress": _value("0x" + "ee" * 20),
        "finalAmount": _value("950"),
    }

    def get(url: str) -> object:
        return {"orderIds": [ORDER_ID]} if "/Transaction/" in url else status

    with pytest.raises(TrackingError, match="destination token mismatch"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )


def test_tracking_rejects_invalid_destination_transaction_hash() -> None:
    status = _fulfilled_status()
    status["fulfilledDstEventMetadata"] = {"transactionHash": _value("0xnot-a-hash")}

    def get(url: str) -> object:
        return {"orderIds": [ORDER_ID]} if "/Transaction/" in url else status

    with pytest.raises(TrackingError, match="destination transaction hash is invalid"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            _plan(), SOURCE_TX
        )
