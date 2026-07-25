"""Failure-safety tests for public execution and custody boundaries."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from eth_account import Account

from agent_bridge_guard.artifacts import ArtifactError, ArtifactPathError, read_json_object
from agent_bridge_guard.http import HttpTransportError, _default_transport, get_json
from agent_bridge_guard.models import Plan
from agent_bridge_guard.rpc import (
    NeedsReconciliationError,
    RpcClient,
    RpcConfigurationError,
    RpcDisagreementError,
    RpcPool,
    RpcProtocolError,
    RpcRemoteError,
    RpcTransportError,
    wait_for_final_receipt,
)
from agent_bridge_guard.signers import DetachedSigner, LocalKeystoreSigner, TurnkeySigner
from agent_bridge_guard.signers.base import eth_account_transaction, normalize_transaction
from agent_bridge_guard.store import (
    OperationState,
    PrivateStoragePathError,
    SQLiteOperationStore,
    StateTransitionError,
)
from agent_bridge_guard.wallets.twak import TWAKAdapter

HASH = "0x" + "ab" * 32
BLOCK_HASH = "0x" + "cd" * 32


def transaction() -> dict[str, object]:
    return {
        "chain_id": 42161,
        "nonce": 7,
        "to": "0x1111111111111111111111111111111111111111",
        "value": 42,
        "data": "0x1234",
        "gas": 800_000,
        "max_fee_per_gas": 30_000_000,
        "max_priority_fee_per_gas": 1_000_000,
    }


def plan() -> Plan:
    return Plan.create(
        {
            "created_at": "2026-07-24T21:50:00Z",
            "intent": {"amount_wei": 1},
            "unsigned_transaction": {"chain_id": 42161, "nonce": 7},
        }
    )


def reserve(store: SQLiteOperationStore) -> str:
    return store.reserve_operation(
        plan(),
        idempotency_key="boundary-request",
        approval_id="boundary-approval",
        signer="0x1111111111111111111111111111111111111111",
        source_chain_id=42161,
        nonce=7,
    ).operation_id


def rpc_replies(*values: object):
    pending = list(values)

    def transport(_url: str, body: bytes, _timeout: float) -> bytes:
        request = json.loads(body)
        value = pending.pop(0)
        if isinstance(value, bytes):
            return value
        return json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": value}).encode()

    return transport


def receipt(*, block_hash: str = BLOCK_HASH, status: str = "0x1") -> dict[str, object]:
    return {
        "transactionHash": HASH,
        "status": status,
        "blockNumber": "0xa",
        "blockHash": block_hash,
        "logs": [],
    }


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("chain_id", True, "chain_id"),
        ("gas", 0, "gas"),
        ("max_fee_per_gas", 1, "max_fee_per_gas"),
        ("data", "0x1", "data"),
    ],
)
def test_transaction_normalization_rejects_ambiguous_execution_inputs(
    field: str, value: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        normalize_transaction({**transaction(), field: value})


def test_rpc_remote_errors_redact_the_server_message_and_default_transport_bounds_response(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "DO_NOT_LEAK_RPC_PRIVATE_PATH"

    def remote_error(_url: str, body: bytes, _timeout: float) -> bytes:
        request = json.loads(body)
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request["id"],
                "error": {"code": -32000, "message": canary},
            }
        ).encode()

    with pytest.raises(RpcRemoteError) as error:
        RpcClient("https://rpc.example.test/private", transport=remote_error).chain_id()
    assert canary not in str(error.value)
    assert canary not in vars(error.value).values()

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, limit: int) -> bytes:
            assert limit == 3
            return b"abc"

    monkeypatch.setattr("agent_bridge_guard.rpc.urlopen", lambda *_args, **_kwargs: Response())
    with pytest.raises(RpcProtocolError, match="byte limit"):
        RpcClient("https://rpc.example.test", max_response_bytes=2).chain_id()


def test_rpc_transport_failure_never_echoes_private_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = "https://rpc.example.test/private-token"

    def fail(*_args: object, **_kwargs: object) -> object:
        raise OSError(endpoint)

    monkeypatch.setattr("agent_bridge_guard.rpc.urlopen", fail)
    with pytest.raises(RpcTransportError) as error:
        RpcClient(endpoint).chain_id()
    assert "private-token" not in str(error.value)


def test_finality_rejects_head_before_receipt_block() -> None:
    rpc = RpcClient(
        "https://rpc.example.test",
        transport=rpc_replies(receipt(), "0x9"),
    )

    with pytest.raises(NeedsReconciliationError, match="precedes"):
        wait_for_final_receipt(rpc, HASH, 1, max_polls=2)


def test_finality_rejects_malformed_canonical_block_hash() -> None:
    rpc = RpcClient(
        "https://rpc.example.test",
        transport=rpc_replies(receipt(), "0xa", receipt(), {"hash": "0x12"}),
    )

    with pytest.raises(RpcProtocolError, match="32-byte"):
        wait_for_final_receipt(rpc, HASH, 0, max_polls=2)


def test_store_rejects_symlinked_database_and_freezes_prepared_transaction(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    target = private / "target.db"
    target.write_bytes(b"")
    os.chmod(target, 0o600)
    database = private / "operations.db"
    database.symlink_to(target)
    with pytest.raises(PrivateStoragePathError, match="symlink"):
        SQLiteOperationStore(database)

    store = SQLiteOperationStore(tmp_path / "fresh" / "operations.db")
    operation_id = reserve(store)
    with pytest.raises(StateTransitionError, match="fenced claim"):
        store.prepare_broadcast(operation_id, b"\x01")
    claim = store.claim_preparation(
        operation_id,
        kind="test-eip1559",
        fingerprint="exact-transaction",
        replay_safe=True,
    )
    assert claim.token is not None
    first = store.complete_preparation(operation_id, claim.token, b"\x01")
    assert first.raw_signed_tx == b"\x01"
    assert store.complete_preparation(operation_id, "stale-token", b"\x02") == first
    assert store.get_operation(operation_id).raw_signed_tx == b"\x01"
    with pytest.raises(StateTransitionError, match="not permitted|proof-bearing state"):
        store.append_state_event(operation_id, OperationState.VERIFIED)


def test_detached_signer_rejects_non_eip1559_raw_transaction_without_echoing_bytes() -> None:
    raw = "0xdeadbeef"
    with pytest.raises(ValueError) as error:
        DetachedSigner("0x1111111111111111111111111111111111111111").import_signed_transaction(
            transaction(), raw
        )
    assert raw not in str(error.value)


def test_local_keystore_rejects_symlinked_secret_files(tmp_path: Path) -> None:
    account = Account.create()
    actual_keyfile = tmp_path / "actual.json"
    password = tmp_path / "password"
    actual_keyfile.write_text(
        json.dumps(Account.encrypt(account.key, "password")), encoding="utf-8"
    )
    password.write_text("password", encoding="utf-8")
    os.chmod(actual_keyfile, 0o600)
    os.chmod(password, 0o600)
    linked_keyfile = tmp_path / "linked.json"
    linked_keyfile.symlink_to(actual_keyfile)

    with pytest.raises(ValueError, match="symlink"):
        LocalKeystoreSigner(linked_keyfile, password)


def test_turnkey_import_is_lazy_and_missing_dependency_hides_private_key(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "DO_NOT_LEAK_TURNKEY_PRIVATE_KEY"
    calls: list[str] = []

    def missing(module: str) -> object:
        calls.append(module)
        raise ImportError(canary)

    monkeypatch.setattr("agent_bridge_guard.signers.turnkey.importlib.import_module", missing)
    with pytest.raises(RuntimeError) as error:
        TurnkeySigner("org", "public", canary)

    assert calls == ["turnkey_api_key_stamper"]
    assert canary not in str(error.value)


def test_twak_default_runner_passes_password_only_in_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "twak"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
    password = "DO_NOT_LEAK_TWAK_PASSWORD"  # noqa: S105 -- redaction canary
    unrelated_secret = "DO_NOT_LEAK_UNRELATED_SECRET"  # noqa: S105 -- redaction canary
    observed: dict[str, object] = {}

    def completed(command: list[str], **kwargs: object) -> SimpleNamespace:
        observed["command"] = command
        observed["environment"] = kwargs["env"]
        observed["timeout"] = kwargs["timeout"]
        observed["pass_fds"] = kwargs["pass_fds"]
        return SimpleNamespace(returncode=0, stdout='{"ready": true}', stderr="")

    monkeypatch.setattr("agent_bridge_guard.wallets.twak.subprocess.run", completed)
    result = TWAKAdapter(executable, executable_sha256).readiness(
        {"TWAK_WALLET_PASSWORD": password, "UNRELATED_SECRET": unrelated_secret}
    )

    assert result == {"ready": True}
    command = observed["command"]
    assert isinstance(command, list)
    assert command[0].startswith("/proc/self/fd/")
    assert command[1:] == ["wallet", "status", "--json"]
    assert len(observed["pass_fds"]) == 1  # type: ignore[arg-type]
    assert observed["environment"] == {}
    assert observed["timeout"] == 5.0
    assert password not in command
    assert unrelated_secret not in observed["environment"]


def test_artifact_read_rejects_symlink_oversize_and_non_object_inputs(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(target)
    with pytest.raises(ArtifactPathError, match="owner-only regular"):
        read_json_object(linked)

    oversized = tmp_path / "large.json"
    oversized.write_text("{}", encoding="utf-8")
    os.chmod(oversized, 0o600)
    with pytest.raises(ArtifactPathError, match="byte limit"):
        read_json_object(oversized, max_bytes=1)

    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")
    os.chmod(array, 0o600)
    with pytest.raises(ArtifactError, match="object"):
        read_json_object(array)


def test_default_http_transport_redacts_network_errors_and_preserves_json_headers(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint = "https://example.test/private-token"

    def fail(*_args: object, **_kwargs: object) -> object:
        raise OSError(endpoint)

    monkeypatch.setattr("agent_bridge_guard.http.urlopen", fail)
    with pytest.raises(HttpTransportError) as error:
        _default_transport(endpoint, 1.0, 8)
    assert "private-token" not in str(error.value)

    class Response:
        headers = {"Content-Type": "application/json; charset=utf-8"}

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, limit: int) -> bytes:
            assert limit == 9
            return b'{"ok":1}'

    captured: dict[str, object] = {}

    def succeed(request: object, **_kwargs: object) -> Response:
        captured["request"] = request
        return Response()

    monkeypatch.setattr("agent_bridge_guard.http.urlopen", succeed)
    assert get_json(endpoint, max_response_bytes=8) == {"ok": 1}
    request = captured["request"]
    assert request.get_header("Accept") == "application/json"  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("reply", "message"),
    [
        (b"[]", "must be an object"),
        (b'{"jsonrpc":"2.0","id":1,"result":NaN}', "invalid JSON"),
        (b'{"jsonrpc":"2.0","id":1,"result":1.5}', "floating-point"),
        (b'{"jsonrpc":"2.0","id":1}', "exactly one"),
    ],
)
def test_rpc_rejects_malformed_wire_replies(reply: bytes, message: str) -> None:
    with pytest.raises(RpcProtocolError, match=message):
        RpcClient("https://rpc.example.test", transport=rpc_replies(reply)).chain_id()


@pytest.mark.parametrize(
    ("method", "params", "message"),
    [
        ("", [], "method"),
        ("eth_chainId", [], "byte limit"),
    ],
)
def test_rpc_rejects_invalid_calls_before_trusting_the_network(
    method: str, params: list[object], message: str
) -> None:
    rpc = RpcClient(
        "https://rpc.example.test",
        max_request_bytes=4 if message == "byte limit" else 128 * 1024,
        transport=rpc_replies("0x1"),
    )
    with pytest.raises((ValueError, RpcProtocolError), match=message):
        rpc.call(method, params)


@pytest.mark.parametrize("endpoint", ["https://rpc.example.test/#fragment", "https:///missing"])
def test_rpc_rejects_ambiguous_endpoint_forms(endpoint: str) -> None:
    with pytest.raises(Exception, match="endpoint"):
        RpcClient(endpoint)


def test_rpc_rejects_malformed_transaction_hash_and_result_object() -> None:
    rpc = RpcClient("https://rpc.example.test", transport=rpc_replies("0x12", []))
    with pytest.raises(RpcProtocolError, match="32-byte"):
        rpc.send_raw_transaction("0x1234")
    with pytest.raises(RpcProtocolError, match="object or null"):
        rpc.transaction_by_hash(HASH)


def test_finality_rejects_disappearing_receipt_and_invalid_arguments() -> None:
    rpc = RpcClient("https://rpc.example.test", transport=rpc_replies(receipt(), "0xa", None))
    with pytest.raises(NeedsReconciliationError, match="disappeared"):
        wait_for_final_receipt(rpc, HASH, 0, max_polls=2)
    with pytest.raises(ValueError, match="confirmations"):
        wait_for_final_receipt(rpc, HASH, True)
    with pytest.raises(ValueError, match="poll interval"):
        wait_for_final_receipt(rpc, HASH, 0, poll_interval=-1)


def test_turnkey_available_optional_imports_still_refuses_unimplemented_signing(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    imported: list[str] = []

    def available(module: str) -> object:
        imported.append(module)
        return SimpleNamespace()

    monkeypatch.setattr("agent_bridge_guard.signers.turnkey.importlib.import_module", available)
    signer = TurnkeySigner("organization", "public-key", "private-key")
    assert imported == ["turnkey_api_key_stamper", "turnkey_http", "turnkey_sdk_types"]
    with pytest.raises(RuntimeError, match="configured wallet"):
        _ = signer.address
    with pytest.raises(RuntimeError, match="not enabled"):
        signer.sign_transaction(transaction())


@pytest.mark.parametrize(
    ("status", "stdout", "message"),
    [
        (1, "{}", "failed"),
        (0, "not-json", "non-JSON"),
        (0, "[]", "non-object"),
    ],
)
def test_twak_failures_do_not_fall_through_to_live_signing(
    tmp_path: Path, status: int, stdout: str, message: str
) -> None:
    password = "DO_NOT_LEAK_TWAK_PASSWORD"  # noqa: S105 -- intentional redaction canary
    executable = tmp_path / "twak"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()

    def runner(
        _command: list[str], _environment: dict[str, str], _timeout: float
    ) -> tuple[int, str, str]:
        return status, stdout, password

    with pytest.raises(RuntimeError, match=message) as error:
        TWAKAdapter(executable, executable_sha256, runner=runner).readiness(
            {"TWAK_WALLET_PASSWORD": password}
        )
    assert password not in str(error.value)


def test_artifact_read_accepts_private_object_and_rejects_missing_path(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text('{"ok": true}', encoding="utf-8")
    os.chmod(artifact, 0o600)
    assert read_json_object(artifact) == {"ok": True}
    with pytest.raises(ArtifactPathError, match="unavailable"):
        read_json_object(tmp_path / "missing.json")


def test_public_receipt_rejects_private_event_shape(tmp_path: Path) -> None:
    from agent_bridge_guard.artifacts import PrivateArtifactStore

    store = PrivateArtifactStore(tmp_path / "private")
    with pytest.raises(ArtifactError, match="events must be a list"):
        store.write_public_receipt("receipt.json", {"events": {}})
    with pytest.raises(ArtifactError, match="event must be an object"):
        store.write_public_receipt("receipt-with-list.json", {"events": ["bad"]})


@pytest.mark.parametrize(
    ("candidate", "message"),
    [
        ({k: v for k, v in transaction().items() if k != "nonce"}, "missing: nonce"),
        ({**transaction(), "gas_price": 1}, "unexpected: gas_price"),
        ({**transaction(), "to": "not-an-address"}, "EVM address"),
        ({**transaction(), "data": "not-hex"}, "0x-prefixed"),
    ],
)
def test_transaction_boundary_requires_exact_known_fields(
    candidate: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        normalize_transaction(candidate)


def test_eth_account_translation_uses_only_eip1559_wire_names() -> None:
    translated = eth_account_transaction(normalize_transaction(transaction()))
    assert translated == {
        "type": 2,
        "chainId": 42161,
        "nonce": 7,
        "to": "0x1111111111111111111111111111111111111111",
        "value": 42,
        "data": "0x1234",
        "gas": 800_000,
        "maxFeePerGas": 30_000_000,
        "maxPriorityFeePerGas": 1_000_000,
    }


def test_detached_signer_rejects_a_valid_signature_from_another_wallet(tmp_path: Path) -> None:
    account = Account.create()
    keyfile = tmp_path / "signer.json"
    password = tmp_path / "password"
    keyfile.write_text(json.dumps(Account.encrypt(account.key, "password")), encoding="utf-8")
    password.write_text("password", encoding="utf-8")
    os.chmod(keyfile, 0o600)
    os.chmod(password, 0o600)
    signed = LocalKeystoreSigner(keyfile, password).sign_transaction(transaction())

    with pytest.raises(ValueError, match="signer does not match"):
        DetachedSigner("0x2222222222222222222222222222222222222222").import_signed_transaction(
            transaction(), signed.raw_transaction
        )


def test_rpc_rejects_bad_quantities_hashes_and_invalid_block_number() -> None:
    bad_quantity = RpcClient("https://rpc.example.test", transport=rpc_replies("0xzz"))
    with pytest.raises(RpcProtocolError, match="hex quantity"):
        bad_quantity.chain_id()

    bad_hash = RpcClient("https://rpc.example.test", transport=rpc_replies({}))
    with pytest.raises(RpcProtocolError, match="transaction hash"):
        bad_hash.send_raw_transaction("0x1234")

    with pytest.raises(ValueError, match="block number"):
        RpcClient("https://rpc.example.test", transport=rpc_replies(None)).block(True)


def test_finality_refuses_incomplete_or_changed_canonical_evidence() -> None:
    disappeared = RpcClient(
        "https://rpc.example.test", transport=rpc_replies(receipt(), "0xa", None)
    )
    with pytest.raises(NeedsReconciliationError, match="disappeared"):
        wait_for_final_receipt(disappeared, HASH, 0, max_polls=2)

    changed_status = RpcClient(
        "https://rpc.example.test", transport=rpc_replies(receipt(), "0xa", receipt(status="0x0"))
    )
    with pytest.raises(NeedsReconciliationError, match="status changed"):
        wait_for_final_receipt(changed_status, HASH, 0, max_polls=2)

    unavailable_block = RpcClient(
        "https://rpc.example.test", transport=rpc_replies(receipt(), "0xa", receipt(), None)
    )
    with pytest.raises(NeedsReconciliationError, match="canonical block was unavailable"):
        wait_for_final_receipt(unavailable_block, HASH, 0, max_polls=2)

    replaced_block = RpcClient(
        "https://rpc.example.test",
        transport=rpc_replies(receipt(), "0xa", receipt(), {"hash": "0x" + "ef" * 32}),
    )
    with pytest.raises(NeedsReconciliationError, match="no longer canonical"):
        wait_for_final_receipt(replaced_block, HASH, 0, max_polls=2)


def test_finality_poll_limit_never_promotes_underconfirmed_transaction() -> None:
    rpc = RpcClient("https://rpc.example.test", transport=rpc_replies(receipt(), "0xa"))
    with pytest.raises(NeedsReconciliationError, match="did not reach"):
        wait_for_final_receipt(rpc, HASH, 1, max_polls=1)


def test_finality_pool_requires_secondary_receipt_and_block_evidence() -> None:
    primary = RpcClient(
        "https://primary.example.test",
        transport=rpc_replies("0xa4b1", receipt(), "0xa", receipt(), {"hash": BLOCK_HASH}),
    )
    missing_receipt = RpcClient(
        "https://secondary.example.test", transport=rpc_replies("0xa4b1", "0xa", None)
    )
    with pytest.raises(RpcDisagreementError, match="did not observe"):
        wait_for_final_receipt(RpcPool(primary, missing_receipt, 42161), HASH, 0, max_polls=2)

    primary = RpcClient(
        "https://primary.example.test",
        transport=rpc_replies("0xa4b1", receipt(), "0xa", receipt(), {"hash": BLOCK_HASH}),
    )
    missing_block = RpcClient(
        "https://secondary.example.test",
        transport=rpc_replies("0xa4b1", "0xa", receipt(), None),
    )
    with pytest.raises(RpcDisagreementError, match="canonical block was unavailable"):
        wait_for_final_receipt(RpcPool(primary, missing_block, 42161), HASH, 0, max_polls=2)


@pytest.mark.parametrize(
    ("result", "message"),
    [
        ("0x", "hex quantity"),
        ("0x-1", "negative"),
        ("0xzz", "hex quantity"),
    ],
)
def test_rpc_quantity_methods_reject_noncanonical_server_numbers(result: str, message: str) -> None:
    with pytest.raises(RpcProtocolError, match=message):
        RpcClient("https://rpc.example.test", transport=rpc_replies(result)).chain_id()


@pytest.mark.parametrize(
    ("raw_transaction", "message"),
    [("0x", "complete hex"), ("0x1", "complete hex"), ("0xzz", "hex bytes")],
)
def test_rpc_rejects_malformed_raw_transaction_before_broadcast(
    raw_transaction: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        RpcClient("https://rpc.example.test", transport=rpc_replies(HASH)).send_raw_transaction(
            raw_transaction
        )


@pytest.mark.parametrize(
    ("reply", "message"),
    [
        (
            b'{"jsonrpc":"2.0","id":1,"error":{"code":"bad","message":"error"}}',
            "error schema",
        ),
        (
            b'{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":3}}',
            "error schema",
        ),
        (b'{"jsonrpc":"2.0","id":1,"result":"0x1","extra":true}', "schema"),
    ],
)
def test_rpc_rejects_malformed_server_error_shapes(reply: bytes, message: str) -> None:
    with pytest.raises(RpcProtocolError, match=message):
        RpcClient("https://rpc.example.test", transport=rpc_replies(reply)).chain_id()


def test_rpc_configuration_rejects_nonlocal_http_and_invalid_limits() -> None:
    with pytest.raises(RpcConfigurationError, match="HTTPS"):
        RpcClient("http://not-local.example.test", allow_insecure_localhost=True)
    with pytest.raises(ValueError, match="positive"):
        RpcClient("https://rpc.example.test", timeout=0)


def test_finality_waits_then_stops_at_poll_limit_without_promoting_receipt() -> None:
    rpc = RpcClient(
        "https://rpc.example.test",
        transport=rpc_replies(receipt(), "0xa", "0xa"),
    )
    sleeps: list[float] = []
    with pytest.raises(NeedsReconciliationError, match="did not reach"):
        wait_for_final_receipt(rpc, HASH, 1, max_polls=3, sleep=sleeps.append)
    assert sleeps == [1.0]


def test_finality_pool_rejects_secondary_canonical_hash_mismatch() -> None:
    primary = RpcClient(
        "https://primary.example.test",
        transport=rpc_replies("0xa4b1", receipt(), "0xa", receipt(), {"hash": BLOCK_HASH}),
    )
    secondary = RpcClient(
        "https://secondary.example.test",
        transport=rpc_replies("0xa4b1", "0xa", receipt(), {"hash": "0x" + "ef" * 32}),
    )
    with pytest.raises(RpcDisagreementError, match="canonical block disagreement"):
        wait_for_final_receipt(RpcPool(primary, secondary, 42161), HASH, 0, max_polls=2)


@pytest.mark.parametrize(
    ("decoded", "message"),
    [({"type": 1}, "not EIP-1559"), ({"type": 2, "to": "not-bytes", "data": b""}, "fields")],
)
def test_detached_decoder_rejects_non_eip1559_or_nonbyte_fields(
    decoded: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        DetachedSigner._decoded_transaction(decoded)


def test_local_keystore_rejects_missing_directory_and_foreign_owned_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    password = tmp_path / "password"
    password.write_text("password", encoding="utf-8")
    os.chmod(password, 0o600)
    with pytest.raises(ValueError, match="unavailable"):
        LocalKeystoreSigner(tmp_path / "missing.json", password)

    directory = tmp_path / "not-a-file"
    directory.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        LocalKeystoreSigner(directory, password)

    account = Account.create()
    keyfile = tmp_path / "signer.json"
    keyfile.write_text(json.dumps(Account.encrypt(account.key, "password")), encoding="utf-8")
    os.chmod(keyfile, 0o600)
    monkeypatch.setattr("agent_bridge_guard.signers.local_keystore.os.getuid", lambda: -1)
    with pytest.raises(PermissionError, match="owned"):
        LocalKeystoreSigner(keyfile, password)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.__setitem__("schema_version", 1), "unsupported approval schema"),
        (lambda value: value.__setitem__("signature", 7), "signature must be a string"),
        (lambda value: value.__setitem__("approval_id", "eip191:" + "00" * 32), "approval_id"),
        (lambda value: value.__setitem__("subject_signer", "0x" + "00" * 20), "zero address"),
    ],
)
def test_approval_artifact_parser_rejects_schema_identity_and_subject_tampering(
    mutate: object, message: str
) -> None:
    from test_approval import plan as approval_plan
    from test_approval import signed_approval

    document = signed_approval(plan_id=approval_plan().plan_id).to_dict()
    mutate(document)  # type: ignore[operator]
    from agent_bridge_guard.approval import Approval, ApprovalError

    with pytest.raises(ApprovalError, match=message):
        Approval.parse(document)


def test_approval_signing_request_rejects_noncanonical_and_untrusted_inputs() -> None:
    from test_approval import ISSUER, SUBJECT_SIGNER
    from test_approval import plan as approval_plan

    from agent_bridge_guard.approval import ApprovalError, ApprovalSigningRequest

    request = ApprovalSigningRequest.create(
        plan_id=approval_plan().plan_id,
        authorization_id="boundary-approval",
        actor="boundary-agent",
        subject_signer=SUBJECT_SIGNER,
        approved_at="2026-07-24T21:51:00Z",
        expires_at="2026-07-24T21:55:00Z",
        allowed_issuers=frozenset({ISSUER}),
    )
    noncanonical = request.to_dict()
    noncanonical["allowed_issuers"] = [ISSUER.lower()]
    with pytest.raises(ApprovalError, match="not canonical"):
        ApprovalSigningRequest.parse(noncanonical)

    with pytest.raises(ApprovalError, match="allowlist is required"):
        ApprovalSigningRequest.create(
            plan_id=request.plan_id,
            authorization_id=request.authorization_id,
            actor=request.actor,
            subject_signer=request.subject_signer,
            approved_at=request.approved_at,
            expires_at=request.expires_at,
            allowed_issuers=frozenset(),
        )


def test_engine_refuses_invalid_reservations_and_unsigned_resume(tmp_path: Path) -> None:
    from test_engine import NOW, MemorySigner, approval_for, engine, make_plan

    from agent_bridge_guard.engine import NeedsReconciliation, PreBroadcastFailure

    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer)
    candidate = make_plan(signer.address)
    approval = approval_for(candidate, subject_signer=signer.address)
    with pytest.raises(ValueError, match="idempotency"):
        guard.reserve(candidate, approval, idempotency_key="not allowed spaces", at=NOW)

    pool.chain_id = 1
    with pytest.raises(NeedsReconciliation, match="source RPC chain"):
        guard.reserve(candidate, approval, idempotency_key="wrong-chain", at=NOW)
    pool.chain_id = 42161

    reserved = guard.reserve(candidate, approval, idempotency_key="unsigned", at=NOW)
    with pytest.raises(PreBroadcastFailure, match="waiting for a signature"):
        guard.resume(reserved.operation_id)


def test_engine_external_signature_path_fails_closed_and_never_broadcasts(tmp_path: Path) -> None:
    from test_engine import NOW, MemorySigner, approval_for, engine, make_plan

    from agent_bridge_guard.engine import PreBroadcastFailure
    from agent_bridge_guard.store import OperationState

    signer = MemorySigner()
    guard, pool = engine(tmp_path, signer)
    candidate = make_plan(signer.address)
    approval = approval_for(candidate, subject_signer=signer.address)
    with pytest.raises(PreBroadcastFailure):
        guard.prepare_external(
            candidate,
            approval,
            b"not-a-signed-transaction",
            idempotency_key="bad-detached-signature",
            at=NOW,
        )
    operation = guard.store.get_operation_by_idempotency_key("bad-detached-signature")
    assert operation.state is OperationState.RESERVED
    assert pool.primary.sent == []


def test_engine_destination_gate_rejects_nonpositive_confirmations_before_rpc(
    tmp_path: Path,
) -> None:
    from test_engine_edges import order_pending_operation


    guard, pool, operation = order_pending_operation(tmp_path)
    with pytest.raises(ValueError, match="confirmations"):
        guard.verify_destination(
            operation.operation_id,
            destination_transaction_hash=HASH,
            destination_rpc=pool,  # type: ignore[arg-type]
            confirmations=0,
        )
    assert guard.store.get_operation(operation.operation_id).state is OperationState.ORDER_PENDING


def test_engine_destination_skips_nonobject_logs_before_failing_closed(tmp_path: Path) -> None:
    from test_engine_edges import order_pending_operation

    from agent_bridge_guard.engine import DestinationVerificationError

    guard, pool, operation = order_pending_operation(
        tmp_path,
        finality_waiter=lambda *_args, **_kwargs: {
            "transactionHash": HASH,
            "blockNumber": "0x1",
            "blockHash": BLOCK_HASH,
            "status": "0x1",
            "logs": ["untrusted", 7],
        },
    )
    with pytest.raises(DestinationVerificationError, match="exactly one"):
        guard.verify_destination(
            operation.operation_id,
            destination_transaction_hash=HASH,
            destination_rpc=pool,  # type: ignore[arg-type]
            confirmations=1,
        )
