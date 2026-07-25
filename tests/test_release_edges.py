from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_authorization import direct_route_document
from test_cli_config_tracking_edges import _operation, _settings
from test_config import write_config
from test_route_manifest import manifest as legacy_route_document
from test_twak import pinned_executable

from agent_bridge_guard import artifacts, cli, config
from agent_bridge_guard.artifacts import ArtifactError, ArtifactPathError, PrivateArtifactStore
from agent_bridge_guard.config import ConfigError
from agent_bridge_guard.models import Plan
from agent_bridge_guard.route_manifest import RouteManifest, RouteManifestError
from agent_bridge_guard.wallets import twak
from agent_bridge_guard.wallets.twak import TWAKAdapter


def private_file(tmp_path: Path, name: str, data: bytes) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    path = root / name
    path.write_bytes(data)
    path.chmod(0o600)
    return path.resolve()


def test_config_validation_edges_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "config-dir"
    directory.mkdir(mode=0o700)
    with pytest.raises(ConfigError, match="regular file"):
        config.load_config(directory.resolve())

    candidate = tmp_path / "config.toml"
    write_config(candidate)
    real_uid = os.getuid()
    monkeypatch.setattr(config.os, "getuid", lambda: real_uid + 1)
    with pytest.raises(ConfigError, match="owned by the current user"):
        config.load_config(candidate.resolve())
    monkeypatch.setattr(config.os, "getuid", lambda: real_uid)

    candidate.write_bytes(b"x" * (config.MAX_CONFIG_BYTES + 1))
    candidate.chmod(0o600)
    with pytest.raises(ConfigError, match="size limit"):
        config.load_config(candidate.resolve())

    with pytest.raises(ConfigError, match="must be a table"):
        config._table([], "value")
    with pytest.raises(ConfigError, match="non-empty string"):
        config._string("", "value")
    with pytest.raises(ConfigError, match="positive integer"):
        config._positive_int(True, "value")
    with pytest.raises(ConfigError, match="invalid"):
        config._safe_url("https://rpc.example:99999", "rpc")


def test_config_schema_and_empty_chains_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "config.toml"
    write_config(candidate)

    monkeypatch.setattr(
        config.tomllib,
        "loads",
        lambda _text: {"database": {}, "provider": {}, "chains": {}, "extra": {}},
    )
    with pytest.raises(ConfigError, match="fields do not match schema"):
        config.load_config(candidate.resolve())

    monkeypatch.setattr(
        config.tomllib,
        "loads",
        lambda _text: {
            "database": {"path": str((tmp_path / "operations.sqlite3").resolve())},
            "provider": {
                "debridge": {
                    "create_tx_url": "https://quote.example",
                    "tracking_url": "https://tracking.example",
                }
            },
            "chains": {},
        },
    )
    with pytest.raises(ConfigError, match="must not be empty"):
        config.load_config(candidate.resolve())

    monkeypatch.setattr(
        config.tomllib,
        "loads",
        lambda _text: {
            "database": {"path": str((tmp_path / "operations.sqlite3").resolve())},
            "provider": {
                "debridge": {
                    "create_tx_url": "https://quote.example",
                    "tracking_url": "https://tracking.example",
                }
            },
            "chains": {
                "": {
                    "chain_id": 1,
                    "primary_rpc": "https://one.example",
                    "secondary_rpc": "https://two.example",
                }
            },
        },
    )
    with pytest.raises(ConfigError, match="aliases must be non-empty"):
        config.load_config(candidate.resolve())


def test_artifact_reader_and_root_edges_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    regular = tmp_path / "not-a-directory"
    regular.write_text("x", encoding="utf-8")
    regular.chmod(0o700)
    with pytest.raises(ArtifactPathError, match="must be a directory"):
        PrivateArtifactStore(regular.resolve())

    root = tmp_path / "foreign-root"
    root.mkdir(mode=0o700)
    real_uid = os.getuid()
    monkeypatch.setattr(artifacts.os, "getuid", lambda: real_uid + 1)
    with pytest.raises(ArtifactPathError, match="owned by the current user"):
        PrivateArtifactStore(root.resolve())
    monkeypatch.setattr(artifacts.os, "getuid", lambda: real_uid)

    malformed = private_file(tmp_path, "malformed.json", b"{")
    with pytest.raises(ArtifactError, match="not valid JSON"):
        artifacts.read_json_object(malformed)

    parent = tmp_path / "broad-parent"
    parent.mkdir(mode=0o755)
    child = parent / "artifact.json"
    child.write_text("{}", encoding="utf-8")
    child.chmod(0o600)
    with pytest.raises(ArtifactPathError, match="parent must be owner-only"):
        artifacts.read_json_object(child.resolve())

    with pytest.raises(ArtifactError, match="must be an object"):
        artifacts._public_evidence([], frozenset({"chain_id"}), label="evidence")


def test_artifact_os_failures_are_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = private_file(tmp_path, "artifact.json", b"{}")

    def fail_open(_path: object, _flags: int) -> int:
        raise OSError("DO_NOT_LEAK")

    monkeypatch.setattr(artifacts.os, "open", fail_open)
    with pytest.raises(ArtifactPathError, match="artifact is unavailable") as error:
        artifacts.read_private_bytes(candidate)
    assert "DO_NOT_LEAK" not in str(error.value)

    monkeypatch.undo()
    missing_parent = (tmp_path / "missing" / "artifact.json").resolve()
    with pytest.raises(ArtifactPathError, match="parent is unavailable"):
        artifacts._ensure_private_ancestors(missing_parent.parent)


def test_twak_remaining_platform_and_process_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="timeout must be positive"):
        TWAKAdapter(timeout_seconds=0)

    missing = (tmp_path / "missing-twak").resolve()
    with pytest.raises(ValueError, match="executable is unavailable"):
        TWAKAdapter(missing, "0" * 64).readiness()

    executable, digest = pinned_executable(tmp_path)
    monkeypatch.setattr(twak.os, "O_NOFOLLOW", None)
    with pytest.raises(ValueError, match="no-follow"):
        TWAKAdapter(executable, digest).readiness()
    monkeypatch.undo()

    executable, digest = pinned_executable(tmp_path)
    monkeypatch.setattr(twak.os, "fstat", lambda _fd: SimpleNamespace(st_mode=stat.S_IFDIR | 0o700))
    with pytest.raises(ValueError, match="regular non-symlink"):
        TWAKAdapter(executable, digest).readiness()
    monkeypatch.undo()

    executable, digest = pinned_executable(tmp_path)

    def timeout(*_args: object, **_kwargs: object) -> object:
        raise subprocess.TimeoutExpired("twak", 1)

    monkeypatch.setattr(twak.subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="timed out"):
        TWAKAdapter(executable, digest).readiness()
    monkeypatch.undo()

    executable, digest = pinned_executable(tmp_path)
    monkeypatch.setattr(twak.Path, "is_dir", lambda _path: False)
    with pytest.raises(ValueError, match="file-descriptor execution support"):
        TWAKAdapter(executable, digest).readiness()


def test_twak_open_race_is_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, digest = pinned_executable(tmp_path)

    def fail_open(_path: object, _flags: int) -> int:
        raise OSError("DO_NOT_LEAK_TWAK_OPEN_RACE")

    monkeypatch.setattr(twak.os, "open", fail_open)
    with pytest.raises(ValueError, match="executable is unavailable") as error:
        TWAKAdapter(executable, digest).readiness()
    assert "DO_NOT_LEAK" not in str(error.value)


def test_plan_internal_invariants_and_binding_edges() -> None:
    with pytest.raises(TypeError, match="JSON object"):
        Plan.create([])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unsupported plan schema"):
        Plan.create({}, schema_version=3)
    with pytest.raises(TypeError, match="JSON object"):
        Plan.parse([])  # type: ignore[arg-type]

    invalid = Plan("sha256:" + "00" * 32, "{}")
    with pytest.raises(AssertionError, match="unsupported schema"):
        _ = invalid.schema_version

    bound = Plan.create({}, schema_version=2)
    with pytest.raises(ValueError, match="only an unbound"):
        bound.bind_policy({})

    already_bound = Plan.create({"policy_binding": {}})
    with pytest.raises(ValueError, match="already contains"):
        already_bound.bind_policy({})

    non_object = Plan("sha256:" + "00" * 32, "[]")
    with pytest.raises(AssertionError, match="decode to an object"):
        non_object.to_dict()


def test_cli_private_signed_transaction_file_edges(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute"):
        cli._private_signed_bytes("relative")
    with pytest.raises(ValueError, match="cannot be read"):
        cli._private_signed_bytes(str(private_file(tmp_path, "unicode.txt", b"\xff")))
    with pytest.raises(ValueError, match="invalid JSON"):
        cli._private_signed_bytes(str(private_file(tmp_path, "bad.json", b"{")))
    with pytest.raises(ValueError, match="JSON schema"):
        cli._private_signed_bytes(
            str(private_file(tmp_path, "schema.json", b'{"raw_signed_transaction":"0x01","x":1}'))
        )
    with pytest.raises(ValueError, match="0x-prefixed"):
        cli._private_signed_bytes(
            str(private_file(tmp_path, "typed.json", b'{"raw_signed_transaction":1}'))
        )
    with pytest.raises(ValueError, match="0x-prefixed"):
        cli._private_signed_bytes(str(private_file(tmp_path, "prefix.txt", b"01")))
    with pytest.raises(ValueError, match="complete hex"):
        cli._private_signed_bytes(str(private_file(tmp_path, "hex.txt", b"0x0")))
    with pytest.raises(ValueError, match="must not be empty"):
        cli._private_signed_bytes(str(private_file(tmp_path, "empty.txt", b"0x")))


def test_cli_private_approval_signature_file_edges(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot be read"):
        cli._private_signature(str(private_file(tmp_path, "unicode.txt", b"\xff")))
    with pytest.raises(ValueError, match="invalid JSON"):
        cli._private_signature(str(private_file(tmp_path, "bad.json", b"{")))
    with pytest.raises(ValueError, match="JSON schema"):
        cli._private_signature(
            str(private_file(tmp_path, "schema.json", b'{"signature":"0x","x":1}'))
        )
    with pytest.raises(ValueError, match="must be a string"):
        cli._private_signature(str(private_file(tmp_path, "typed.json", b'{"signature":1}')))
    with pytest.raises(ValueError, match="65-byte"):
        cli._private_signature(str(private_file(tmp_path, "short.txt", b"0x01")))


def test_cli_chain_lookup_and_operation_evidence_edges(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with pytest.raises(ConfigError, match="exactly one matching chain"):
        cli._chain_by_id(settings, 1)

    duplicate = replace(
        settings,
        chains={
            "one": settings.chains["source"],
            "two": settings.chains["source"],
        },
    )
    with pytest.raises(ConfigError, match="exactly one matching chain"):
        cli._chain_by_id(duplicate, 42161)

    operation = replace(
        _operation(),
        destination_fulfillment_evidence={"chain_id": 4663, "order_id": "0x" + "ab" * 32},
    )
    result = cli._operation_result(operation)
    assert result["source_finality_evidence"] is not None
    assert result["destination_fulfillment_evidence"] is not None


def test_cli_rejects_bad_explicit_destination_hash_before_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    operation = _operation()

    class Store:
        def __init__(self, _path: Path) -> None:
            pass

        def get_operation(self, _operation_id: str) -> object:
            return operation

    monkeypatch.setattr(cli, "load_config", lambda _path: settings)
    monkeypatch.setattr(cli, "SQLiteOperationStore", Store)
    monkeypatch.setattr(
        cli,
        "_engine_for_operation",
        lambda *_args: (_ for _ in ()).throw(AssertionError("engine touched")),
    )
    with pytest.raises(ValueError, match="destination transaction hash is invalid"):
        cli._cmd_verify_destination(
            SimpleNamespace(
                config="/config",
                operation=operation.operation_id,
                policy="/policy",
                destination_tx_hash="0x12",
                max_polls=None,
            )
        )


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda value: value.update({"route_id": "bad route"}), "opaque identifier"),
        (lambda value: value.update({"source_reserve_token": "bad"}), "invalid address"),
        (lambda value: value.update({"extra": True}), "direct schema"),
        (
            lambda value: value.update({"destination_chain_id": value["source_chain_id"]}),
            "chains must differ",
        ),
        (
            lambda value: value.update({"source_dln_implementation_codehash": "0x" + "00" * 32}),
            "codehash is invalid",
        ),
        (
            lambda value: value.update({"destination_fulfillment_topic": "0x" + "00" * 32}),
            "topic is unsupported",
        ),
    ],
)
def test_direct_route_manifest_remaining_validation_edges(
    mutate: object, match: str
) -> None:
    document = direct_route_document()
    mutate(document)  # type: ignore[operator]
    with pytest.raises(RouteManifestError, match=match):
        RouteManifest.parse_document(document)


def test_legacy_route_manifest_edge_validation_and_projection() -> None:
    document = legacy_route_document()
    document["extra"] = True
    with pytest.raises(RouteManifestError, match="fields do not match"):
        RouteManifest.parse_document(document)

    document = legacy_route_document()
    document["allowed_source_swap_selectors"] = []
    with pytest.raises(RouteManifestError, match="non-empty selector"):
        RouteManifest.parse_document(document)

    document = legacy_route_document()
    document["allowed_source_swap_selectors"] = ["0x12345678", "0x12345678"]
    with pytest.raises(RouteManifestError, match="duplicate selector"):
        RouteManifest.parse_document(document)

    legacy = RouteManifest.parse_document(legacy_route_document())
    assert legacy.to_dict()["schema_version"] == 2


def test_direct_route_manifest_incomplete_projection_is_rejected() -> None:
    direct = RouteManifest.parse_document(direct_route_document())
    incomplete = replace(direct, source_reserve_token=None)

    with pytest.raises(RouteManifestError, match="incomplete"):
        incomplete.to_dict()


def test_checked_in_approval_example_matches_plan_request_amounts() -> None:
    request_document = json.loads(
        Path("examples/plan.request.example.json").read_text(encoding="utf-8")
    )
    approval_document = json.loads(
        Path("examples/approval-signing-request.example.json").read_text(encoding="utf-8")
    )
    intent = approval_document["intent"]

    assert intent["source_gross_amount_wei"] == int(request_document["amount_wei"])
    assert intent["minimum_destination_amount_wei"] == int(
        request_document["minimum_output_wei"]
    )
