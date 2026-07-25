from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from agent_bridge_guard.wallets.twak import (
    DEFAULT_STATUS_TIMEOUT_SECONDS,
    TWAKAdapter,
    TWAKCapability,
)


def pinned_executable(tmp_path: Path) -> tuple[Path, str]:
    executable = tmp_path / "twak"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    return executable, hashlib.sha256(executable.read_bytes()).hexdigest()


def test_twak_capability_explicitly_disables_evm_and_live_debridge() -> None:
    capability = TWAKAdapter().capability

    assert capability == TWAKCapability(
        experimental=True,
        arbitrary_evm_signing=False,
        live_debridge_enabled=False,
    )


def test_twak_readiness_uses_fixed_pinned_local_wallet_status_command(tmp_path: Path) -> None:
    executable, executable_sha256 = pinned_executable(tmp_path)
    calls: list[tuple[list[str], dict[str, str], float]] = []

    def runner(command: list[str], env: dict[str, str], timeout: float) -> tuple[int, str, str]:
        calls.append((command, env, timeout))
        return 0, '{"ready":true}', ""

    result = TWAKAdapter(executable, executable_sha256, runner=runner).readiness({})

    assert result == {"ready": True}
    command, environment, timeout = calls[0]
    assert command[0].startswith("/proc/self/fd/")
    assert command[1:] == ["wallet", "status", "--json"]
    assert environment == {}
    assert timeout == DEFAULT_STATUS_TIMEOUT_SECONDS


def test_twak_readiness_requires_an_absolute_hash_pinned_executable(tmp_path: Path) -> None:
    executable, executable_sha256 = pinned_executable(tmp_path)

    with pytest.raises(ValueError, match="requires an executable"):
        TWAKAdapter().readiness()
    with pytest.raises(ValueError, match="configuration is invalid"):
        TWAKAdapter(Path(executable.name), executable_sha256).readiness()
    with pytest.raises(ValueError, match="integrity check"):
        TWAKAdapter(executable, "0" * 64).readiness()


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_twak_readiness_rejects_non_executable_files(tmp_path: Path, mode: int) -> None:
    executable, executable_sha256 = pinned_executable(tmp_path)
    executable.chmod(mode)

    with pytest.raises(ValueError, match="execute bit"):
        TWAKAdapter(executable, executable_sha256).readiness()


def test_twak_readiness_rejects_symlinked_executable(tmp_path: Path) -> None:
    executable, executable_sha256 = pinned_executable(tmp_path)
    linked = tmp_path / "linked-twak"
    linked.symlink_to(executable)

    with pytest.raises(ValueError, match="non-symlink"):
        TWAKAdapter(linked, executable_sha256).readiness()


def test_twak_readiness_rejects_group_or_world_writable_executable(tmp_path: Path) -> None:
    executable, executable_sha256 = pinned_executable(tmp_path)
    executable.chmod(0o775)
    executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="group or world writable"):
        TWAKAdapter(executable, executable_sha256).readiness()


def test_twak_default_runner_executes_pinned_file_descriptor_after_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, executable_sha256 = pinned_executable(tmp_path)
    replacement = tmp_path / "replacement"
    replacement.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    replacement.chmod(0o700)
    observed: dict[str, object] = {}

    def completed(command: list[str], **kwargs: object) -> object:
        os.replace(replacement, executable)
        observed["command"] = command
        observed["pass_fds"] = kwargs["pass_fds"]
        return type("Completed", (), {"returncode": 0, "stdout": "{}", "stderr": ""})()

    monkeypatch.setattr("agent_bridge_guard.wallets.twak.subprocess.run", completed)

    assert TWAKAdapter(executable, executable_sha256).readiness() == {}
    assert observed["command"][0].startswith("/proc/self/fd/")  # type: ignore[index,union-attr]
    assert len(observed["pass_fds"]) == 1  # type: ignore[arg-type,index]


def test_twak_default_runner_executes_pinned_file_descriptor(tmp_path: Path) -> None:
    executable = tmp_path / "twak"
    executable.write_text("#!/bin/sh\nprintf '%s' '{\"ready\":true}'\n", encoding="utf-8")
    executable.chmod(0o700)
    executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()

    assert TWAKAdapter(executable, executable_sha256).readiness() == {"ready": True}


def test_twak_status_env_allowlist_excludes_password_and_unrelated_canaries(tmp_path: Path) -> None:
    executable, executable_sha256 = pinned_executable(tmp_path)
    observed: dict[str, str] = {}

    def runner(_command: list[str], env: dict[str, str], _timeout: float) -> tuple[int, str, str]:
        observed.update(env)
        return 0, '{"initialized":false}', ""

    environment = {
        "HOME": "/operator/home",
        "XDG_CONFIG_HOME": "/operator/config",
        "TWAK_WALLET_PASSWORD": "DO_NOT_LEAK_TWAK_PASSWORD",
        "UNRELATED_SECRET": "DO_NOT_LEAK_UNRELATED_SECRET",
    }
    result = TWAKAdapter(executable, executable_sha256, runner=runner).readiness(environment)

    assert result == {"initialized": False}
    assert observed == {"HOME": "/operator/home", "XDG_CONFIG_HOME": "/operator/config"}
    assert "TWAK_WALLET_PASSWORD" not in observed
    assert "UNRELATED_SECRET" not in observed


def test_twak_readiness_never_reads_process_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, executable_sha256 = pinned_executable(tmp_path)
    monkeypatch.setenv("UNRELATED_SECRET", "DO_NOT_LEAK_UNRELATED_SECRET")
    observed: dict[str, str] = {}

    def runner(_command: list[str], env: dict[str, str], _timeout: float) -> tuple[int, str, str]:
        observed.update(env)
        return 0, "{}", ""

    assert TWAKAdapter(executable, executable_sha256, runner=runner).readiness() == {}
    assert observed == {}
    assert os.environ["UNRELATED_SECRET"] not in observed.values()


def test_twak_rejects_non_json_output_without_leaking_subprocess_error(tmp_path: Path) -> None:
    executable, executable_sha256 = pinned_executable(tmp_path)
    canary = "DO_NOT_LEAK_TWAK_SUBPROCESS_ERROR"

    def runner(_command: list[str], _env: dict[str, str], _timeout: float) -> tuple[int, str, str]:
        return 1, "not-json", canary

    with pytest.raises(RuntimeError) as error:
        TWAKAdapter(executable, executable_sha256, runner=runner).readiness()

    assert canary not in str(error.value)


def test_twak_readiness_timeout_is_fixed_and_sanitized(tmp_path: Path) -> None:
    executable, executable_sha256 = pinned_executable(tmp_path)
    canary = "DO_NOT_LEAK_TWAK_TIMEOUT_DETAILS"

    def runner(_command: list[str], _env: dict[str, str], _timeout: float) -> tuple[int, str, str]:
        raise OSError(canary)

    with pytest.raises(RuntimeError, match="could not be started") as error:
        TWAKAdapter(executable, executable_sha256, runner=runner).readiness()

    assert canary not in str(error.value)
