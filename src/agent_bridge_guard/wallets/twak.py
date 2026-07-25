"""Constrained Trust Wallet CLI readiness adapter.

TWAK is intentionally not a signing/broadcasting backend for bridge execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

Runner = Callable[[list[str], dict[str, str], float], tuple[int, str, str]]
STATUS_ENV_ALLOWLIST = frozenset({"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"})
STATUS_COMMAND = ("wallet", "status", "--json")
DEFAULT_STATUS_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True, slots=True)
class TWAKCapability:
    experimental: bool
    arbitrary_evm_signing: bool
    live_debridge_enabled: bool


class TWAKAdapter:
    """Probe a hash-pinned local CLI without exposing the wallet password."""

    capability = TWAKCapability(
        experimental=True,
        arbitrary_evm_signing=False,
        live_debridge_enabled=False,
    )

    def __init__(
        self,
        executable: Path | None = None,
        executable_sha256: str | None = None,
        *,
        timeout_seconds: float = DEFAULT_STATUS_TIMEOUT_SECONDS,
        runner: Runner | None = None,
    ) -> None:
        self._executable = executable
        self._executable_sha256 = executable_sha256
        if timeout_seconds <= 0:
            raise ValueError("TWAK readiness timeout must be positive")
        self._timeout_seconds = timeout_seconds
        self._runner = runner

    def readiness(self, environment: Mapping[str, str] | None = None) -> dict[str, object]:
        """Run only a fixed status probe against an explicitly pinned local binary."""
        executable_fd = self._validated_executable()
        status_environment = {
            name: value
            for name, value in ({} if environment is None else environment).items()
            if name in STATUS_ENV_ALLOWLIST
        }
        try:
            command = [_fd_execution_path(executable_fd), *STATUS_COMMAND]
            if self._runner is None:
                status, stdout, _stderr = self._subprocess_runner(
                    command, status_environment, self._timeout_seconds, executable_fd
                )
            else:
                status, stdout, _stderr = self._runner(
                    command, status_environment, self._timeout_seconds
                )
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError("TWAK readiness command could not be started") from error
        finally:
            os.close(executable_fd)
        if status != 0:
            raise RuntimeError("TWAK readiness command failed")
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("TWAK readiness command returned non-JSON output") from error
        if not isinstance(parsed, dict):
            raise RuntimeError("TWAK readiness command returned a non-object JSON value")
        return parsed

    def _validated_executable(self) -> int:
        executable = self._executable
        expected_hash = self._executable_sha256
        if executable is None or expected_hash is None:
            raise ValueError("TWAK readiness requires an executable and SHA-256 pin")
        if not executable.is_absolute() or not _is_sha256(expected_hash):
            raise ValueError("TWAK executable configuration is invalid")
        try:
            if stat.S_ISLNK(executable.lstat().st_mode):
                raise ValueError("TWAK executable must be a regular non-symlink file")
        except OSError as error:
            raise ValueError("TWAK executable is unavailable") from error
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise ValueError("TWAK executable requires a no-follow file descriptor")
        try:
            executable_fd = os.open(executable, os.O_RDONLY | nofollow)
        except OSError as error:
            raise ValueError("TWAK executable is unavailable") from error
        try:
            metadata = os.fstat(executable_fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("TWAK executable must be a regular non-symlink file")
            if not metadata.st_mode & 0o111:
                raise ValueError("TWAK executable must have an execute bit")
            if metadata.st_mode & 0o022:
                raise ValueError("TWAK executable must not be group or world writable")
            if _sha256_fd(executable_fd) != expected_hash.lower():
                raise ValueError("TWAK executable integrity check failed")
        except Exception:
            os.close(executable_fd)
            raise
        return executable_fd

    @staticmethod
    def _subprocess_runner(
        command: list[str], environment: dict[str, str], timeout_seconds: float, executable_fd: int
    ) -> tuple[int, str, str]:
        try:
            completed = subprocess.run(  # noqa: S603 -- fixed command with validated absolute binary
                command,
                check=False,
                capture_output=True,
                env=environment,
                shell=False,
                text=True,
                timeout=timeout_seconds,
                pass_fds=(executable_fd,),
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("TWAK readiness command timed out") from error
        return completed.returncode, completed.stdout, completed.stderr


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _fd_execution_path(executable_fd: int) -> str:
    fd_directory = Path("/proc/self/fd")
    if not fd_directory.is_dir():
        raise ValueError("TWAK executable requires file-descriptor execution support")
    return str(fd_directory / str(executable_fd))


def _sha256_fd(executable_fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(executable_fd, 0, os.SEEK_SET)
    while block := os.read(executable_fd, 64 * 1024):
        digest.update(block)
    os.lseek(executable_fd, 0, os.SEEK_SET)
    return digest.hexdigest()
