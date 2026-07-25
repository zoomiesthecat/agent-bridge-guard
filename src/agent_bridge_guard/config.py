"""Private runtime configuration with secret-safe representations."""

from __future__ import annotations

import os
import stat
import tomllib
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .artifacts import ArtifactError, read_private_bytes

MAX_CONFIG_BYTES = 128 * 1024


class ConfigError(ValueError):
    """Configuration is unsafe or malformed."""


@dataclass(frozen=True, slots=True)
class SecretUrl:
    _value: str = field(repr=False)

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SecretUrl([redacted])"


@dataclass(frozen=True, slots=True)
class ChainConfig:
    chain_id: int
    primary_rpc: SecretUrl
    secondary_rpc: SecretUrl


@dataclass(frozen=True, slots=True)
class DebridgeConfig:
    create_tx_url: SecretUrl
    tracking_url: SecretUrl


@dataclass(frozen=True, slots=True)
class Settings:
    database_path: Path = field(repr=False)
    debridge: DebridgeConfig
    chains: dict[str, ChainConfig]


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            break
        if stat.S_ISLNK(mode):
            raise ConfigError("configuration path contains a symlink")


def _validate_private_file(path: Path) -> None:
    if not path.is_absolute():
        raise ConfigError("configuration path must be absolute")
    _reject_symlink_components(path)
    try:
        metadata = path.stat()
    except OSError as exc:
        raise ConfigError("configuration file is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ConfigError("configuration must be a regular file")
    if metadata.st_uid != os.getuid():
        raise ConfigError("configuration must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ConfigError("configuration must use mode 0600")
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise ConfigError("configuration file exceeds size limit")


def _table(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a table")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{label} must be a non-empty string")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{label} must be a positive integer")
    return value


def _safe_url(value: object, label: str) -> SecretUrl:
    text = _string(value, label)
    try:
        parsed = urllib.parse.urlsplit(text)
        port = parsed.port
    except ValueError as exc:
        raise ConfigError(f"{label} is invalid") from exc
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError(f"{label} must not contain embedded credentials")
    if parsed.scheme != "https" or not parsed.hostname or port is not None and port <= 0:
        raise ConfigError(f"{label} must be an HTTPS URL")
    return SecretUrl(text)


def load_config(path: str | Path) -> Settings:
    config_path = Path(path)
    _validate_private_file(config_path)
    try:
        raw = read_private_bytes(config_path, max_bytes=MAX_CONFIG_BYTES)
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (ArtifactError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError("configuration cannot be decoded") from exc
    if set(parsed) != {"database", "provider", "chains"}:
        raise ConfigError("configuration fields do not match schema")

    database = _table(parsed.get("database"), "database")
    database_path = Path(_string(database.get("path"), "database.path"))
    if not database_path.is_absolute():
        raise ConfigError("database.path must be absolute")

    provider = _table(parsed.get("provider"), "provider")
    debridge_data = _table(provider.get("debridge"), "provider.debridge")
    debridge = DebridgeConfig(
        create_tx_url=_safe_url(
            debridge_data.get("create_tx_url"), "provider.debridge.create_tx_url"
        ),
        tracking_url=_safe_url(debridge_data.get("tracking_url"), "provider.debridge.tracking_url"),
    )

    chain_data = _table(parsed.get("chains"), "chains")
    if not chain_data:
        raise ConfigError("chains must not be empty")
    chains: dict[str, ChainConfig] = {}
    for name, value in chain_data.items():
        if not isinstance(name, str) or not name:
            raise ConfigError("chain aliases must be non-empty strings")
        chain = _table(value, f"chains.{name}")
        if set(chain) != {"chain_id", "primary_rpc", "secondary_rpc"}:
            raise ConfigError(f"chains.{name} fields do not match schema")
        primary_rpc = _safe_url(chain.get("primary_rpc"), f"chains.{name}.primary_rpc")
        secondary_rpc = _safe_url(chain.get("secondary_rpc"), f"chains.{name}.secondary_rpc")
        if primary_rpc.reveal() == secondary_rpc.reveal():
            raise ConfigError(f"chains.{name} RPC endpoints must be distinct")
        chains[name] = ChainConfig(
            chain_id=_positive_int(chain.get("chain_id"), f"chains.{name}.chain_id"),
            primary_rpc=primary_rpc,
            secondary_rpc=secondary_rpc,
        )
    return Settings(
        database_path=database_path,
        debridge=debridge,
        chains=chains,
    )
