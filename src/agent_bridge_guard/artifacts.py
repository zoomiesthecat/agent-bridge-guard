"""Owner-only, atomic JSON artifacts with an explicitly redacted public view."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from .models import JSONObject, JSONValue, canonical_json

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PUBLIC_RECEIPT_FIELDS = frozenset(
    {
        "operation_id",
        "plan_id",
        "state",
        "tx_hash",
        "source_tx_hash",
        "destination_tx_hash",
        "order_id",
        "source_finality_evidence",
        "destination_fulfillment_evidence",
        "events",
    }
)
PUBLIC_EVENT_FIELDS = frozenset({"sequence", "state", "occurred_at_ns"})
PUBLIC_FINALITY_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "verifier_version",
        "plan_id",
        "chain_id",
        "transaction_hash",
        "block_number",
        "block_hash",
        "confirmations",
        "rpc_quorum",
        "receipt_status",
    }
)
PUBLIC_DESTINATION_EVIDENCE_FIELDS = PUBLIC_FINALITY_EVIDENCE_FIELDS | frozenset(
    {
        "order_id",
        "log_index",
        "log_address",
        "log_topic",
        "receiver",
        "destination_token",
        "destination_amount_wei",
    }
)


class ArtifactError(RuntimeError):
    """Base error for artifact persistence."""


class ArtifactPathError(ArtifactError):
    """An artifact path is unsafe or has unexpected ownership or permissions."""


class ArtifactExistsError(ArtifactError):
    """An immutable artifact already exists."""


def _ensure_private_root(path: Path) -> None:
    if not path.is_absolute():
        raise ArtifactPathError("artifact root must be absolute")

    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                metadata = current.lstat()
            else:
                metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ArtifactPathError("artifact path must not contain a symlink")
        if current == path and not stat.S_ISDIR(metadata.st_mode):
            raise ArtifactPathError("artifact root must be a directory")

    metadata = path.stat()
    if metadata.st_uid != os.getuid():
        raise ArtifactPathError("artifact root must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ArtifactPathError("artifact root must use mode 0700")


def _public_event(value: object) -> JSONObject:
    if not isinstance(value, Mapping):
        raise ArtifactError("public receipt event must be an object")
    return {
        key: cast(JSONValue, value[key])
        for key in sorted(PUBLIC_EVENT_FIELDS)
        if key in value
    }


def _public_evidence(
    value: object,
    fields: frozenset[str],
    *,
    label: str,
) -> JSONObject:
    if not isinstance(value, Mapping):
        raise ArtifactError(f"{label} must be an object")
    return {
        key: cast(JSONValue, value[key])
        for key in sorted(fields)
        if key in value
    }


class PrivateArtifactStore:
    """Persist immutable artifacts below one owner-only directory."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        _ensure_private_root(self._root)

    @property
    def root(self) -> Path:
        return self._root

    def write_json(self, name: str, value: object) -> Path:
        """Create one canonical JSON artifact without following links or overwriting."""

        if not SAFE_NAME.fullmatch(name):
            raise ArtifactPathError("artifact name must be one safe path component")
        encoded = (canonical_json(value) + "\n").encode("utf-8")
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        directory = os.open(self._root, directory_flags)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(name, flags, 0o600, dir_fd=directory)
            except FileExistsError as exc:
                raise ArtifactExistsError("artifact already exists") from exc
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(descriptor)
            os.fsync(directory)
        finally:
            os.close(directory)
        return self._root / name

    def write_public_receipt(self, name: str, operation: Mapping[str, object]) -> Path:
        """Write a strict allowlisted receipt that cannot inherit private fields."""

        receipt: JSONObject = {
            "schema_version": 1,
            "artifact_type": "public_receipt",
        }
        for key in sorted(PUBLIC_RECEIPT_FIELDS - {"events"}):
            if key in operation and operation[key] is not None:
                value = operation[key]
                if key == "source_finality_evidence":
                    receipt[key] = _public_evidence(
                        value,
                        PUBLIC_FINALITY_EVIDENCE_FIELDS,
                        label="source finality evidence",
                    )
                elif key == "destination_fulfillment_evidence":
                    receipt[key] = _public_evidence(
                        value,
                        PUBLIC_DESTINATION_EVIDENCE_FIELDS,
                        label="destination fulfillment evidence",
                    )
                else:
                    receipt[key] = cast(JSONValue, value)
        events = operation.get("events")
        if events is not None:
            if not isinstance(events, list):
                raise ArtifactError("public receipt events must be a list")
            receipt["events"] = [_public_event(event) for event in events]
        return self.write_json(name, receipt)


def read_json_object(path: str | Path, *, max_bytes: int = 2 * 1024 * 1024) -> dict[str, object]:
    """Read one bounded owner-only JSON object without accepting symlinks."""

    data = read_private_bytes(path, max_bytes=max_bytes)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactError("artifact is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ArtifactError("artifact must contain a JSON object")
    return cast(dict[str, object], value)


def read_private_bytes(path: str | Path, *, max_bytes: int = 2 * 1024 * 1024) -> bytes:
    """Read bounded owner-only bytes through a no-follow descriptor."""

    candidate = Path(path)
    if not candidate.is_absolute():
        raise ArtifactPathError("artifact path must be absolute")
    _ensure_private_ancestors(candidate.parent)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise ArtifactPathError("artifact is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ArtifactPathError("artifact must be an owner-only regular file")
    try:
        descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            data = stream.read(max_bytes + 1)
    except OSError as exc:
        raise ArtifactPathError("artifact is unavailable") from exc
    if len(data) > max_bytes:
        raise ArtifactPathError("artifact exceeds byte limit")
    return data


def _ensure_private_ancestors(directory: Path) -> None:
    """Reject a link or permissive directory below the filesystem anchor."""

    current = Path(directory.anchor)
    for part in directory.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ArtifactPathError("artifact parent is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ArtifactPathError("artifact parent must be a directory without symlinks")
        if current == directory and (
            metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ArtifactPathError("artifact parent must be owner-only mode 0700")
