"""Operator-protected trust policy for authorization and route manifests."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import cast

from eth_utils import is_address, to_checksum_address  # type: ignore[attr-defined]

from .models import JSONObject, canonical_json

POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "policy_id",
        "policy_version",
        "approval_issuers",
        "authorized_route_manifests",
        "chains",
    }
)
ROUTE_FIELDS = frozenset({"route_id", "sha256"})
CHAIN_FIELDS = frozenset({"chain_id", "confirmations"})
OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_POLICY_BYTES = 256 * 1024


class PolicyError(ValueError):
    """The trust policy document is malformed or ambiguous."""


class ProtectedPolicyPathError(PolicyError):
    """The trust policy path is writable by the runtime authority."""


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not OPAQUE_ID.fullmatch(value):
        raise PolicyError(f"{label} must be an opaque identifier")
    return value


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PolicyError(f"{label} must be a positive integer")
    return value


def _address(value: object, label: str) -> str:
    if not isinstance(value, str) or not is_address(value):
        raise PolicyError(f"{label} must be an EVM address")
    return cast(str, to_checksum_address(value))


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise PolicyError(f"{label} must be a sha256 digest")
    return value


@dataclass(frozen=True, slots=True)
class AuthorizedManifest:
    route_id: str
    digest: str


@dataclass(frozen=True, slots=True)
class ChainPolicy:
    chain_id: int
    confirmations: int


@dataclass(frozen=True, slots=True)
class TrustedPolicy:
    """Canonical policy loaded from an operator-controlled filesystem boundary."""

    policy_id: str
    policy_version: int
    digest: str
    approval_issuers: frozenset[str]
    authorized_manifests: tuple[AuthorizedManifest, ...]
    chains: tuple[ChainPolicy, ...]
    _document_json: str = field(repr=False)

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        runtime_uid: int | None = None,
        runtime_gids: set[int] | None = None,
    ) -> TrustedPolicy:
        runtime_uid = os.getuid() if runtime_uid is None else runtime_uid
        if runtime_uid == 0:
            raise ProtectedPolicyPathError("guard runtime must not run as root")
        groups = {os.getgid(), *os.getgroups()} if runtime_gids is None else set(runtime_gids)
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ProtectedPolicyPathError("trusted policy path must be absolute")
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise ProtectedPolicyPathError("trusted policy is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ProtectedPolicyPathError("trusted policy must not be a symlink")
        if not stat.S_ISREG(metadata.st_mode):
            raise ProtectedPolicyPathError("trusted policy must be a regular file")
        if metadata.st_uid == runtime_uid:
            raise ProtectedPolicyPathError(
                "trusted policy must be owned by a different operator UID"
            )
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ProtectedPolicyPathError("trusted policy must not be group or world writable")
        _validate_ancestors(candidate.parent, runtime_uid, groups)
        try:
            descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (
                    opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                    or opened.st_uid != metadata.st_uid
                    or not stat.S_ISREG(opened.st_mode)
                ):
                    raise ProtectedPolicyPathError("trusted policy changed during open")
                raw = stream.read(MAX_POLICY_BYTES + 1)
        except OSError as exc:
            raise ProtectedPolicyPathError("trusted policy is unavailable") from exc
        if len(raw) > MAX_POLICY_BYTES:
            raise ProtectedPolicyPathError("trusted policy exceeds byte limit")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PolicyError("trusted policy is not valid JSON") from exc
        if not isinstance(document, dict):
            raise PolicyError("trusted policy must contain an object")
        return cls.parse(cast(dict[str, object], document))

    @classmethod
    def parse(cls, document: dict[str, object]) -> TrustedPolicy:
        if set(document) != POLICY_FIELDS:
            raise PolicyError("trusted policy fields do not match schema")
        if document.get("schema_version") != 1:
            raise PolicyError("trusted policy schema_version is unsupported")
        if document.get("artifact_type") != "trusted_policy":
            raise PolicyError("trusted policy artifact_type is unsupported")
        policy_id = _identifier(document.get("policy_id"), "policy_id")
        policy_version = _positive_integer(
            document.get("policy_version"),
            "policy_version",
        )
        issuers_value = document.get("approval_issuers")
        if not isinstance(issuers_value, list) or not issuers_value:
            raise PolicyError("approval_issuers must be a non-empty list")
        issuers = tuple(_address(value, "approval issuer") for value in issuers_value)
        if len(set(issuers)) != len(issuers):
            raise PolicyError("approval_issuers contains a duplicate")

        routes_value = document.get("authorized_route_manifests")
        if not isinstance(routes_value, list) or not routes_value:
            raise PolicyError("authorized_route_manifests must be a non-empty list")
        routes: list[AuthorizedManifest] = []
        for value in routes_value:
            if not isinstance(value, dict) or set(value) != ROUTE_FIELDS:
                raise PolicyError("authorized route manifest fields do not match schema")
            routes.append(
                AuthorizedManifest(
                    route_id=_identifier(value.get("route_id"), "route_id"),
                    digest=_digest(value.get("sha256"), "manifest digest"),
                )
            )
        route_bindings = {(route.route_id, route.digest) for route in routes}
        if len(route_bindings) != len(routes):
            raise PolicyError("authorized route manifests contain a duplicate")
        if len({route.route_id for route in routes}) != len(routes):
            raise PolicyError("one route_id must bind exactly one manifest digest")

        chains_value = document.get("chains")
        if not isinstance(chains_value, list) or not chains_value:
            raise PolicyError("chains must be a non-empty list")
        chains: list[ChainPolicy] = []
        for value in chains_value:
            if not isinstance(value, dict) or set(value) != CHAIN_FIELDS:
                raise PolicyError("chain policy fields do not match schema")
            chains.append(
                ChainPolicy(
                    chain_id=_positive_integer(value.get("chain_id"), "chain_id"),
                    confirmations=_positive_integer(
                        value.get("confirmations"),
                        "confirmations",
                    ),
                )
            )
        if len({chain.chain_id for chain in chains}) != len(chains):
            raise PolicyError("chains contains a duplicate")

        normalized: JSONObject = {
            "schema_version": 1,
            "artifact_type": "trusted_policy",
            "policy_id": policy_id,
            "policy_version": policy_version,
            "approval_issuers": list(issuers),
            "authorized_route_manifests": [
                {"route_id": route.route_id, "sha256": route.digest} for route in routes
            ],
            "chains": [
                {
                    "chain_id": chain.chain_id,
                    "confirmations": chain.confirmations,
                }
                for chain in chains
            ],
        }
        encoded = canonical_json(normalized)
        policy_digest = "sha256:" + sha256(encoded.encode("utf-8")).hexdigest()
        return cls(
            policy_id=policy_id,
            policy_version=policy_version,
            digest=policy_digest,
            approval_issuers=frozenset(issuers),
            authorized_manifests=tuple(routes),
            chains=tuple(chains),
            _document_json=encoded,
        )

    def to_dict(self) -> JSONObject:
        document = json.loads(self._document_json)
        if not isinstance(document, dict):
            raise AssertionError("canonical policy must decode to an object")
        return cast(JSONObject, document)

    def authorizes_manifest(self, route_id: str, digest: str) -> bool:
        return any(
            route.route_id == route_id and route.digest == digest
            for route in self.authorized_manifests
        )

    def confirmations_for(self, chain_id: int) -> int:
        for chain in self.chains:
            if chain.chain_id == chain_id:
                return chain.confirmations
        raise PolicyError("chain is not authorized by trusted policy")


def _validate_ancestors(directory: Path, runtime_uid: int, runtime_gids: set[int]) -> None:
    current = directory
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ProtectedPolicyPathError("trusted policy ancestor is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ProtectedPolicyPathError("trusted policy path must not contain a symlink")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ProtectedPolicyPathError("trusted policy ancestor must be a directory")
        mode = metadata.st_mode
        runtime_owner_write = metadata.st_uid == runtime_uid and bool(mode & stat.S_IWUSR)
        runtime_group_write = metadata.st_gid in runtime_gids and bool(mode & stat.S_IWGRP)
        unsafe_other_write = bool(mode & stat.S_IWOTH) and not bool(mode & stat.S_ISVTX)
        if runtime_owner_write or runtime_group_write or unsafe_other_write:
            raise ProtectedPolicyPathError("trusted policy path has a runtime-writable ancestor")
        if current == current.parent:
            return
        current = current.parent
