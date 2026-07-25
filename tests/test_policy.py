from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from eth_account import Account

from agent_bridge_guard.models import canonical_json
from agent_bridge_guard.policy import PolicyError, ProtectedPolicyPathError, TrustedPolicy


def policy_document() -> dict[str, object]:
    issuer = Account.from_key("0x" + "11" * 32).address
    return {
        "schema_version": 1,
        "artifact_type": "trusted_policy",
        "policy_id": "zoomies-production",
        "policy_version": 3,
        "approval_issuers": [issuer],
        "authorized_route_manifests": [
            {
                "route_id": "arb-rh-usdc-v1",
                "sha256": "sha256:" + "ab" * 32,
            }
        ],
        "chains": [
            {"chain_id": 42161, "confirmations": 12},
            {"chain_id": 4663, "confirmations": 20},
        ],
    }


def write_policy(path: Path, document: dict[str, object] | None = None) -> Path:
    path.write_text(canonical_json(document or policy_document()) + "\n", encoding="utf-8")
    path.chmod(0o644)
    return path


def test_policy_digest_and_authorizations_are_canonical(tmp_path: Path) -> None:
    path = write_policy(tmp_path / "policy.json")

    policy = TrustedPolicy.load(
        path.resolve(),
        runtime_uid=os.getuid() + 10_000,
        runtime_gids={os.getgid() + 10_000},
    )

    assert policy.policy_id == "zoomies-production"
    assert policy.policy_version == 3
    assert policy.digest.startswith("sha256:")
    assert policy.to_dict() == policy_document()
    assert policy.authorizes_manifest("arb-rh-usdc-v1", "sha256:" + "ab" * 32)
    assert not policy.authorizes_manifest("arb-rh-usdc-v1", "sha256:" + "cd" * 32)
    assert policy.confirmations_for(42161) == 12

    reordered = json.loads(json.dumps(policy_document(), sort_keys=False))
    assert TrustedPolicy.parse(reordered).digest == policy.digest


def test_policy_rejects_unknown_chain_and_extra_top_level_field() -> None:
    policy = TrustedPolicy.parse(policy_document())
    with pytest.raises(PolicyError, match="not authorized"):
        policy.confirmations_for(1)

    document = policy_document()
    document["unexpected"] = True
    with pytest.raises(PolicyError, match="fields"):
        TrustedPolicy.parse(document)


def test_policy_rejects_same_uid_owner_even_when_read_only(tmp_path: Path) -> None:
    path = write_policy(tmp_path / "policy.json")
    path.chmod(0o444)

    with pytest.raises(ProtectedPolicyPathError, match="different operator UID"):
        TrustedPolicy.load(path.resolve())


def test_policy_rejects_symlink_and_runtime_writable_ancestor(tmp_path: Path) -> None:
    path = write_policy(tmp_path / "policy.json")
    linked = tmp_path / "linked-policy.json"
    linked.symlink_to(path)
    runtime_uid = os.getuid() + 10_000

    with pytest.raises(ProtectedPolicyPathError, match="symlink"):
        TrustedPolicy.load(
            linked.absolute(),
            runtime_uid=runtime_uid,
            runtime_gids={os.getgid() + 10_000},
        )

    insecure = tmp_path / "insecure"
    insecure.mkdir(mode=0o777)
    insecure.chmod(0o777)
    nested = write_policy(insecure / "policy.json")
    with pytest.raises(ProtectedPolicyPathError, match="runtime-writable"):
        TrustedPolicy.load(
            nested.resolve(),
            runtime_uid=runtime_uid,
            runtime_gids={insecure.stat().st_gid},
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(policy_version=0), "policy_version"),
        (lambda value: value.update(approval_issuers=[]), "approval_issuers"),
        (
            lambda value: value["authorized_route_manifests"][0].update(sha256="sha256:bad"),
            "manifest digest",
        ),
        (
            lambda value: value["authorized_route_manifests"].append(
                dict(value["authorized_route_manifests"][0])
            ),
            "duplicate",
        ),
        (
            lambda value: value["chains"].append({"chain_id": 42161, "confirmations": 1}),
            "duplicate",
        ),
    ],
)
def test_policy_rejects_malformed_or_ambiguous_documents(
    mutate: object, message: str
) -> None:
    document = policy_document()
    mutate(document)  # type: ignore[operator]

    with pytest.raises(PolicyError, match=message):
        TrustedPolicy.parse(document)
