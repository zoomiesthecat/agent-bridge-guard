from __future__ import annotations

import json
import os
from pathlib import Path
from stat import S_IMODE

import pytest

from agent_bridge_guard.artifacts import (
    ArtifactExistsError,
    ArtifactPathError,
    PrivateArtifactStore,
)


def test_private_artifact_is_exclusive_durable_and_owner_only(tmp_path: Path) -> None:
    root = tmp_path / "private-artifacts"
    store = PrivateArtifactStore(root)

    path = store.write_json("plan.json", {"value": 7, "secret": "not-a-real-secret"})

    assert path == root / "plan.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "secret": "not-a-real-secret",
        "value": 7,
    }
    assert S_IMODE(root.stat().st_mode) == 0o700
    assert S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(ArtifactExistsError):
        store.write_json("plan.json", {"value": 8})


def test_artifact_store_rejects_relative_broad_or_symlink_paths(tmp_path: Path) -> None:
    with pytest.raises(ArtifactPathError, match="absolute"):
        PrivateArtifactStore(Path("relative"))

    broad = tmp_path / "broad"
    broad.mkdir(mode=0o755)
    with pytest.raises(ArtifactPathError, match="0700"):
        PrivateArtifactStore(broad)

    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    os.symlink(target, link)
    with pytest.raises(ArtifactPathError, match="symlink"):
        PrivateArtifactStore(link)


@pytest.mark.parametrize("name", ["../escape.json", "nested/file.json", "", "."])
def test_artifact_name_must_be_one_safe_component(tmp_path: Path, name: str) -> None:
    store = PrivateArtifactStore(tmp_path / "artifacts")

    with pytest.raises(ArtifactPathError):
        store.write_json(name, {"safe": True})


def test_public_receipt_redacts_private_operation_fields(tmp_path: Path) -> None:
    store = PrivateArtifactStore(tmp_path / "artifacts")
    canary = "DO_NOT_PUBLISH_RAW_TRANSACTION_OR_KEY"
    receipt = store.write_public_receipt(
        "receipt.public.json",
        {
            "operation_id": "op-1",
            "plan_id": "sha256:" + "ab" * 32,
            "state": "verified",
            "tx_hash": "0x" + "cd" * 32,
            "raw_signed_tx": canary,
            "idempotency_key": canary,
            "rpc_url": f"https://rpc.example/{canary}",
            "events": [{"state": "verified", "occurred_at_ns": 1}],
        },
    )

    encoded = receipt.read_text(encoding="utf-8")
    assert canary not in encoded
    assert json.loads(encoded) == {
        "artifact_type": "public_receipt",
        "events": [{"occurred_at_ns": 1, "state": "verified"}],
        "operation_id": "op-1",
        "plan_id": "sha256:" + "ab" * 32,
        "schema_version": 1,
        "state": "verified",
        "tx_hash": "0x" + "cd" * 32,
    }


def test_public_receipt_keeps_durable_chain_evidence_but_not_private_fields(tmp_path: Path) -> None:
    store = PrivateArtifactStore(tmp_path / "artifacts")
    receipt = store.write_public_receipt(
        "receipt.public.json",
        {
            "operation_id": "op-1",
            "source_finality_evidence": {
                "chain_id": 42161,
                "transaction_hash": "0x" + "ab" * 32,
                "block_number": 1,
                "block_hash": "0x" + "cd" * 32,
                "confirmations": 12,
                "rpc_quorum": 2,
                "receipt_status": 1,
                "private_rpc_url": "DO_NOT_PUBLISH_NESTED",
            },
            "destination_fulfillment_evidence": {
                "chain_id": 4663,
                "transaction_hash": "0x" + "ef" * 32,
                "block_number": 2,
                "block_hash": "0x" + "01" * 32,
                "confirmations": 12,
                "rpc_quorum": 2,
                "receipt_status": 1,
                "order_id": "0x" + "02" * 32,
                "log_index": 0,
                "log_address": "0x" + "03" * 20,
                "log_topic": "0x" + "04" * 32,
                "receiver": "0x" + "05" * 20,
                "private_debug": "DO_NOT_PUBLISH_NESTED",
            },
            "raw_signed_tx": "DO_NOT_PUBLISH",
        },
    )

    encoded = receipt.read_text(encoding="utf-8")
    assert "DO_NOT_PUBLISH" not in encoded
    assert "DO_NOT_PUBLISH_NESTED" not in encoded
    value = json.loads(encoded)
    assert value["source_finality_evidence"]["rpc_quorum"] == 2
    assert value["destination_fulfillment_evidence"]["log_index"] == 0
    assert value["destination_fulfillment_evidence"]["receiver"] == "0x" + "05" * 20
