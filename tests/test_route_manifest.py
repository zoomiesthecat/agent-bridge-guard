from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agent_bridge_guard.providers.debridge import FULFILLED_ORDER_TOPIC
from agent_bridge_guard.route_manifest import RouteManifest, RouteManifestError


def manifest() -> dict[str, object]:
    return {
        "schema_version": 2,
        "route_kind": "native_in_swap_dln_native_out",
        "route_id": "arbitrum-robinhood-native-v1",
        "source_chain_alias": "arbitrum",
        "destination_chain_alias": "robinhood",
        "source_chain_id": 42161,
        "destination_chain_id": 4663,
        "allowed_bridge_routers": ["0x" + "11" * 20],
        "allowed_source_swap_routers": ["0x" + "22" * 20],
        "allowed_source_swap_selectors": ["0x12345678"],
        "allowed_intermediary_give_tokens": ["0x" + "23" * 20],
        "allowed_dln_sources": ["0x" + "33" * 20],
        "allowed_refund_recipients": ["0x" + "44" * 20],
        "destination_dln_proxy": "0x" + "55" * 20,
        "destination_fulfillment_topic": FULFILLED_ORDER_TOPIC,
        "maximum_total_spend_wei": 2_000,
        "maximum_value_overhead_wei": 100,
        "maximum_price_impact_bps": 100,
        "maximum_swap_calldata_bytes": 4_096,
        "maximum_metadata_bytes": 512,
        "maximum_quote_age_seconds": 30,
        "maximum_plan_lifetime_seconds": 120,
    }


def write_manifest(tmp_path: Path, value: object) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    path = root / "route.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def test_route_manifest_creates_exact_provider_policy(tmp_path: Path) -> None:
    route = RouteManifest.load(write_manifest(tmp_path, manifest()).resolve())
    policy = route.to_policy()

    assert route.source_chain_id == 42161
    assert route.destination_chain_id == 4663
    assert policy.allowed_bridge_routers == ("0x" + "11" * 20,)
    assert policy.allowed_source_swap_routers == ("0x" + "22" * 20,)
    assert policy.allowed_source_swap_selectors == ("0x12345678",)
    assert policy.allowed_intermediary_give_tokens == ("0x" + "23" * 20,)
    assert policy.destination_fulfillment_topic == FULFILLED_ORDER_TOPIC
    assert policy.maximum_total_spend_wei == 2_000
    assert policy.maximum_plan_lifetime_seconds == 120


def test_route_manifest_pins_one_source_swap_router_selector_pair(tmp_path: Path) -> None:
    document = manifest()
    document["allowed_source_swap_routers"] = [
        "0x" + "22" * 20,
        "0x" + "66" * 20,
    ]

    with pytest.raises(RouteManifestError, match="exactly one"):
        RouteManifest.load(write_manifest(tmp_path, document).resolve())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("destination_fulfillment_topic", "0x" + "00" * 32),
        ("allowed_bridge_routers", []),
        ("allowed_source_swap_selectors", ["0x1234"]),
        ("route_kind", "native-only"),
        ("maximum_total_spend_wei", 0),
        ("maximum_price_impact_bps", -1),
        ("source_chain_id", True),
        ("maximum_plan_lifetime_seconds", 0),
    ],
)
def test_route_manifest_fails_closed_on_unsafe_values(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    document = manifest()
    document[field] = value

    with pytest.raises(RouteManifestError):
        RouteManifest.load(write_manifest(tmp_path, document).resolve())
