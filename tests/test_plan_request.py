from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agent_bridge_guard.plan_request import PlanRequest, PlanRequestError


def request() -> dict[str, object]:
    return {
        "schema_version": 2,
        "request_id": "ticket-123",
        "route_id": "arb-rh-native-v1",
        "source_chain_alias": "arbitrum",
        "destination_chain_alias": "robinhood",
        "amount_wei": "1000",
        "minimum_output_wei": "900",
        "signer": "0x" + "11" * 20,
        "recipient": "0x" + "22" * 20,
        "expires_at": "2030-01-01T00:05:00Z",
    }


def write(tmp_path: Path, value: object) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    path = root / "request.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    os.chmod(path, 0o600)
    return path.resolve()


def test_plan_request_uses_decimal_strings_for_exact_base_units(tmp_path: Path) -> None:
    parsed = PlanRequest.load(write(tmp_path, request()))

    assert parsed.amount_wei == 1_000
    assert parsed.minimum_output_wei == 900
    assert parsed.route_id == "arb-rh-native-v1"
    assert parsed.source_chain_alias == "arbitrum"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("amount_wei", 1_000),
        ("minimum_output_wei", "0"),
        ("signer", "wallet-alias"),
        ("expires_at", "2030-01-01"),
    ],
)
def test_plan_request_rejects_ambiguous_or_unsafe_values(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    document = request()
    document[field] = value

    with pytest.raises(PlanRequestError):
        PlanRequest.load(write(tmp_path, document))
