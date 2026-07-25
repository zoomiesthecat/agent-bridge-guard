from copy import deepcopy

import pytest

from agent_bridge_guard.models import Plan, PlanIntegrityError


def plan_body() -> dict[str, object]:
    return {
        "created_at": "2026-07-24T21:50:00Z",
        "expires_at": "2026-07-24T21:50:30Z",
        "provider": {
            "name": "debridge",
            "version": "2",
            "route_id": "arb-rh-native-v2",
            "route_kind": "native_in_swap_dln_native_out",
        },
        "intent": {
            "source_chain_id": 42161,
            "destination_chain_id": 4663,
            "amount_wei": 541_000_000_000_000_000,
            "minimum_output_wei": 535_000_000_000_000_000,
            "recipient": "0x2222222222222222222222222222222222222222",
            "expected_signer": "0x2222222222222222222222222222222222222222",
        },
        "policy": {
            "maximum_total_spend_wei": 542_200_000_000_000_000,
            "maximum_price_impact_bps": 100,
        },
        "unsigned_transaction": {
            "chain_id": 42161,
            "nonce": 7,
            "to": "0x1111111111111111111111111111111111111111",
            "value": 542_000_000_000_000_000,
            "data": "0x1234",
            "gas": 800_000,
            "max_fee_per_gas": 30_000_000,
            "max_priority_fee_per_gas": 0,
        },
        "decoded_semantics": {
            "source_order_token": "0x" + "55" * 20,
            "source_gross_amount_wei": 1_002_193_568,
            "protocol_fee_amount_wei": 400_877,
            "source_net_amount_wei": 1_001_792_691,
            "source_swap_router": "0x" + "55" * 20,
            "external_call": False,
        },
        "checks": ["signer", "chain", "recipient", "amount", "calldata"],
    }


def test_plan_id_binds_every_execution_field() -> None:
    plan = Plan.create(plan_body())
    parsed = Plan.parse(plan.to_dict())

    assert parsed.plan_id == plan.plan_id
    assert parsed.to_dict() == plan.to_dict()

    mutated = deepcopy(plan.to_dict())
    transaction = mutated["unsigned_transaction"]
    assert isinstance(transaction, dict)
    transaction["value"] = 1

    with pytest.raises(PlanIntegrityError, match="plan_id mismatch"):
        Plan.parse(mutated)


def test_plan_rejects_floating_point_values() -> None:
    body = plan_body()
    policy = body["policy"]
    assert isinstance(policy, dict)
    policy["maximum_price_impact_bps"] = 1.0

    with pytest.raises(TypeError, match="floating point"):
        Plan.create(body)
