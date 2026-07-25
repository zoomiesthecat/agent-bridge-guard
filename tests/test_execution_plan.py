from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_bridge_guard.execution_plan import (
    ExecutionPlan,
    ExecutionPlanError,
)
from agent_bridge_guard.models import Plan
from agent_bridge_guard.providers.debridge import FULFILLED_ORDER_TOPIC

SIGNER = "0x1111111111111111111111111111111111111111"
ROUTER = "0x2222222222222222222222222222222222222222"
RECIPIENT = "0x3333333333333333333333333333333333333333"
ORDER_ID = "0x" + "ab" * 32
DESTINATION_PROXY = "0x4444444444444444444444444444444444444444"


def plan_body() -> dict[str, object]:
    return {
        "provider": {
            "name": "debridge",
            "version": "2",
            "route_id": "arb-rh-native-v2",
            "route_kind": "native_in_swap_dln_native_out",
            "destination_dln_proxy": DESTINATION_PROXY,
            "destination_fulfillment_topic": FULFILLED_ORDER_TOPIC,
        },
        "intent": {
            "created_at": "2026-07-24T21:00:00Z",
            "expires_at": "2026-07-24T21:10:00Z",
            "source_chain_id": 42161,
            "destination_chain_id": 4663,
            "amount_wei": 1_000,
            "minimum_output_wei": 900,
            "recipient": RECIPIENT,
            "expected_signer": SIGNER,
        },
        "unsigned_transaction": {
            "chain_id": 42161,
            "nonce": 7,
            "to": ROUTER,
            "value": 1_100,
            "data": "0x1234",
            "gas": 800_000,
            "max_fee_per_gas": 30_000_000,
            "max_priority_fee_per_gas": 1_000_000,
        },
        "decoded_semantics": {
            "source_order_token": "0x" + "55" * 20,
            "source_gross_amount_wei": 1_000,
            "protocol_fee_amount_wei": 1,
            "source_net_amount_wei": 999,
            "source_swap_router": "0x" + "55" * 20,
            "order_id": ORDER_ID,
            "destination_chain_id": 4663,
            "destination_receiver": RECIPIENT,
            "destination_token": "0x0000000000000000000000000000000000000000",
            "destination_amount_wei": 950,
            "external_call": False,
            "allowed_taker": None,
        },
    }


def test_execution_plan_extracts_the_exact_approved_transaction() -> None:
    plan = Plan.create(plan_body())

    execution = ExecutionPlan.from_plan(
        plan,
        at=datetime(2026, 7, 24, 21, 5, tzinfo=UTC),
    )

    assert execution.plan is plan
    assert execution.signer.lower() == SIGNER.lower()
    assert execution.transaction["nonce"] == 7
    assert execution.transaction["chain_id"] == 42161
    assert execution.order_id == ORDER_ID
    assert execution.destination_chain_id == 4663
    assert execution.minimum_output_wei == 900
    assert execution.destination_dln_proxy.lower() == DESTINATION_PROXY.lower()


def test_execution_plan_rejects_expired_or_incomplete_transaction() -> None:
    with pytest.raises(ExecutionPlanError, match="expired"):
        ExecutionPlan.from_plan(
            Plan.create(plan_body()),
            at=datetime(2026, 7, 24, 21, 10, tzinfo=UTC),
        )

    body = plan_body()
    transaction = body["unsigned_transaction"]
    assert isinstance(transaction, dict)
    del transaction["nonce"]
    with pytest.raises(ExecutionPlanError, match="transaction"):
        ExecutionPlan.from_plan(
            Plan.create(body),
            at=datetime(2026, 7, 24, 21, 5, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("intent", "source_chain_id"), 1, "source chain"),
        (("intent", "recipient"), SIGNER, "receiver"),
        (("decoded_semantics", "external_call"), True, "external"),
        (("decoded_semantics", "destination_amount_wei"), 899, "minimum"),
        (("decoded_semantics", "order_id"), "0x1234", "order"),
    ],
)
def test_execution_plan_rejects_cross_field_semantic_mismatch(
    path: tuple[str, str],
    value: object,
    message: str,
) -> None:
    body = plan_body()
    section = body[path[0]]
    assert isinstance(section, dict)
    section[path[1]] = value

    with pytest.raises(ExecutionPlanError, match=message):
        ExecutionPlan.from_plan(
            Plan.create(body),
            at=datetime(2026, 7, 24, 21, 5, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    ("gross", "fee", "net", "message"),
    [
        (1_000, -1, 1_001, "protocol fee amount must be a non-negative"),
        (1_000, 1_000, 1, "source order fee accounting mismatch"),
        (1_000, 1, 1_000, "source order fee accounting mismatch"),
    ],
)
def test_execution_plan_rejects_invalid_source_fee_accounting(
    gross: int, fee: int, net: int, message: str
) -> None:
    body = plan_body()
    semantics = body["decoded_semantics"]
    assert isinstance(semantics, dict)
    semantics.update(
        {
            "source_gross_amount_wei": gross,
            "protocol_fee_amount_wei": fee,
            "source_net_amount_wei": net,
        }
    )

    with pytest.raises(ExecutionPlanError, match=message):
        ExecutionPlan.from_plan(
            Plan.create(body),
            at=datetime(2026, 7, 24, 21, 5, tzinfo=UTC),
        )
