from __future__ import annotations

from agent_bridge_guard.models import Plan
from agent_bridge_guard.providers.debridge import FULFILLED_ORDER_TOPIC
from agent_bridge_guard.tracking import DeBridgeTrackingClient, TrackingPending

SIGNER = "0x1111111111111111111111111111111111111111"
RECIPIENT = "0x2222222222222222222222222222222222222222"
ORDER_ID = "0x" + "ab" * 32
SOURCE_TX = "0x" + "cd" * 32
DESTINATION_TX = "0x" + "ef" * 32


def plan() -> Plan:
    return Plan.create(
        {
            "provider": {
                "name": "debridge",
                "version": "2",
                "route_id": "arb-rh-native-v2",
                "route_kind": "native_in_swap_dln_native_out",
                "destination_dln_proxy": "0x" + "33" * 20,
                "destination_fulfillment_topic": FULFILLED_ORDER_TOPIC,
            },
            "intent": {
                "created_at": "2026-07-24T20:00:00Z",
                "expires_at": "2026-07-24T20:01:00Z",
                "source_chain_id": 42161,
                "destination_chain_id": 4663,
                "amount_wei": 1,
                "minimum_output_wei": 900,
                "recipient": RECIPIENT,
                "expected_signer": SIGNER,
            },
            "unsigned_transaction": {
                "chain_id": 42161,
                "nonce": 1,
                "to": "0x" + "44" * 20,
                "value": 1,
                "data": "0x12",
                "gas": 1,
                "max_fee_per_gas": 1,
                "max_priority_fee_per_gas": 0,
            },
            "decoded_semantics": {
                "source_order_token": "0x" + "55" * 20,
                "source_gross_amount_wei": 2,
                "protocol_fee_amount_wei": 1,
                "source_net_amount_wei": 1,
                "source_swap_router": "0x" + "55" * 20,
                "order_id": ORDER_ID,
                "destination_chain_id": 4663,
                "destination_receiver": RECIPIENT,
                "destination_token": "0x" + "00" * 20,
                "destination_amount_wei": 950,
                "external_call": False,
                "allowed_taker": None,
            },
        }
    )


def value(text: str) -> dict[str, str]:
    return {"stringValue": text}


def fulfilled_status() -> dict[str, object]:
    return {
        "orderId": value(ORDER_ID),
        "state": "Fulfilled",
        "externalCallState": "NoExtCall",
        "receiverDst": value(RECIPIENT),
        "givePatchAuthoritySrc": value(SIGNER),
        "orderAuthorityAddressDst": value(RECIPIENT),
        "createdSrcEventMetadata": {
            "transactionHash": value(SOURCE_TX),
            "initiator": value(SIGNER),
        },
        "giveOfferWithMetadata": {"chainId": value("42161")},
        "takeOfferWithMetadata": {
            "chainId": value("4663"),
            "tokenAddress": value("0x" + "00" * 20),
            "finalAmount": value("950"),
        },
        "fulfilledDstEventMetadata": {"transactionHash": value(DESTINATION_TX)},
    }


def test_tracking_is_advisory_discovery_but_binds_exact_order_and_parties() -> None:
    def get(url: str) -> object:
        if url.endswith(f"/Transaction/{SOURCE_TX}/orderIds"):
            return {"orderIds": [ORDER_ID]}
        if url.endswith(f"/Orders/{ORDER_ID}"):
            return fulfilled_status()
        raise AssertionError("unexpected tracking URL")

    result = DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
        plan(),
        SOURCE_TX,
    )

    assert result.order_id == ORDER_ID
    assert result.destination_transaction_hash == DESTINATION_TX
    assert result.final_amount_wei == 950


def test_tracking_pending_is_not_misreported_as_fulfillment() -> None:
    def get(url: str) -> object:
        if "/Transaction/" in url:
            return {"orderIds": [ORDER_ID]}
        return {"orderId": value(ORDER_ID), "state": "Created"}

    try:
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            plan(),
            SOURCE_TX,
        )
    except TrackingPending as error:
        assert error.state == "Created"
    else:
        raise AssertionError("pending order was treated as fulfilled")
