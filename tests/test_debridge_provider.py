"""Characterization and adversarial tests for the deBridge quote boundary.

The fixtures are ABI builders rather than provider-shaped mocks. They let the
tests mutate one property of an ABI-valid synthetic calldata payload at a time.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agent_bridge_guard.providers import debridge
from agent_bridge_guard.providers.debridge import (
    FULFILLED_ORDER_TOPIC,
    NATIVE_TOKEN,
    DeBridgeProvider,
    QuoteRequest,
    RoutePolicy,
    create_plan,
    decode_fulfilled_order,
    decode_strictly_swap_and_call,
    deterministic_order_id,
    validate_cancellation_events,
    validate_quote,
)

SOURCE_CHAIN = 42161
DESTINATION_CHAIN = 4663
SIGNER = "0x" + "11" * 20
RECIPIENT = "0x" + "22" * 20
BRIDGE_ROUTER = "0x" + "33" * 20
SWAP_ROUTER = "0x" + "44" * 20
INTERMEDIARY_TOKEN = "0x" + "88" * 20
DLN_SOURCE = "0x" + "55" * 20
REFUND_RECIPIENT = SIGNER
DESTINATION_PROXY = "0x" + "66" * 20
ALLOWED_TAKER = "0x" + "77" * 20
AMOUNT = 1_000
OUTPUT = 900
GAS_LIMIT = 100
MAX_FEE = 2
PROTOCOL_FEE = 10
SWAP_SELECTOR = "0x12345678"
SYNTHETIC_SOURCE_TX = "0x" + "99" * 32


def test_synthetic_source_transaction_fixture_preserves_route_math() -> None:
    """Synthetic invariant fixture; never contacts a chain in tests."""
    fixture = {
        "transaction_hash": SYNTHETIC_SOURCE_TX,
        "source_chain_id": SOURCE_CHAIN,
        "router": BRIDGE_ROUTER,
        "value_wei": 1_005,
        "native_input_wei": AMOUNT,
        "intermediary_token": INTERMEDIARY_TOKEN,
        "gross_amount": AMOUNT,
        "protocol_fee": PROTOCOL_FEE,
        "net_amount": AMOUNT - PROTOCOL_FEE,
        "source_swap_router": SWAP_ROUTER,
    }

    assert fixture["value_wei"] - fixture["native_input_wei"] == 5
    assert fixture["gross_amount"] - fixture["protocol_fee"] == fixture["net_amount"]
    assert debridge.canonical_address(str(fixture["router"])) == fixture["router"]
    assert (
        debridge.canonical_address(str(fixture["intermediary_token"]))
        == fixture["intermediary_token"]
    )
    assert (
        debridge.canonical_address(str(fixture["source_swap_router"]))
        == fixture["source_swap_router"]
    )


def word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def address_word(value: str) -> bytes:
    return word(int(value[2:], 16))


def dynamic(value: bytes) -> bytes:
    return word(len(value)) + value + b"\0" * ((-len(value)) % 32)


def dynamic_tuple(fields: list[int | bytes]) -> bytes:
    """Encode a tuple with uint words and ABI dynamic byte fields."""
    head = bytearray(32 * len(fields))
    tail = bytearray()
    for index, value in enumerate(fields):
        if isinstance(value, int):
            head[index * 32 : (index + 1) * 32] = word(value)
        else:
            offset = len(head) + len(tail)
            head[index * 32 : (index + 1) * 32] = word(offset)
            tail.extend(dynamic(value))
    return bytes(head + tail)


def create_salted_order_calldata(
    *,
    give_token: str = INTERMEDIARY_TOKEN,
    give_amount: int = AMOUNT,
    take_amount: int = OUTPUT,
    take_chain: int = DESTINATION_CHAIN,
    receiver: str = RECIPIENT,
    take_authority: str = RECIPIENT,
    allowed_taker: bytes = bytes.fromhex(ALLOWED_TAKER[2:]),
    external_call: bytes = b"",
    cancel_beneficiary: bytes = bytes.fromhex(SIGNER[2:]),
    affiliate_fee: bytes = b"",
    permit: bytes = b"",
    metadata: bytes = b"",
    referral_code: int = 0,
) -> str:
    order = dynamic_tuple(
        [
            int(give_token[2:], 16),
            give_amount,
            bytes.fromhex(NATIVE_TOKEN[2:]),
            take_amount,
            take_chain,
            bytes.fromhex(receiver[2:]),
            int(SIGNER[2:], 16),
            bytes.fromhex(take_authority[2:]),
            allowed_taker,
            external_call,
            cancel_beneficiary,
        ]
    )
    head_size = 6 * 32
    affiliate = dynamic(affiliate_fee)
    permit_data = dynamic(permit)
    metadata_data = dynamic(metadata)
    order_offset = head_size
    affiliate_offset = order_offset + len(order)
    permit_offset = affiliate_offset + len(affiliate)
    metadata_offset = permit_offset + len(permit_data)
    body = b"".join(
        (
            word(order_offset),
            word(7),
            word(affiliate_offset),
            word(referral_code),
            word(permit_offset),
            word(metadata_offset),
            order,
            affiliate,
            permit_data,
            metadata_data,
        )
    )
    return debridge.CREATE_SALTED_ORDER_SELECTOR + body.hex()


def strict_swap_calldata(
    *,
    input_amount: int = AMOUNT,
    input_token: str = NATIVE_TOKEN,
    source_swap_router: str = SWAP_ROUTER,
    refund_recipient: str = REFUND_RECIPIENT,
    dln_source: str = DLN_SOURCE,
    swap_permit: bytes = b"",
    swap_calldata: bytes = bytes.fromhex(SWAP_SELECTOR[2:]),
    swap_token_out: str = INTERMEDIARY_TOKEN,
    swap_minimum_amount_out: int = AMOUNT,
    target: str | None = None,
    **order_overrides: Any,
) -> str:
    target_bytes = bytes.fromhex((target or create_salted_order_calldata(**order_overrides))[2:])
    permit = dynamic(swap_permit)
    swap_data = dynamic(swap_calldata)
    target_data = dynamic(target_bytes)
    head_size = 10 * 32
    permit_offset = head_size
    swap_data_offset = permit_offset + len(permit)
    target_offset = swap_data_offset + len(swap_data)
    body = b"".join(
        (
            address_word(input_token),
            word(input_amount),
            word(permit_offset),
            address_word(source_swap_router),
            word(swap_data_offset),
            address_word(swap_token_out),
            word(swap_minimum_amount_out),
            address_word(refund_recipient),
            address_word(dln_source),
            word(target_offset),
            permit,
            swap_data,
            target_data,
        )
    )
    return debridge.STRICT_SWAP_AND_CALL_SELECTOR + body.hex()


@pytest.fixture
def quote_request() -> QuoteRequest:
    return QuoteRequest(
        source_chain_id=SOURCE_CHAIN,
        destination_chain_id=DESTINATION_CHAIN,
        amount_wei=AMOUNT,
        minimum_output_wei=OUTPUT,
        signer=SIGNER,
        recipient=RECIPIENT,
        nonce=7,
        created_at="2026-07-24T00:00:00Z",
        expires_at="2026-07-24T00:01:00Z",
    )


@pytest.fixture
def policy() -> RoutePolicy:
    return RoutePolicy(
        allowed_bridge_routers=(BRIDGE_ROUTER,),
        allowed_source_swap_routers=(SWAP_ROUTER,),
        allowed_source_swap_selectors=(SWAP_SELECTOR,),
        allowed_intermediary_give_tokens=(INTERMEDIARY_TOKEN,),
        allowed_dln_sources=(DLN_SOURCE,),
        allowed_refund_recipients=(REFUND_RECIPIENT,),
        destination_dln_proxy=DESTINATION_PROXY,
        destination_fulfillment_topic=FULFILLED_ORDER_TOPIC,
        maximum_total_spend_wei=1_300,
        maximum_value_overhead_wei=10,
        maximum_price_impact_bps=10,
        maximum_swap_calldata_bytes=64,
        maximum_metadata_bytes=32,
        route_id="test-native-swap-route",
        maximum_quote_age_seconds=60,
    )


def valid_quote(**calldata_overrides: Any) -> dict[str, object]:
    calldata = strict_swap_calldata(**calldata_overrides)
    decoded = decode_strictly_swap_and_call(calldata)
    nested = decoded["create_salted_order"]
    assert isinstance(nested, dict)
    order = nested["order"]
    assert isinstance(order, dict)
    order_id = deterministic_order_id(
        {**order, "give_chain_id": SOURCE_CHAIN, "give_amount": AMOUNT - PROTOCOL_FEE},
        maker=SIGNER,
    )
    return {
        "createdAt": "2026-07-24T00:00:00Z",
        "expiresAt": "2026-07-24T00:00:30Z",
        "estimation": {
            "srcChainTokenIn": {
                "chainId": SOURCE_CHAIN,
                "address": NATIVE_TOKEN,
                "amount": str(AMOUNT),
            },
            "srcChainTokenOut": {
                "chainId": SOURCE_CHAIN,
                "address": INTERMEDIARY_TOKEN,
                "amount": str(AMOUNT),
            },
            "dstChainTokenOut": {
                "chainId": DESTINATION_CHAIN,
                "address": NATIVE_TOKEN,
                "recommendedAmount": str(OUTPUT),
            },
        },
        "tx": {
            "to": BRIDGE_ROUTER,
            "data": calldata,
            "value": str(AMOUNT),
            "gasLimit": str(GAS_LIMIT),
        },
        "estimatedTransactionFee": {
            "details": {
                "gasLimit": str(GAS_LIMIT),
                "maxFeePerGas": str(MAX_FEE),
                "maxPriorityFeePerGas": "1",
            }
        },
        "usdPriceImpact": "0.01",
        "fixFee": "0",
        "protocolFee": str(PROTOCOL_FEE),
        "order": {"metadata": "0x" + bytes(calldata_overrides.get("metadata", b"")).hex()},
        "orderId": order_id,
    }


def direct_policy() -> RoutePolicy:
    return replace(
        policy.__wrapped__(),
        route_id="test-direct-reserve-route",
        route_kind=debridge.RESERVE_ERC20_DLN_NATIVE_OUT,
        source_reserve_token=INTERMEDIARY_TOKEN,
        source_dln_proxy=BRIDGE_ROUTER,
        source_dln_implementation_codehash="0x" + "aa" * 32,
        allowed_takers=(ALLOWED_TAKER,),
        maximum_fixed_native_fee_wei=10,
        maximum_input_token_amount=AMOUNT,
        maximum_gas_limit=GAS_LIMIT,
        expected_global_transfer_fee_bps=100,
    )


def direct_quote() -> dict[str, object]:
    calldata = create_salted_order_calldata(give_token=INTERMEDIARY_TOKEN, give_amount=AMOUNT)
    decoded = debridge.decode_create_salted_order(calldata)
    order = decoded["order"]
    assert isinstance(order, dict)
    order_id = deterministic_order_id(
        {
            **order,
            "give_chain_id": SOURCE_CHAIN,
            "give_amount": AMOUNT - PROTOCOL_FEE,
        },
        maker=SIGNER,
    )
    return {
        "createdAt": "2026-07-24T00:00:00Z",
        "expiresAt": "2026-07-24T00:00:30Z",
        "estimation": {
            "srcChainTokenIn": {
                "chainId": SOURCE_CHAIN,
                "address": INTERMEDIARY_TOKEN,
                "amount": str(AMOUNT),
            },
            "dstChainTokenOut": {
                "chainId": DESTINATION_CHAIN,
                "address": NATIVE_TOKEN,
                "recommendedAmount": str(OUTPUT),
            },
        },
        "tx": {"to": BRIDGE_ROUTER, "value": "5", "data": calldata, "gasLimit": str(GAS_LIMIT)},
        "order": {"metadata": "0x"},
        "orderId": order_id,
        "fixFee": "5",
        "protocolFee": str(PROTOCOL_FEE),
        "usdPriceImpact": "0",
        "estimatedTransactionFee": {
            "details": {
                "gasLimit": str(GAS_LIMIT),
                "maxFeePerGas": str(MAX_FEE),
                "maxPriorityFeePerGas": "0",
            }
        },
    }


def test_direct_reserve_quote_rejects_source_aggregator_and_accepts_exact_direct_order(
    quote_request: QuoteRequest,
) -> None:
    quote = direct_quote()
    validated = validate_quote(
        quote, quote_request, direct_policy(), now=datetime(2026, 7, 24, tzinfo=UTC)
    )
    assert validated["source_order_token"] == INTERMEDIARY_TOKEN
    assert validated["source_gross_amount_wei"] == AMOUNT
    assert validated["source_net_amount_wei"] == AMOUNT - PROTOCOL_FEE
    quote["estimation"]["srcChainTokenOut"] = {}  # type: ignore[index]
    with pytest.raises(ValueError, match="must not include a source swap output"):
        validate_quote(quote, quote_request, direct_policy(), now=datetime(2026, 7, 24, tzinfo=UTC))


def validate(
    response: object, quote_request: QuoteRequest, policy: RoutePolicy
) -> dict[str, object]:
    return validate_quote(response, quote_request, policy, now=datetime(2026, 7, 24, tzinfo=UTC))


def test_valid_quote_binds_all_execution_fields(
    quote_request: QuoteRequest, policy: RoutePolicy
) -> None:
    result = validate(valid_quote(), quote_request, policy)

    assert result == {
        "bridge_router": BRIDGE_ROUTER,
        "data": strict_swap_calldata(),
        "value_wei": AMOUNT,
        "total_spend_wei": 1_200,
        "gas": GAS_LIMIT,
        "bounded_gas": GAS_LIMIT,
        "max_fee_per_gas": MAX_FEE,
        "max_priority_fee_per_gas": 1,
        "output_wei": OUTPUT,
        "price_impact_bps": 1,
        "order_id": valid_quote()["orderId"],
        "source_dln_target": DLN_SOURCE,
        "source_order_token": INTERMEDIARY_TOKEN,
        "source_gross_amount_wei": AMOUNT,
        "swap_minimum_amount_out_wei": AMOUNT,
        "protocol_fee_amount_wei": PROTOCOL_FEE,
        "fix_fee_amount_wei": 0,
        "source_net_amount_wei": AMOUNT - PROTOCOL_FEE,
        "source_swap_router": SWAP_ROUTER,
        "source_swap_selector": SWAP_SELECTOR,
        "source_swap_calldata_sha256": debridge.sha256(
            bytes.fromhex(SWAP_SELECTOR[2:])
        ).hexdigest(),
        "source_swap_calldata_length": 4,
        "metadata_sha256": debridge.sha256(b"").hexdigest(),
        "metadata_length": 0,
        "destination_amount_wei": OUTPUT,
        "destination_receiver": RECIPIENT,
        "allowed_taker": ALLOWED_TAKER,
        "external_call": False,
    }


def test_create_plan_binds_nonce_time_policy_and_validated_taker(
    quote_request: QuoteRequest, policy: RoutePolicy
) -> None:
    plan = create_plan(validate(valid_quote(), quote_request, policy), quote_request, policy)
    body = plan.body()

    assert body["intent"] == {
        "created_at": quote_request.created_at,
        "expires_at": quote_request.expires_at,
        "source_chain_id": SOURCE_CHAIN,
        "destination_chain_id": DESTINATION_CHAIN,
        "amount_wei": AMOUNT,
        "minimum_output_wei": OUTPUT,
        "recipient": RECIPIENT,
        "expected_signer": SIGNER,
    }
    assert body["unsigned_transaction"] == {
        "chain_id": SOURCE_CHAIN,
        "nonce": 7,
        "to": BRIDGE_ROUTER,
        "value": AMOUNT,
        "data": strict_swap_calldata(),
        "gas": GAS_LIMIT,
        "max_fee_per_gas": MAX_FEE,
        "max_priority_fee_per_gas": 1,
    }
    assert body["decoded_semantics"]["allowed_taker"] == ALLOWED_TAKER
    assert body["provider"]["route_id"] == "test-native-swap-route"
    assert body["decoded_semantics"]["source_net_amount_wei"] == AMOUNT - PROTOCOL_FEE


def test_quote_binds_allowlisted_opaque_swap_calldata_metadata_and_fee_math(
    quote_request: QuoteRequest, policy: RoutePolicy
) -> None:
    swap_calldata = bytes.fromhex(SWAP_SELECTOR[2:]) + b"opaque-route-args"
    metadata = b"route-metadata"
    quote = valid_quote(swap_calldata=swap_calldata, metadata=metadata)
    result = validate(quote, quote_request, policy)

    assert result["source_gross_amount_wei"] == AMOUNT
    assert result["protocol_fee_amount_wei"] == PROTOCOL_FEE
    assert result["source_net_amount_wei"] == AMOUNT - PROTOCOL_FEE
    assert result["source_swap_selector"] == SWAP_SELECTOR
    assert result["source_swap_calldata_sha256"] == debridge.sha256(swap_calldata).hexdigest()
    assert result["metadata_sha256"] == debridge.sha256(metadata).hexdigest()


def test_quote_rejects_empty_source_swap_calldata(
    quote_request: QuoteRequest, policy: RoutePolicy
) -> None:
    with pytest.raises(ValueError, match="swap calldata must not be empty"):
        validate(valid_quote(swap_calldata=b""), quote_request, policy)


def test_quote_binds_fixed_fee_exact_transaction_gas_and_response_metadata(
    quote_request: QuoteRequest, policy: RoutePolicy
) -> None:
    metadata = b"route-metadata"
    quote = valid_quote(metadata=metadata)
    transaction = quote["tx"]
    assert isinstance(transaction, dict)
    transaction["value"] = str(AMOUNT + 5)
    transaction["gasLimit"] = str(GAS_LIMIT - 1)
    quote["fixFee"] = "5"
    result = validate(quote, quote_request, policy)

    assert result["fix_fee_amount_wei"] == 5
    assert result["gas"] == GAS_LIMIT - 1
    assert result["bounded_gas"] == GAS_LIMIT
    assert result["total_spend_wei"] == AMOUNT + 5 + (GAS_LIMIT - 1) * MAX_FEE


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda quote: quote.update({"fixFee": "1"}), "fixed fee"),
        (lambda quote: quote["tx"].update({"gasLimit": str(GAS_LIMIT + 1)}), "gas limit"),
        (
            lambda quote: quote["order"].update({"metadata": "0x00"}),
            "metadata does not match",
        ),
    ],
)
def test_quote_rejects_unbound_fixed_fee_signed_gas_or_metadata(
    quote_request: QuoteRequest, policy: RoutePolicy, mutate: Any, match: str
) -> None:
    quote = valid_quote()
    mutate(quote)
    with pytest.raises(ValueError, match=match):
        validate(quote, quote_request, policy)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (
            lambda quote: quote["estimation"]["srcChainTokenOut"].update({"amount": "999"}),
            "order give amount",
        ),
        (lambda quote: quote.update({"protocolFee": str(AMOUNT)}), "leaves no source order"),
        (lambda quote: quote.update({"protocolFee": str(PROTOCOL_FEE + 1)}), "order ID mismatch"),
        (
            lambda quote: quote["estimation"]["srcChainTokenOut"].update({"address": SIGNER}),
            "intermediary token",
        ),
    ],
)
def test_quote_rejects_intermediary_and_protocol_fee_tampering(
    quote_request: QuoteRequest, policy: RoutePolicy, mutate: Any, match: str
) -> None:
    quote = valid_quote()
    mutate(quote)
    with pytest.raises(ValueError, match=match):
        validate(quote, quote_request, policy)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda quote: quote.update({"junk": {"nan": float("nan")}}), "strict JSON"),
        (lambda quote: quote.update({"estimation": []}), "estimation must be an object"),
        (
            lambda quote: quote["estimation"]["srcChainTokenIn"].update(
                {"chainId": DESTINATION_CHAIN}
            ),
            "source chain",
        ),
        (
            lambda quote: quote["estimation"]["srcChainTokenIn"].update({"address": SIGNER}),
            "source token",
        ),
        (
            lambda quote: quote["estimation"]["srcChainTokenIn"].update({"amount": "999"}),
            "source amount",
        ),
        (
            lambda quote: quote["estimation"]["dstChainTokenOut"].update(
                {"recommendedAmount": "899"}
            ),
            "destination amount",
        ),
        (lambda quote: quote.update({"usdPriceImpact": "0.11"}), "price impact"),
        (lambda quote: quote["tx"].update({"to": SIGNER}), "bridge router"),
        (lambda quote: quote["tx"].update({"value": "999"}), "transaction value"),
        (lambda quote: quote["tx"].update({"value": "1011"}), "transaction value"),
        (
            lambda quote: quote["estimatedTransactionFee"]["details"].update(
                {"maxPriorityFeePerGas": "3"}
            ),
            "priority fee",
        ),
        (lambda quote: quote.update({"orderId": "0x12"}), "order ID"),
    ],
    ids=[
        "non-strict-json",
        "missing-estimation-object",
        "wrong-source-chain",
        "non-native-input",
        "input-amount-drift",
        "output-below-minimum",
        "impact-over-policy",
        "bridge-router-not-allowlisted",
        "value-below-input",
        "value-above-input",
        "priority-over-max-fee",
        "malformed-order-id",
    ],
)
def test_quote_rejects_schema_and_policy_mutations(
    quote_request: QuoteRequest,
    policy: RoutePolicy,
    mutation: Any,
    match: str,
) -> None:
    quote = valid_quote()
    mutation(quote)
    with pytest.raises(ValueError, match=match):
        validate(quote, quote_request, policy)


@pytest.mark.parametrize(
    ("calldata_kwargs", "match"),
    [
        ({"input_token": SIGNER}, "swap input is not native"),
        ({"input_amount": 999}, "swap input amount"),
        ({"source_swap_router": SIGNER}, "source swap router"),
        ({"refund_recipient": RECIPIENT}, "refund recipient"),
        ({"dln_source": SIGNER}, "DLN source"),
        ({"swap_permit": b"permit"}, "swap permit"),
        ({"swap_calldata": b"swap"}, "swap calldata"),
        ({"swap_token_out": SIGNER}, "swap output token"),
        ({"swap_minimum_amount_out": OUTPUT - 1}, "swap minimum output"),
        ({"give_token": SIGNER}, "order give token"),
        ({"give_amount": AMOUNT - 1}, "order give amount"),
        ({"take_amount": 899}, "destination amount"),
        ({"take_chain": SOURCE_CHAIN}, "destination chain"),
        ({"receiver": SIGNER}, "destination receiver"),
        ({"take_authority": SIGNER}, "destination authority"),
        ({"cancel_beneficiary": bytes.fromhex(RECIPIENT[2:])}, "cancel beneficiary"),
        ({"affiliate_fee": b"fee"}, "affiliate fees"),
        ({"permit": b"permit"}, "affiliate fees"),
        ({"metadata": b"x" * 33}, "metadata"),
        ({"referral_code": 1}, "referral code"),
    ],
    ids=[
        "input-token",
        "input-amount",
        "source-swap-router",
        "refund-recipient",
        "dln-source",
        "swap-permit",
        "swap-calldata",
        "swap-output-token",
        "swap-minimum-output",
        "order-give-token",
        "order-give-amount",
        "take-amount",
        "take-chain",
        "receiver",
        "take-authority",
        "cancel-beneficiary",
        "affiliate-fee",
        "nested-permit",
        "metadata",
        "referral-code",
    ],
)
def test_quote_rejects_decoded_calldata_policy_mutations(
    quote_request: QuoteRequest,
    policy: RoutePolicy,
    calldata_kwargs: dict[str, object],
    match: str,
) -> None:
    quote = valid_quote(**calldata_kwargs)
    with pytest.raises(ValueError, match=match):
        validate(quote, quote_request, policy)


def test_quote_rejects_an_external_call_before_accepting_provider_order_id(
    quote_request: QuoteRequest, policy: RoutePolicy
) -> None:
    quote = valid_quote()
    transaction = quote["tx"]
    assert isinstance(transaction, dict)
    transaction["data"] = strict_swap_calldata(external_call=b"forbidden")

    with pytest.raises(ValueError, match="external calls"):
        validate(quote, quote_request, policy)


def test_quote_rejects_a_provider_order_id_that_does_not_bind_calldata(
    quote_request: QuoteRequest, policy: RoutePolicy
) -> None:
    quote = valid_quote()
    quote["orderId"] = "0x" + "00" * 32

    with pytest.raises(ValueError, match="order ID mismatch"):
        validate(quote, quote_request, policy)


def test_quote_rejects_oversized_provider_response(
    quote_request: QuoteRequest, policy: RoutePolicy
) -> None:
    quote = valid_quote()
    quote["padding"] = "x" * debridge.MAX_RESPONSE_BYTES

    with pytest.raises(ValueError, match="size limit"):
        validate(quote, quote_request, policy)


@pytest.mark.parametrize(
    ("created_at", "expires_at", "policy_age", "match"),
    [
        ("2026-07-24T00:01:00Z", "2026-07-24T00:00:00Z", 60, "expires_at"),
        ("2026-07-24T00:00:00Z", "2026-07-24T00:01:00Z", -1, "quote age"),
    ],
)
def test_quote_rejects_invalid_request_time_or_age_policy(
    quote_request: QuoteRequest,
    policy: RoutePolicy,
    created_at: str,
    expires_at: str,
    policy_age: int,
    match: str,
) -> None:
    changed_request = replace(quote_request, created_at=created_at, expires_at=expires_at)
    changed_policy = replace(policy, maximum_quote_age_seconds=policy_age)

    with pytest.raises(ValueError, match=match):
        validate(valid_quote(), changed_request, changed_policy)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (
            lambda quote: quote.update({"created_at": "2026-07-24T00:00:00Z"}),
            "ambiguous created timestamps",
        ),
        (
            lambda quote: quote.update({"createdAt": "2026-07-24T00:01:00Z"}),
            "too far in the future",
        ),
    ],
    ids=["ambiguous", "future-skew"],
)
def test_quote_age_policy_requires_one_nonfuture_created_timestamp(
    quote_request: QuoteRequest, policy: RoutePolicy, mutate: Any, match: str
) -> None:
    quote = valid_quote()
    mutate(quote)
    with pytest.raises(ValueError, match=match):
        validate(quote, quote_request, policy)


def test_quote_without_provider_timestamp_uses_local_request_start(
    quote_request: QuoteRequest,
    policy: RoutePolicy,
) -> None:
    quote = valid_quote()
    quote.pop("createdAt")

    validated = validate(quote, quote_request, policy)

    assert validated["order_id"] == quote["orderId"]


def test_provider_rejects_non_https_before_transport_is_called(
    quote_request: QuoteRequest, policy: RoutePolicy
) -> None:
    calls: list[str] = []
    provider = DeBridgeProvider(lambda url: calls.append(url) or valid_quote())

    with pytest.raises(ValueError, match="HTTPS"):
        provider.quote("http://quote.invalid", quote_request, policy)
    assert calls == []


def test_provider_encodes_request_without_secret_or_unbounded_fields(
    quote_request: QuoteRequest, policy: RoutePolicy
) -> None:
    calls: list[str] = []

    def response(url: str) -> object:
        calls.append(url)
        quote = valid_quote()
        quote.pop("createdAt")
        quote.pop("expiresAt")
        return quote

    provider = DeBridgeProvider(response)

    provider.quote(
        "https://quote.invalid/api",
        quote_request,
        replace(policy, maximum_quote_age_seconds=None),
    )

    assert len(calls) == 1
    assert "srcChainId=42161" in calls[0]
    assert "dstChainId=4663" in calls[0]
    assert "srcChainTokenInAmount=1000" in calls[0]
    assert "0x1111111111111111111111111111111111111111" in calls[0]


def test_dual_rpc_source_preflight_binds_router_exact_call_gas_and_balance() -> None:
    calls: list[tuple[str, list[object]]] = []

    def rpc(method: str, params: list[object]) -> object:
        calls.append((method, params))
        if method == "eth_call":
            transaction = params[0]
            assert isinstance(transaction, dict)
            router_selector = "0x" + debridge.keccak(b"supportedRouters(address)")[:4].hex()
            if transaction.get("data", "").startswith(router_selector):
                return "0x" + "00" * 31 + "01"
            assert transaction == {
                "from": SIGNER,
                "to": BRIDGE_ROUTER,
                "value": hex(AMOUNT),
                "data": strict_swap_calldata(),
            }
            return "0x"
        if method == "eth_estimateGas":
            return hex(GAS_LIMIT)
        if method == "eth_getTransactionCount":
            assert params == [SIGNER, params[1]]
            assert params[1] in {"latest", "pending"}
            return hex(7)
        if method == "eth_getBalance":
            return hex(1_300)
        raise AssertionError(method)

    result = debridge.preflight_source_transaction(
        rpc,
        rpc,
        signer=SIGNER,
        bridge_router=BRIDGE_ROUTER,
        value_wei=AMOUNT,
        data=strict_swap_calldata(),
        source_swap_router=SWAP_ROUTER,
        nonce=7,
        maximum_gas=GAS_LIMIT,
        required_total_spend_wei=1_200,
    )

    assert result["gas"] == GAS_LIMIT
    assert result["nonce"] == 7
    assert result["required_total_spend_wei"] == 1_200
    assert [method for method, _ in calls].count("eth_call") == 4
    assert [method for method, _ in calls].count("eth_getTransactionCount") == 4


def direct_rpc(
    *,
    allowance: int = AMOUNT,
    reserve_balance: int = AMOUNT,
    native_balance: int = 500,
    observed_fixed_fee: int = 5,
    observed_transfer_fee: int = 100,
    gas: int = GAS_LIMIT,
    latest_nonce: int = 7,
    pending_nonce: int = 7,
    simulation_result: object = "0x",
    implementation_slot_override: object | None = None,
    implementation_code: object = "0x6000",
) -> Any:
    implementation = "0x" + "99" * 20
    implementation_slot = (
        "0x" + "00" * 12 + implementation[2:]
        if implementation_slot_override is None
        else implementation_slot_override
    )
    balance_selector = "0x" + debridge.keccak(b"balanceOf(address)")[:4].hex()
    allowance_selector = "0x" + debridge.keccak(b"allowance(address,address)")[:4].hex()
    fixed_fee_selector = "0x" + debridge.keccak(b"globalFixedNativeFee()")[:4].hex()
    transfer_fee_selector = "0x" + debridge.keccak(b"globalTransferFeeBps()")[:4].hex()

    def call(method: str, params: list[object]) -> object:
        if method == "eth_call":
            transaction = params[0]
            assert isinstance(transaction, dict)
            selector = str(transaction.get("data", ""))[:10]
            if transaction.get("to") == INTERMEDIARY_TOKEN:
                if selector == balance_selector:
                    return hex(reserve_balance)
                if selector == allowance_selector:
                    return hex(allowance)
            if transaction.get("to") == BRIDGE_ROUTER:
                if selector == fixed_fee_selector:
                    return hex(observed_fixed_fee)
                if selector == transfer_fee_selector:
                    return hex(observed_transfer_fee)
                assert transaction == {
                    "from": SIGNER,
                    "to": BRIDGE_ROUTER,
                    "value": hex(5),
                    "data": direct_quote()["tx"]["data"],
                }
                return simulation_result
            raise AssertionError(transaction)
        if method == "eth_estimateGas":
            return hex(gas)
        if method == "eth_getStorageAt":
            return implementation_slot
        if method == "eth_getCode":
            assert params[0] == implementation
            return implementation_code
        if method == "eth_getTransactionCount":
            return hex(latest_nonce if params[1] == "latest" else pending_nonce)
        if method == "eth_getBalance":
            return hex(native_balance)
        raise AssertionError(method)

    return call


def test_direct_source_preflight_requires_exact_gross_allowance_and_dual_rpc_evidence() -> None:
    expected_codehash = "0x" + debridge.keccak(bytes.fromhex("6000")).hex()

    result = debridge.preflight_reserve_erc20_source_transaction(
        direct_rpc(),
        direct_rpc(),
        signer=SIGNER,
        dln_proxy=BRIDGE_ROUTER,
        reserve_token=INTERMEDIARY_TOKEN,
        amount_wei=AMOUNT,
        fixed_fee_wei=5,
        data=str(direct_quote()["tx"]["data"]),
        nonce=7,
        maximum_gas=GAS_LIMIT,
        required_native_spend_wei=205,
        expected_implementation_codehash=expected_codehash,
        expected_global_transfer_fee_bps=100,
    )

    assert result["allowance_wei"] == AMOUNT
    assert result["reserve_balance_wei"] == AMOUNT
    assert result["implementation_codehash"] == expected_codehash


@pytest.mark.parametrize("allowance", [AMOUNT - 1, AMOUNT + 1])
def test_direct_source_preflight_rejects_under_or_over_approval(allowance: int) -> None:
    expected_codehash = "0x" + debridge.keccak(bytes.fromhex("6000")).hex()

    with pytest.raises(ValueError, match="allowance must equal"):
        debridge.preflight_reserve_erc20_source_transaction(
            direct_rpc(allowance=allowance),
            direct_rpc(allowance=allowance),
            signer=SIGNER,
            dln_proxy=BRIDGE_ROUTER,
            reserve_token=INTERMEDIARY_TOKEN,
            amount_wei=AMOUNT,
            fixed_fee_wei=5,
            data=str(direct_quote()["tx"]["data"]),
            nonce=7,
            maximum_gas=GAS_LIMIT,
            required_native_spend_wei=205,
            expected_implementation_codehash=expected_codehash,
            expected_global_transfer_fee_bps=100,
        )


@pytest.mark.parametrize(
    ("primary_gas", "secondary_gas", "balance", "match"),
    [
        (GAS_LIMIT, GAS_LIMIT + 1, 1_300, "gas estimates disagree"),
        (GAS_LIMIT + 1, GAS_LIMIT + 1, 1_300, "exceeds signed gas"),
        (GAS_LIMIT, GAS_LIMIT, 1_199, "balance cannot cover"),
    ],
)
def test_dual_rpc_source_preflight_fails_closed(
    primary_gas: int, secondary_gas: int, balance: int, match: str
) -> None:
    def rpc(gas: int):
        def call(method: str, _params: list[object]) -> object:
            if method == "eth_call":
                exact_transaction = {
                    "from": SIGNER,
                    "to": BRIDGE_ROUTER,
                    "value": hex(AMOUNT),
                    "data": strict_swap_calldata(),
                }
                return "0x" + "00" * 31 + "01" if _params[0] != exact_transaction else "0x"
            if method == "eth_estimateGas":
                return hex(gas)
            if method == "eth_getTransactionCount":
                return hex(7)
            if method == "eth_getBalance":
                return hex(balance)
            raise AssertionError(method)

        return call

    with pytest.raises(ValueError, match=match):
        debridge.preflight_source_transaction(
            rpc(primary_gas),
            rpc(secondary_gas),
            signer=SIGNER,
            bridge_router=BRIDGE_ROUTER,
            value_wei=AMOUNT,
            data=strict_swap_calldata(),
            source_swap_router=SWAP_ROUTER,
            nonce=7,
            maximum_gas=GAS_LIMIT,
            required_total_spend_wei=1_200,
        )


@pytest.mark.parametrize(
    ("primary_latest", "primary_pending", "secondary_latest", "secondary_pending", "match"),
    [
        (8, 8, 8, 8, "does not match planned nonce"),
        (7, 8, 7, 8, "source nonce counts disagree"),
        (7, 7, 8, 8, "source nonce counts disagree"),
    ],
)
def test_dual_rpc_source_preflight_rejects_nonce_drift_or_disagreement(
    primary_latest: int,
    primary_pending: int,
    secondary_latest: int,
    secondary_pending: int,
    match: str,
) -> None:
    def rpc(latest: int, pending: int):
        def call(method: str, params: list[object]) -> object:
            if method == "eth_call":
                exact_transaction = {
                    "from": SIGNER,
                    "to": BRIDGE_ROUTER,
                    "value": hex(AMOUNT),
                    "data": strict_swap_calldata(),
                }
                return "0x" + "00" * 31 + "01" if params[0] != exact_transaction else "0x"
            if method == "eth_estimateGas":
                return hex(GAS_LIMIT)
            if method == "eth_getTransactionCount":
                return hex(latest if params[1] == "latest" else pending)
            if method == "eth_getBalance":
                return hex(1_300)
            raise AssertionError(method)

        return call

    with pytest.raises(ValueError, match=match):
        debridge.preflight_source_transaction(
            rpc(primary_latest, primary_pending),
            rpc(secondary_latest, secondary_pending),
            signer=SIGNER,
            bridge_router=BRIDGE_ROUTER,
            value_wei=AMOUNT,
            data=strict_swap_calldata(),
            source_swap_router=SWAP_ROUTER,
            nonce=7,
            maximum_gas=GAS_LIMIT,
            required_total_spend_wei=1_200,
        )


def fulfilled_log() -> dict[str, object]:
    """Minimal ABI-valid fulfillment event matching the deployed event ABI."""
    fields: list[int | bytes] = [
        7,
        bytes.fromhex(SIGNER[2:]),
        SOURCE_CHAIN,
        bytes.fromhex(NATIVE_TOKEN[2:]),
        AMOUNT,
        DESTINATION_CHAIN,
        bytes.fromhex(NATIVE_TOKEN[2:]),
        OUTPUT,
        bytes.fromhex(RECIPIENT[2:]),
        bytes.fromhex(SIGNER[2:]),
        bytes.fromhex(RECIPIENT[2:]),
        bytes.fromhex(ALLOWED_TAKER[2:]),
        bytes.fromhex(SIGNER[2:]),
        b"",
    ]
    order_id = bytes.fromhex(
        deterministic_order_id(
            {
                "salt": fields[0],
                "give_chain_id": fields[2],
                "give_token": NATIVE_TOKEN,
                "give_amount": fields[4],
                "take_chain_id": fields[5],
                "take_token": fields[6],
                "take_amount": fields[7],
                "receiver": fields[8],
                "give_authority": SIGNER,
                "take_authority": fields[10],
                "allowed_taker": fields[11],
                "cancel_beneficiary": fields[12],
                "external_call": fields[13],
            },
            maker=SIGNER,
        )[2:]
    )
    head = word(160) + order_id + word(OUTPUT) + word(1) + word(1)
    return {
        "address": DESTINATION_PROXY,
        "topics": [FULFILLED_ORDER_TOPIC],
        "data": "0x" + (head + dynamic_tuple(fields)).hex(),
    }


def decode_test_log(log: object) -> dict[str, object]:
    assert isinstance(log, dict)
    data = log["data"]
    assert isinstance(data, str)
    order_id = "0x" + bytes.fromhex(data[2:])[32:64].hex()
    return decode_fulfilled_order(
        log,
        destination_proxy=DESTINATION_PROXY,
        expected_order_id=order_id,
        expected_signer=SIGNER,
        source_chain_id=SOURCE_CHAIN,
        source_token=NATIVE_TOKEN,
        source_amount_wei=AMOUNT,
        destination_chain_id=DESTINATION_CHAIN,
        receiver=RECIPIENT,
        destination_token=NATIVE_TOKEN,
        minimum_amount_wei=OUTPUT,
        expected_take_amount_wei=OUTPUT,
        expected_allowed_taker=ALLOWED_TAKER,
    )


def test_fulfillment_binds_proxy_order_chain_receiver_native_amount_and_taker() -> None:
    result = decode_test_log(fulfilled_log())
    assert result == {
        "order_id": result["order_id"],
        "amount_wei": OUTPUT,
        "receiver": RECIPIENT,
        "destination_token": NATIVE_TOKEN,
        "external_call": False,
    }


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda log: log.update({"address": SIGNER}), "proxy"),
        (lambda log: log.update({"topics": []}), "topic"),
        (lambda log: log.update({"data": "0x1234"}), "truncated"),
    ],
    ids=["wrong-proxy", "wrong-topic", "truncated-data"],
)
def test_fulfillment_rejects_unbound_log_shape(mutate: Any, match: str) -> None:
    log = fulfilled_log()
    mutate(log)
    with pytest.raises(ValueError, match=match):
        decode_test_log(log)


def test_synthetic_fulfillment_fixture_binds_every_identifier() -> None:
    fixture_path = Path(__file__).parent / "fixtures/debridge/fulfilled_order_synthetic.json"
    fixture = json.loads(fixture_path.read_text())
    expected = fixture["expected"]
    assert isinstance(expected, dict)
    raw_data = debridge._hex(fixture["data"], "fixture fulfillment data", required=True)
    synthetic_order = debridge._decode_fulfilled_order_tuple(
        raw_data, debridge._word(raw_data, 0, "fixture order offset")
    )
    give_token = synthetic_order["give_token"]
    give_amount = synthetic_order["give_amount"]
    assert isinstance(give_token, bytes)
    assert isinstance(give_amount, int)
    assert "0x" + give_token.hex() == expected["source_token"]
    assert give_amount == expected["source_amount_wei"]

    result = decode_fulfilled_order(
        fixture,
        destination_proxy=str(fixture["address"]),
        expected_order_id=str(expected["order_id"]),
        expected_signer=str(expected["signer"]),
        source_chain_id=int(expected["source_chain_id"]),
        source_token=str(expected["source_token"]),
        source_amount_wei=int(expected["source_amount_wei"]),
        destination_chain_id=int(expected["destination_chain_id"]),
        receiver=str(expected["receiver"]),
        destination_token=str(expected["destination_token"]),
        minimum_amount_wei=int(expected["amount_wei"]),
        expected_take_amount_wei=int(expected["amount_wei"]),
        expected_allowed_taker=str(expected["allowed_taker"]),
    )

    assert result["order_id"] == expected["order_id"]
    assert result["amount_wei"] == expected["amount_wei"]


def test_cancellation_fails_closed_even_when_both_event_names_are_claimed() -> None:
    with pytest.raises(NotImplementedError, match="fail-closed"):
        validate_cancellation_events(
            [
                {"event": debridge.SENT_ORDER_CANCEL_EVENT, "order_id": "0x" + "12" * 32},
                {"event": debridge.CLAIMED_ORDER_CANCEL_EVENT, "order_id": "0x" + "12" * 32},
            ],
            order_id="0x" + "12" * 32,
        )


@pytest.mark.parametrize(
    ("value", "label"),
    [
        ("not-an-address", "address"),
        (True, "integer"),
        ("not-an-integer", "integer"),
        (-1, "range"),
        ("0x0", "canonical hex"),
    ],
)
def test_low_level_inputs_reject_ambiguous_encodings(value: object, label: str) -> None:
    if label == "address":
        with pytest.raises(ValueError, match=label):
            debridge.canonical_address(value)
    elif label == "canonical hex":
        with pytest.raises(ValueError, match=label):
            debridge._hex(value, "test")
    else:
        with pytest.raises(ValueError, match=label):
            debridge._integer(value, "test")


@pytest.mark.parametrize(
    ("calldata", "match"),
    [
        ("0x", "must not be empty"),
        ("0x1234", "unsupported strictlySwapAndCall selector"),
        (debridge.STRICT_SWAP_AND_CALL_SELECTOR, "truncated"),
    ],
)
def test_strict_swap_decoder_rejects_empty_wrong_or_truncated_calldata(
    calldata: str, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        decode_strictly_swap_and_call(calldata)


@pytest.mark.parametrize(
    ("calldata", "match"),
    [
        ("0x", "must not be empty"),
        ("0x1234", "unsupported createSaltedOrder selector"),
        (debridge.CREATE_SALTED_ORDER_SELECTOR, "truncated"),
    ],
)
def test_order_decoder_rejects_empty_wrong_or_truncated_calldata(calldata: str, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        debridge.decode_create_salted_order(calldata)


def test_order_decoder_rejects_unaligned_dynamic_offset() -> None:
    raw = bytes.fromhex(create_salted_order_calldata()[2:])
    malformed = raw[:4] + word(1) + raw[36:]
    with pytest.raises(ValueError, match="order offset is unaligned"):
        debridge.decode_create_salted_order("0x" + malformed.hex())


def test_strict_swap_decoder_rejects_nonzero_abi_padding() -> None:
    raw = bytearray(bytes.fromhex(strict_swap_calldata()[2:]))
    target_offset = int.from_bytes(raw[4 + 9 * 32 : 4 + 10 * 32], "big")
    target_size = int.from_bytes(raw[4 + target_offset : 4 + target_offset + 32], "big")
    raw[4 + target_offset + 32 + target_size] = 1
    with pytest.raises(ValueError, match="non-zero ABI padding"):
        decode_strictly_swap_and_call("0x" + raw.hex())


def test_deterministic_order_id_rejects_missing_external_and_overflow_fields() -> None:
    decoded = decode_strictly_swap_and_call(strict_swap_calldata())
    nested = decoded["create_salted_order"]
    assert isinstance(nested, dict)
    order = nested["order"]
    assert isinstance(order, dict)
    with pytest.raises(ValueError, match="incomplete"):
        deterministic_order_id({}, maker=SIGNER)
    with pytest.raises(ValueError, match="external calls"):
        deterministic_order_id(
            {**order, "give_chain_id": SOURCE_CHAIN, "external_call": b"x"}, maker=SIGNER
        )
    with pytest.raises(ValueError, match="overflows"):
        deterministic_order_id(
            {**order, "give_chain_id": SOURCE_CHAIN, "salt": 1 << 64}, maker=SIGNER
        )


@pytest.mark.parametrize(
    ("quote_mutation", "policy_mutation", "match"),
    [
        (lambda quote: quote.update({"expiresAt": "2026-07-23T00:00:00Z"}), None, "expired"),
        (lambda quote: quote.update({"createdAt": "2026-07-23T00:00:00Z"}), None, "stale"),
        (None, lambda policy: replace(policy, maximum_total_spend_wei=0), "policy limits"),
        (None, lambda policy: replace(policy, destination_dln_proxy=NATIVE_TOKEN), "proxy"),
        (
            None,
            lambda policy: replace(policy, destination_fulfillment_topic="0x" + "00" * 32),
            "topic",
        ),
    ],
)
def test_quote_rejects_expired_stale_and_invalid_route_policy(
    quote_request: QuoteRequest,
    policy: RoutePolicy,
    quote_mutation: Any,
    policy_mutation: Any,
    match: str,
) -> None:
    quote = valid_quote()
    if quote_mutation is not None:
        quote_mutation(quote)
    if policy_mutation is not None:
        policy = policy_mutation(policy)
    with pytest.raises(ValueError, match=match):
        validate(quote, quote_request, policy)


def test_quote_rejects_total_spend_over_cap_and_non_string_calldata(
    quote_request: QuoteRequest, policy: RoutePolicy
) -> None:
    quote = valid_quote()
    quote["estimatedTransactionFee"] = {
        "details": {"gasLimit": "100", "maxFeePerGas": "4", "maxPriorityFeePerGas": "1"}
    }
    with pytest.raises(ValueError, match="total spend"):
        validate(quote, quote_request, policy)

    quote = valid_quote()
    transaction = quote["tx"]
    assert isinstance(transaction, dict)
    transaction["data"] = None
    with pytest.raises(ValueError, match="calldata"):
        validate(quote, quote_request, policy)


def baseline_fulfillment_order() -> dict[str, object]:
    return {
        "salt": 7,
        "maker": bytes.fromhex(SIGNER[2:]),
        "give_chain_id": SOURCE_CHAIN,
        "give_token": bytes.fromhex(NATIVE_TOKEN[2:]),
        "give_amount": AMOUNT,
        "take_chain_id": DESTINATION_CHAIN,
        "take_token": bytes.fromhex(NATIVE_TOKEN[2:]),
        "take_amount": OUTPUT,
        "receiver": bytes.fromhex(RECIPIENT[2:]),
        "give_authority": bytes.fromhex(SIGNER[2:]),
        "take_authority": bytes.fromhex(RECIPIENT[2:]),
        "allowed_taker": bytes.fromhex(ALLOWED_TAKER[2:]),
        "cancel_beneficiary": bytes.fromhex(SIGNER[2:]),
        "external_call": b"",
    }


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("give_chain_id", 1, "source chain"),
        ("give_token", bytes.fromhex(SIGNER[2:]), "source token"),
        ("give_amount", AMOUNT - 1, "source amount"),
        ("take_chain_id", 1, "destination chain"),
        ("receiver", bytes.fromhex(SIGNER[2:]), "receiver"),
        ("maker", bytes.fromhex(RECIPIENT[2:]), "maker"),
        ("give_authority", bytes.fromhex(RECIPIENT[2:]), "give authority"),
        ("take_authority", bytes.fromhex(SIGNER[2:]), "authority"),
        ("take_token", bytes.fromhex(SIGNER[2:]), "token"),
        ("external_call", b"x", "external call"),
        ("allowed_taker", bytes.fromhex(SIGNER[2:]), "allowed taker"),
        ("cancel_beneficiary", bytes.fromhex(RECIPIENT[2:]), "cancel beneficiary"),
        ("take_amount", OUTPUT - 1, "amount"),
    ],
)
def test_fulfillment_rejects_each_unbound_decoded_identifier(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object, match: str
) -> None:
    order = baseline_fulfillment_order()
    order[field] = value
    monkeypatch.setattr(debridge, "_decode_fulfilled_order_tuple", lambda _data, _base: order)
    with pytest.raises(ValueError, match=match):
        decode_test_log(fulfilled_log())


def test_fulfillment_rejects_allowed_taker_when_expected_taker_is_not_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        debridge, "_decode_fulfilled_order_tuple", lambda _data, _base: baseline_fulfillment_order()
    )
    with pytest.raises(ValueError, match="allowed taker mismatch"):
        decode_fulfilled_order(
            fulfilled_log(),
            destination_proxy=DESTINATION_PROXY,
            expected_order_id=decode_test_log(fulfilled_log())["order_id"],
            expected_signer=SIGNER,
            source_chain_id=SOURCE_CHAIN,
            source_token=NATIVE_TOKEN,
            source_amount_wei=AMOUNT,
            destination_chain_id=DESTINATION_CHAIN,
            receiver=RECIPIENT,
            destination_token=NATIVE_TOKEN,
            minimum_amount_wei=OUTPUT,
            expected_take_amount_wei=OUTPUT,
        )


def test_fulfillment_rejects_empty_event_taker_for_a_planned_taker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order = baseline_fulfillment_order()
    order["allowed_taker"] = b""
    monkeypatch.setattr(debridge, "_decode_fulfilled_order_tuple", lambda _data, _base: order)
    with pytest.raises(ValueError, match="allowed taker mismatch"):
        decode_test_log(fulfilled_log())


def test_fulfillment_rejects_event_amount_that_only_meets_the_minimum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        debridge, "_decode_fulfilled_order_tuple", lambda _data, _base: baseline_fulfillment_order()
    )
    log = fulfilled_log()
    with pytest.raises(ValueError, match="amount mismatch"):
        decode_fulfilled_order(
            log,
            destination_proxy=DESTINATION_PROXY,
            expected_order_id=decode_test_log(log)["order_id"],
            expected_signer=SIGNER,
            source_chain_id=SOURCE_CHAIN,
            source_token=NATIVE_TOKEN,
            source_amount_wei=AMOUNT,
            destination_chain_id=DESTINATION_CHAIN,
            receiver=RECIPIENT,
            destination_token=NATIVE_TOKEN,
            minimum_amount_wei=OUTPUT - 1,
            expected_take_amount_wei=OUTPUT - 1,
            expected_allowed_taker=ALLOWED_TAKER,
        )


def test_fulfillment_rejects_event_order_id_not_derived_from_decoded_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order = baseline_fulfillment_order()
    order["salt"] = 8
    monkeypatch.setattr(debridge, "_decode_fulfilled_order_tuple", lambda _data, _base: order)
    with pytest.raises(ValueError, match="deterministic order ID"):
        decode_test_log(fulfilled_log())
