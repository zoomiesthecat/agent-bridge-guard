from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from test_debridge_provider import (
    AMOUNT,
    BRIDGE_ROUTER,
    DESTINATION_CHAIN,
    GAS_LIMIT,
    INTERMEDIARY_TOKEN,
    OUTPUT,
    RECIPIENT,
    SIGNER,
    SOURCE_CHAIN,
    create_salted_order_calldata,
    direct_policy,
    direct_quote,
    direct_rpc,
)

from agent_bridge_guard.providers import debridge
from agent_bridge_guard.providers.debridge import QuoteRequest, RoutePolicy

EXPECTED_CODEHASH = "0x" + debridge.keccak(bytes.fromhex("6000")).hex()


def request() -> QuoteRequest:
    return QuoteRequest(
        source_chain_id=SOURCE_CHAIN,
        destination_chain_id=DESTINATION_CHAIN,
        amount_wei=AMOUNT,
        minimum_output_wei=OUTPUT,
        signer=SIGNER,
        recipient=RECIPIENT,
        nonce=7,
        created_at="2026-07-24T00:00:00Z",
        expires_at="2026-07-24T00:00:30Z",
    )


def preflight(
    primary: Any | None = None,
    secondary: Any | None = None,
    **overrides: object,
) -> dict[str, int | str]:
    arguments: dict[str, object] = {
        "signer": SIGNER,
        "dln_proxy": BRIDGE_ROUTER,
        "reserve_token": INTERMEDIARY_TOKEN,
        "amount_wei": AMOUNT,
        "fixed_fee_wei": 5,
        "data": direct_quote()["tx"]["data"],
        "nonce": 7,
        "maximum_gas": GAS_LIMIT,
        "required_native_spend_wei": 205,
        "expected_implementation_codehash": EXPECTED_CODEHASH,
        "expected_global_transfer_fee_bps": 100,
    }
    arguments.update(overrides)
    return debridge.preflight_reserve_erc20_source_transaction(
        direct_rpc() if primary is None else primary,
        direct_rpc() if secondary is None else secondary,
        **arguments,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"amount_wei": 0}, "limits are invalid"),
        ({"fixed_fee_wei": -1}, "limits are invalid"),
        ({"maximum_gas": 0}, "limits are invalid"),
        ({"required_native_spend_wei": 4}, "limits are invalid"),
        ({"expected_implementation_codehash": "0x12"}, "codehash is invalid"),
    ],
)
def test_direct_preflight_rejects_invalid_limits(
    overrides: dict[str, object], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        preflight(**overrides)


@pytest.mark.parametrize(
    ("rpc", "match"),
    [
        (direct_rpc(latest_nonce=8, pending_nonce=8), "nonce counts disagree"),
        (direct_rpc(simulation_result="not-hex"), "simulation returned malformed"),
        (direct_rpc(implementation_slot_override="0x12"), "slot is malformed"),
        (direct_rpc(implementation_code="0x"), "code is unavailable"),
    ],
)
def test_direct_preflight_rejects_malformed_or_stale_rpc_evidence(
    rpc: Any, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        preflight(rpc, rpc)


@pytest.mark.parametrize(
    ("primary", "secondary", "overrides", "match"),
    [
        (
            direct_rpc(reserve_balance=AMOUNT),
            direct_rpc(reserve_balance=AMOUNT + 1),
            {},
            "RPC evidence disagrees",
        ),
        (
            direct_rpc(reserve_balance=AMOUNT - 1),
            direct_rpc(reserve_balance=AMOUNT - 1),
            {},
            "balance cannot cover",
        ),
        (
            direct_rpc(observed_fixed_fee=6),
            direct_rpc(observed_fixed_fee=6),
            {},
            "fixed native fee",
        ),
        (
            direct_rpc(observed_transfer_fee=101),
            direct_rpc(observed_transfer_fee=101),
            {},
            "transfer fee differs",
        ),
        (
            direct_rpc(),
            direct_rpc(),
            {"expected_implementation_codehash": "0x" + "bb" * 32},
            "codehash differs",
        ),
        (
            direct_rpc(gas=GAS_LIMIT + 1),
            direct_rpc(gas=GAS_LIMIT + 1),
            {},
            "gas estimate exceeds",
        ),
        (
            direct_rpc(native_balance=204),
            direct_rpc(native_balance=204),
            {},
            "native balance cannot cover",
        ),
        (
            direct_rpc(native_balance=500),
            direct_rpc(native_balance=501),
            {},
            "native balance cannot cover",
        ),
    ],
)
def test_direct_preflight_rejects_every_conflicting_fact(
    primary: Any,
    secondary: Any,
    overrides: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        preflight(primary, secondary, **overrides)


def decoded_order() -> dict[str, object]:
    return deepcopy(debridge.decode_create_salted_order(create_salted_order_calldata()))


def mutate_order(decoded: dict[str, object], field: str, value: object) -> None:
    order = decoded["order"]
    assert isinstance(order, dict)
    order[field] = value


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda value: value.update({"affiliate_fee": b"x"}), "affiliate fees"),
        (lambda value: value.update({"permit": b"x"}), "affiliate fees"),
        (lambda value: value.update({"referral_code": 1}), "referral code"),
        (lambda value: value.update({"metadata": b"x" * 33}), "metadata"),
        (
            lambda value: mutate_order(value, "give_token", SIGNER),
            "give token",
        ),
        (
            lambda value: mutate_order(value, "give_authority", RECIPIENT),
            "source authority",
        ),
        (lambda value: mutate_order(value, "take_chain_id", 1), "destination chain"),
        (
            lambda value: mutate_order(value, "take_token", bytes.fromhex(SIGNER[2:])),
            "not native",
        ),
        (
            lambda value: mutate_order(value, "receiver", bytes.fromhex(SIGNER[2:])),
            "receiver mismatch",
        ),
        (
            lambda value: mutate_order(value, "take_authority", bytes.fromhex(SIGNER[2:])),
            "authority mismatch",
        ),
        (lambda value: mutate_order(value, "take_amount", OUTPUT - 1), "below minimum"),
        (lambda value: mutate_order(value, "external_call", b"x"), "external calls"),
        (
            lambda value: mutate_order(
                value, "cancel_beneficiary", bytes.fromhex(RECIPIENT[2:])
            ),
            "cancel beneficiary",
        ),
        (lambda value: mutate_order(value, "allowed_taker", "bad"), "taker is invalid"),
        (lambda value: mutate_order(value, "allowed_taker", b""), "not allowlisted"),
        (lambda value: mutate_order(value, "give_amount", AMOUNT - 1), "give amount"),
    ],
)
def test_direct_semantics_reject_every_material_mutation(
    mutate: Any, match: str
) -> None:
    decoded = decoded_order()
    mutate(decoded)
    with pytest.raises(ValueError, match=match):
        debridge._validate_direct_semantics(
            decoded,
            request(),
            direct_policy(),
            INTERMEDIARY_TOKEN,
        )


def test_direct_semantics_rejects_incomplete_policy() -> None:
    with pytest.raises(ValueError, match="policy is incomplete"):
        debridge._validate_direct_semantics(
            decoded_order(),
            request(),
            replace(direct_policy(), source_dln_proxy=None),
            INTERMEDIARY_TOKEN,
        )


def validate_direct(
    response: object | None = None,
    *,
    quote_request: QuoteRequest | None = None,
    policy: RoutePolicy | None = None,
) -> dict[str, object]:
    return debridge.validate_quote(
        direct_quote() if response is None else response,
        request() if quote_request is None else quote_request,
        direct_policy() if policy is None else policy,
        now=datetime(2026, 7, 24, tzinfo=UTC),
    )


@pytest.mark.parametrize(
    ("quote_request", "policy", "match"),
    [
        (request(), replace(direct_policy(), source_reserve_token=None), "policy is incomplete"),
        (replace(request(), amount_wei=0), direct_policy(), "amounts must be positive"),
        (
            request(),
            replace(direct_policy(), maximum_input_token_amount=AMOUNT - 1),
            "exceeds policy",
        ),
        (replace(request(), nonce=-1), direct_policy(), "nonce must be non-negative"),
        (
            replace(request(), expires_at=request().created_at),
            direct_policy(),
            "must be after",
        ),
        (
            request(),
            replace(direct_policy(), maximum_plan_lifetime_seconds=0),
            "lifetime exceeds",
        ),
    ],
)
def test_direct_quote_rejects_invalid_request_or_policy(
    quote_request: QuoteRequest, policy: RoutePolicy, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        validate_direct(quote_request=quote_request, policy=policy)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (
            lambda quote: quote["estimation"]["srcChainTokenIn"].update({"address": SIGNER}),
            "reserve token is not pinned",
        ),
        (
            lambda quote: quote["estimation"]["srcChainTokenIn"].update({"chainId": 1}),
            "source chain mismatch",
        ),
        (
            lambda quote: quote["estimation"]["srcChainTokenIn"].update({"amount": "999"}),
            "source amount mismatch",
        ),
        (
            lambda quote: quote["estimation"]["dstChainTokenOut"].update({"chainId": 1}),
            "destination chain mismatch",
        ),
        (
            lambda quote: quote["estimation"]["dstChainTokenOut"].update({"address": SIGNER}),
            "destination token is not native",
        ),
        (
            lambda quote: quote["estimation"]["dstChainTokenOut"].update(
                {"recommendedAmount": str(OUTPUT - 1)}
            ),
            "destination amount below",
        ),
        (lambda quote: quote.update({"usdPriceImpact": "bad"}), "invalid price impact"),
        (lambda quote: quote.update({"usdPriceImpact": "NaN"}), "price impact exceeds"),
        (lambda quote: quote.update({"usdPriceImpact": "0.11"}), "price impact exceeds"),
        (lambda quote: quote["tx"].update({"to": SIGNER}), "proxy is not pinned"),
        (lambda quote: quote["tx"].update({"value": "11"}), "fee exceeds policy"),
        (lambda quote: quote.update({"fixFee": "6"}), "does not match fixed fee"),
        (lambda quote: quote["tx"].update({"data": None}), "calldata must be a string"),
        (lambda quote: quote.update({"protocolFee": "0"}), "leaves no source order"),
        (
            lambda quote: quote.update({"protocolFee": str(AMOUNT // 100 + 1)}),
            "differs from pinned",
        ),
        (
            lambda quote: quote["order"].update({"metadata": "0x01"}),
            "metadata does not match",
        ),
        (lambda quote: quote.update({"orderId": "0x12"}), "order ID mismatch"),
        (
            lambda quote: quote["tx"].update({"gasLimit": str(GAS_LIMIT + 1)}),
            "gas details are invalid",
        ),
    ],
)
def test_direct_quote_rejects_response_mutations(mutate: Any, match: str) -> None:
    quote = direct_quote()
    mutate(quote)
    with pytest.raises(ValueError, match=match):
        validate_direct(quote)


def test_direct_quote_rejects_total_spend_over_policy() -> None:
    with pytest.raises(ValueError, match="total spend exceeds"):
        validate_direct(policy=replace(direct_policy(), maximum_total_spend_wei=204))
