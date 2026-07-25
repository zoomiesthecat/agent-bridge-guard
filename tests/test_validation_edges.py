"""Edge cases for immutable artifacts and operator supplied validation inputs."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from agent_bridge_guard.approval import Approval, ApprovalError
from agent_bridge_guard.execution_plan import ExecutionPlan, ExecutionPlanError
from agent_bridge_guard.models import Plan, PlanIntegrityError, canonical_json
from agent_bridge_guard.plan_request import PlanRequest, PlanRequestError
from agent_bridge_guard.providers.debridge import FULFILLED_ORDER_TOPIC
from agent_bridge_guard.route_manifest import RouteManifest, RouteManifestError

SIGNER = "0x1111111111111111111111111111111111111111"
RECIPIENT = "0x2222222222222222222222222222222222222222"
ORDER_ID = "0x" + "ab" * 32
OPERATOR = Account.from_key(bytes(range(33, 65)))


def write_json(tmp_path: Path, name: str, value: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    os.chmod(path, 0o600)
    return path.resolve()


def request_document() -> dict[str, object]:
    return {
        "schema_version": 2,
        "request_id": "ticket-123",
        "route_id": "arbitrum-robinhood-native-v2",
        "source_chain_alias": "arbitrum",
        "destination_chain_alias": "robinhood",
        "amount_wei": "1000",
        "minimum_output_wei": "900",
        "signer": SIGNER,
        "recipient": RECIPIENT,
        "expires_at": "2030-01-01T00:05:00Z",
    }


def manifest_document() -> dict[str, object]:
    return {
        "schema_version": 2,
        "route_id": "arbitrum-robinhood-native-v2",
        "route_kind": "native_in_swap_dln_native_out",
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
        "maximum_swap_calldata_bytes": 1_024,
        "maximum_metadata_bytes": 1_024,
        "maximum_quote_age_seconds": 30,
        "maximum_plan_lifetime_seconds": 120,
    }


def executable_plan_body() -> dict[str, object]:
    return {
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
            "expires_at": "2026-07-24T20:10:00Z",
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
            "to": "0x" + "44" * 20,
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
            "destination_token": "0x" + "00" * 20,
            "destination_amount_wei": 950,
            "external_call": False,
            "allowed_taker": None,
        },
    }


def approval() -> Approval:
    values = {
        "plan_id": Plan.create({"unsigned_transaction": {"nonce": 7}}).plan_id,
        "authorization_id": "ticket-123",
        "actor": "operator-1",
        "subject_signer": SIGNER,
        "approved_at": "2026-07-24T20:00:00Z",
        "expires_at": "2026-07-24T20:10:00Z",
    }
    return Approval.create(
        **values,
        issuer=OPERATOR.address,
        signature=OPERATOR.sign_message(
            encode_defunct(primitive=Approval.signing_payload(**values))
        ).signature.to_0x_hex(),
    )


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (1.5, "floating point"),
        ({1: "value"}, "keys must be strings"),
        ({"value": {1, 2}}, "unsupported JSON value"),
    ],
)
def test_canonical_json_rejects_non_json_values(value: object, message: str) -> None:
    with pytest.raises(TypeError, match=message):
        canonical_json(value)


def test_canonical_json_normalizes_tuples_and_sorts_nested_keys() -> None:
    assert canonical_json({"z": (2, 1), "a": {"b": True}}) == '{"a":{"b":true},"z":[2,1]}'


def test_plan_rejects_reserved_artifact_fields_in_body() -> None:
    with pytest.raises(ValueError, match="reserved fields: artifact_type, plan_id"):
        Plan.create({"plan_id": "forged", "artifact_type": "plan"})


def test_plan_parse_rejects_document_without_plan_id() -> None:
    with pytest.raises(PlanIntegrityError, match="plan_id is missing"):
        Plan.parse({"schema_version": 1, "artifact_type": "plan"})


def test_plan_parse_rejects_supported_hash_with_unsupported_schema() -> None:
    plan = Plan.create({"intent": {"amount_wei": 1}})
    document = plan.to_dict()
    document["schema_version"] = 3
    without_id = dict(document)
    del without_id["plan_id"]
    document["plan_id"] = "sha256:" + sha256(canonical_json(without_id).encode()).hexdigest()

    with pytest.raises(PlanIntegrityError, match="unsupported plan schema"):
        Plan.parse(document)


def test_approval_rejects_equal_approval_and_expiry_timestamps() -> None:
    with pytest.raises(ApprovalError, match="expiry must be after"):
        Approval.create(
            plan_id="sha256:plan",
            authorization_id="ticket-123",
            actor="operator-1",
            subject_signer=SIGNER,
            approved_at="2026-07-24T20:00:00Z",
            expires_at="2026-07-24T20:00:00Z",
            issuer=OPERATOR.address,
            signature="0x" + "00" * 65,
        )


def test_approval_rejects_non_utc_timestamp() -> None:
    with pytest.raises(ApprovalError, match="approved_at must be UTC"):
        Approval.create(
            plan_id="sha256:plan",
            authorization_id="ticket-123",
            actor="operator-1",
            subject_signer=SIGNER,
            approved_at="2026-07-24T20:00:00+01:00",
            expires_at="2026-07-24T21:00:00Z",
            issuer=OPERATOR.address,
            signature="0x" + "00" * 65,
        )


def test_approval_rejects_malformed_timestamp() -> None:
    with pytest.raises(ApprovalError, match="ISO-8601"):
        Approval.create(
            plan_id="sha256:plan",
            authorization_id="ticket-123",
            actor="operator-1",
            subject_signer=SIGNER,
            approved_at="not-a-timestamp",
            expires_at="2026-07-24T21:00:00Z",
            issuer=OPERATOR.address,
            signature="0x" + "00" * 65,
        )


def test_approval_rejects_free_form_actor() -> None:
    with pytest.raises(ApprovalError, match="actor must be an opaque"):
        Approval.create(
            plan_id="sha256:plan",
            authorization_id="ticket-123",
            actor="operator says yes",
            subject_signer=SIGNER,
            approved_at="2026-07-24T20:00:00Z",
            expires_at="2026-07-24T21:00:00Z",
            issuer=OPERATOR.address,
            signature="0x" + "00" * 65,
        )


def test_approval_parse_rejects_missing_signed_field() -> None:
    document = approval().to_dict()
    del document["actor"]

    with pytest.raises(ApprovalError, match="invalid schema"):
        Approval.parse(document)


def test_approval_parse_rejects_unsupported_schema_with_matching_hash() -> None:
    document = approval().to_dict()
    document["schema_version"] = 1

    with pytest.raises(ApprovalError, match="unsupported approval schema"):
        Approval.parse(document)


def test_approval_rejects_naive_verification_time() -> None:
    with pytest.raises(ApprovalError, match="timezone-aware"):
        approval().verify_for(
            Plan.create({"unsigned_transaction": {"nonce": 7}}),
            allowed_issuers=frozenset({OPERATOR.address}),
            expected_subject_signer=SIGNER,
            at=datetime(2026, 7, 24, 20, 1),
        )


@pytest.mark.parametrize(
    ("section", "field", "value", "message"),
    [
        ("intent", "expires_at", "2026-07-24T20:00:00Z", "expiry must follow"),
        ("provider", "name", "other", "provider must be debridge"),
        ("provider", "version", "1", "provider plan version is unsupported"),
        ("provider", "route_id", "not a route", "provider route ID is invalid"),
        ("provider", "route_kind", "other", "provider route kind is unsupported"),
        ("provider", "destination_fulfillment_topic", "0x12", "32-byte hash"),
        ("unsigned_transaction", "value", 999, "below the input"),
        ("decoded_semantics", "destination_token", SIGNER, "must be native"),
    ],
)
def test_execution_plan_rejects_internally_inconsistent_values(
    section: str, field: str, value: object, message: str
) -> None:
    body = executable_plan_body()
    target = body[section]
    assert isinstance(target, dict)
    target[field] = value

    with pytest.raises(ExecutionPlanError, match=message):
        ExecutionPlan.from_plan(Plan.create(body), at=datetime(2026, 7, 24, 20, 5, tzinfo=UTC))


def test_execution_plan_canonicalizes_empty_allowed_taker_to_none() -> None:
    body = executable_plan_body()
    semantics = body["decoded_semantics"]
    assert isinstance(semantics, dict)
    semantics["allowed_taker"] = "0x"

    execution = ExecutionPlan.from_plan(
        Plan.create(body), at=datetime(2026, 7, 24, 20, 5, tzinfo=UTC)
    )
    assert execution.allowed_taker is None


@pytest.mark.parametrize(
    ("section", "field", "value", "message"),
    [
        ("intent", "created_at", "not-a-time", "created_at must be a UTC"),
        ("intent", "source_chain_id", True, "source chain must be a positive"),
        ("intent", "recipient", "not-an-address", "recipient must be an EVM"),
        ("decoded_semantics", "destination_receiver", "not-an-address", "receiver must be an EVM"),
    ],
)
def test_execution_plan_rejects_malformed_typed_values(
    section: str, field: str, value: object, message: str
) -> None:
    body = executable_plan_body()
    target = body[section]
    assert isinstance(target, dict)
    target[field] = value

    with pytest.raises(ExecutionPlanError, match=message):
        ExecutionPlan.from_plan(Plan.create(body), at=datetime(2026, 7, 24, 20, 5, tzinfo=UTC))


def test_plan_request_rejects_extra_schema_field(tmp_path: Path) -> None:
    document = request_document()
    document["memo"] = "untrusted"

    with pytest.raises(PlanRequestError, match="fields do not match"):
        PlanRequest.load(write_json(tmp_path, "request.json", document))


def test_plan_request_rejects_unreadable_artifact(tmp_path: Path) -> None:
    with pytest.raises(PlanRequestError, match="cannot be read"):
        PlanRequest.load((tmp_path / "missing.json").resolve())


def test_plan_request_rejects_free_form_request_id(tmp_path: Path) -> None:
    document = request_document()
    document["request_id"] = "operator approved it"

    with pytest.raises(PlanRequestError, match="request_id must be an opaque"):
        PlanRequest.load(write_json(tmp_path, "request.json", document))


def test_plan_request_rejects_non_utc_expiry_offset(tmp_path: Path) -> None:
    document = request_document()
    document["expires_at"] = "2030-01-01T00:05:00+01:00"

    with pytest.raises(PlanRequestError, match="UTC timestamp"):
        PlanRequest.load(write_json(tmp_path, "request.json", document))


def test_plan_request_canonicalizes_checksum_addresses(tmp_path: Path) -> None:
    document = request_document()
    document["signer"] = SIGNER.upper().replace("0X", "0x")

    parsed = PlanRequest.load(write_json(tmp_path, "request.json", document))
    assert parsed.signer == "0x1111111111111111111111111111111111111111"


def test_route_manifest_rejects_same_source_and_destination_chain(tmp_path: Path) -> None:
    document = manifest_document()
    document["destination_chain_id"] = 42161

    with pytest.raises(RouteManifestError, match="must differ"):
        RouteManifest.load(write_json(tmp_path, "route.json", document))


def test_route_manifest_rejects_unreadable_artifact(tmp_path: Path) -> None:
    with pytest.raises(RouteManifestError, match="cannot be read"):
        RouteManifest.load((tmp_path / "missing.json").resolve())


def test_route_manifest_rejects_unsupported_schema_version(tmp_path: Path) -> None:
    document = manifest_document()
    document["schema_version"] = 1

    with pytest.raises(RouteManifestError, match="schema is unsupported"):
        RouteManifest.load(write_json(tmp_path, "route.json", document))


def test_route_manifest_rejects_duplicate_addresses_after_canonicalization(tmp_path: Path) -> None:
    document = manifest_document()
    document["allowed_bridge_routers"] = ["0x" + "ab" * 20, "0x" + "AB" * 20]

    with pytest.raises(RouteManifestError, match="duplicate"):
        RouteManifest.load(write_json(tmp_path, "route.json", document))


def test_route_manifest_rejects_invalid_destination_proxy(tmp_path: Path) -> None:
    document = manifest_document()
    document["destination_dln_proxy"] = "not-an-address"

    with pytest.raises(RouteManifestError, match="destination DLN proxy is invalid"):
        RouteManifest.load(write_json(tmp_path, "route.json", document))


def test_route_manifest_rejects_plan_lifetime_above_one_hour(tmp_path: Path) -> None:
    document = manifest_document()
    document["maximum_plan_lifetime_seconds"] = 3_601

    with pytest.raises(RouteManifestError, match="maximum_plan_lifetime_seconds is out of range"):
        RouteManifest.load(write_json(tmp_path, "route.json", document))


def test_route_manifest_accepts_one_hour_plan_lifetime(tmp_path: Path) -> None:
    document = manifest_document()
    document["maximum_plan_lifetime_seconds"] = 3_600

    route = RouteManifest.load(write_json(tmp_path, "route.json", document))
    assert route.maximum_plan_lifetime_seconds == 3_600
