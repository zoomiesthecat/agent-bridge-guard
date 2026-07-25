from __future__ import annotations

from datetime import UTC, datetime

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from agent_bridge_guard.approval import Approval, ApprovalError
from agent_bridge_guard.artifacts import ArtifactError, ArtifactPathError, read_json_object
from agent_bridge_guard.engine import NeedsReconciliation
from agent_bridge_guard.execution_plan import ExecutionPlan, ExecutionPlanError
from agent_bridge_guard.models import Plan
from agent_bridge_guard.providers.debridge import FULFILLED_ORDER_TOPIC
from agent_bridge_guard.store import OperationState, SQLiteOperationStore
from agent_bridge_guard.tracking import DeBridgeTrackingClient, TrackingError

SIGNER = "0x1111111111111111111111111111111111111111"
RECIPIENT = "0x2222222222222222222222222222222222222222"
ORDER_ID = "0x" + "ab" * 32
SOURCE_TX = "0x" + "cd" * 32
OPERATOR = Account.from_key(bytes(range(33, 65)))
APPROVAL_ISSUERS = frozenset({OPERATOR.address})


def signed_approval(candidate: Plan, *, authorization_id: str = "ticket-1") -> Approval:
    values = {
        "plan_id": candidate.plan_id,
        "authorization_id": authorization_id,
        "actor": "operator-1",
        "subject_signer": SIGNER,
        "approved_at": "2026-07-24T20:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
    }
    return Approval.create(
        **values,
        issuer=OPERATOR.address,
        signature=OPERATOR.sign_message(
            encode_defunct(primitive=Approval.signing_payload(**values))
        ).signature.to_0x_hex(),
    )


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


def test_expired_plan_is_inspectable_only_with_explicit_opt_in() -> None:
    expired_at = datetime(2026, 7, 24, 20, 2, tzinfo=UTC)

    with pytest.raises(ExecutionPlanError, match="expired"):
        ExecutionPlan.from_plan(plan(), at=expired_at)

    inspection = ExecutionPlan.from_plan(plan(), at=expired_at, allow_expired=True)
    assert inspection.order_id == ORDER_ID


def test_tracking_rejects_success_below_approved_minimum_output() -> None:
    def value(text: str) -> dict[str, str]:
        return {"stringValue": text}

    def get(url: str) -> object:
        if "/Transaction/" in url:
            return {"orderIds": [ORDER_ID]}
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
                "finalAmount": value("899"),
            },
            "fulfilledDstEventMetadata": {"transactionHash": value("0x" + "ef" * 32)},
        }

    with pytest.raises(TrackingError, match="below minimum"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            plan(), SOURCE_TX
        )


def test_tracking_rejects_multiple_order_ids_for_one_approved_source_transaction() -> None:
    def get(_url: str) -> object:
        return {"orderIds": [ORDER_ID, "0x" + "ef" * 32]}

    with pytest.raises(TrackingError, match="exact planned order"):
        DeBridgeTrackingClient("https://tracking.example/api", get).discover_fulfillment(
            plan(), SOURCE_TX
        )


def test_approval_parse_rejects_tampered_actor_before_execution() -> None:
    approval = signed_approval(plan())
    tampered = approval.to_dict()
    tampered["actor"] = "operator-2"

    with pytest.raises(ApprovalError, match="approval_id mismatch"):
        Approval.parse(tampered)


def test_json_artifact_reader_refuses_relative_symlink_and_non_object_inputs(tmp_path) -> None:
    with pytest.raises(ArtifactPathError, match="absolute"):
        read_json_object("relative.json")

    document = tmp_path / "document.json"
    document.write_text("[]", encoding="utf-8")
    document.chmod(0o600)
    with pytest.raises(ArtifactError, match="JSON object"):
        read_json_object(document.resolve())

    link = tmp_path / "link.json"
    link.symlink_to(document)
    with pytest.raises(ArtifactPathError, match="owner-only regular"):
        read_json_object(link)


def test_refresh_without_persisted_transaction_stops_for_reconciliation(tmp_path) -> None:
    from test_engine import FixtureAuthorizer, FixtureExecutionEngine

    class RpcPool:
        chain_id = 42161

    store = SQLiteOperationStore(tmp_path / "private" / "operations.db")
    candidate = plan()
    approval = signed_approval(candidate)
    operation = store.reserve_operation(
        candidate,
        idempotency_key="request-1",
        signer=SIGNER,
        source_chain_id=42161,
        nonce=1,
        approval_id=approval.approval_id,
    )
    claim = store.claim_preparation(
        operation.operation_id,
        kind="test-eip1559",
        fingerprint="signed",
        replay_safe=True,
    )
    assert claim.token is not None
    prepared = store.complete_preparation(operation.operation_id, claim.token, b"signed")
    attempted = store.append_state_event(prepared.operation_id, OperationState.BROADCAST_ATTEMPTED)
    pending = store.append_state_event(attempted.operation_id, OperationState.SOURCE_PENDING)

    assert pending.tx_hash is not None

    # A damaged private record must never be treated as finalized without a source hash.
    class MissingHashStore:
        def get_operation(self, _operation_id: str):
            return pending.__class__(
                operation_id=pending.operation_id,
                idempotency_key=pending.idempotency_key,
                approval_id=pending.approval_id,
                plan=pending.plan,
                signer=pending.signer,
                source_chain_id=pending.source_chain_id,
                nonce=pending.nonce,
                state=OperationState.SOURCE_PENDING,
                created_at_ns=pending.created_at_ns,
                raw_signed_tx=pending.raw_signed_tx,
                tx_hash=None,
                source_finality_evidence=None,
                destination_fulfillment_evidence=None,
                events=pending.events,
            )

        def append_state_event(self, _operation_id: str, state: OperationState):
            assert state is OperationState.NEEDS_RECONCILIATION
            return pending

    with pytest.raises(NeedsReconciliation, match="hash is absent"):
        FixtureExecutionEngine(
            MissingHashStore(), RpcPool(), authorizer=FixtureAuthorizer()
        ).refresh_source(pending.operation_id)  # type: ignore[arg-type]
