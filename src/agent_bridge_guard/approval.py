"""Plan-bound EIP-191 operator approval artifacts.

An operator signature authenticates workflow provenance on an uncompromised
signer.  It is not, by itself, human separation on a compromised host: a host
that can invoke an unlocked operator signer can still request an approval.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils.address import is_address, to_checksum_address

from agent_bridge_guard.execution_plan import ExecutionPlan
from agent_bridge_guard.models import JSONObject, Plan, canonical_json
from agent_bridge_guard.providers.debridge import RESERVE_ERC20_DLN_NATIVE_OUT

OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SIGNATURE = re.compile(r"^0x[0-9a-fA-F]{130}$")
LEGACY_APPROVAL_DOMAIN = "agent-bridge-guard/approval/v1"
APPROVAL_DOMAIN = "agent-bridge-guard/approval/v3"
INTENT_KEYS = frozenset(
    {
        "schema_version",
        "action",
        "route_id",
        "route_kind",
        "source_chain_id",
        "destination_chain_id",
        "source_asset_kind",
        "source_asset_address",
        "source_gross_amount_wei",
        "quoted_destination_amount_wei",
        "minimum_destination_amount_wei",
        "max_transaction_spend_wei",
        "recipient",
        "signer",
        "nonce",
        "transaction_target",
        "transaction_value_wei",
        "transaction_gas_limit",
        "transaction_max_fee_per_gas",
        "transaction_max_priority_fee_per_gas",
        "transaction_calldata_sha256",
        "order_id",
        "plan_expires_at",
        "policy_id",
        "policy_version",
        "policy_digest",
        "route_manifest_digest",
    }
)
_ARTIFACT_KEYS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "plan_id",
        "authorization_id",
        "actor",
        "subject_signer",
        "approved_at",
        "expires_at",
        "issuer",
        "signature",
        "approval_id",
    }
)
_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "plan_id",
        "authorization_id",
        "actor",
        "subject_signer",
        "approved_at",
        "expires_at",
        "allowed_issuers",
        "eip191_message_hex",
    }
)
_REVIEWABLE_ARTIFACT_KEYS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "plan_id",
        "authorization_id",
        "actor",
        "approved_at",
        "expires_at",
        "intent",
        "issuer",
        "signature",
        "approval_id",
    }
)
_REVIEWABLE_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "plan_id",
        "authorization_id",
        "actor",
        "approved_at",
        "expires_at",
        "intent",
        "eip191_message_hex",
    }
)


class ApprovalError(ValueError):
    """Approval is invalid, expired, bound to another plan, or unauthorized."""


def _timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ApprovalError(f"{label} must be UTC")
    return parsed


def _issuer(value: object, label: str = "issuer") -> str:
    if not isinstance(value, str) or not is_address(value):
        raise ApprovalError(f"{label} must be an EVM address")
    normalized = to_checksum_address(value)
    if normalized == "0x0000000000000000000000000000000000000000":
        raise ApprovalError(f"{label} must not be the zero address")
    return normalized


def _body(
    *,
    plan_id: object,
    authorization_id: object,
    actor: object,
    subject_signer: object,
    approved_at: object,
    expires_at: object,
) -> JSONObject:
    if not isinstance(plan_id, str) or not plan_id:
        raise ApprovalError("plan_id must be a non-empty string")
    if not isinstance(authorization_id, str) or not OPAQUE_ID.fullmatch(authorization_id):
        raise ApprovalError("authorization_id must be an opaque identifier")
    if not isinstance(actor, str) or not OPAQUE_ID.fullmatch(actor):
        raise ApprovalError("actor must be an opaque identifier")
    normalized_subject = _issuer(subject_signer, "subject_signer")
    if not isinstance(approved_at, str) or not isinstance(expires_at, str):
        raise ApprovalError("approval timestamps must be strings")
    approved = _timestamp(approved_at, "approved_at")
    expires = _timestamp(expires_at, "expires_at")
    if expires <= approved:
        raise ApprovalError("approval expiry must be after approval time")
    return {
        "schema_version": 2,
        "artifact_type": "approval",
        "plan_id": plan_id,
        "authorization_id": authorization_id,
        "actor": actor,
        "subject_signer": normalized_subject,
        "approved_at": approved_at,
        "expires_at": expires_at,
    }


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ApprovalError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _integer(value: object, label: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "positive" if positive else "non-negative"
        raise ApprovalError(f"{label} must be a {qualifier} integer")
    return value


def approval_intent(plan: Plan) -> JSONObject:
    """Project one validated, human-reviewable intent from a bound plan."""

    if plan.schema_version != 2:
        raise ApprovalError("legacy unbound plan has no reviewable approval intent")
    try:
        execution = ExecutionPlan.from_plan(plan, allow_expired=True)
    except ValueError as exc:
        raise ApprovalError("plan cannot produce a reviewable approval intent") from exc
    body = plan.body()
    plan_intent = _object(body.get("intent"), "plan intent")
    semantics = _object(body.get("decoded_semantics"), "decoded semantics")
    binding = _object(body.get("policy_binding"), "policy binding")
    if set(binding) != {
        "schema_version",
        "policy_id",
        "policy_version",
        "policy_digest",
        "route_id",
        "route_manifest_digest",
        "route_manifest",
    }:
        raise ApprovalError("policy binding fields do not match schema")
    source_amount = _integer(
        plan_intent.get("amount_wei"), "source gross amount", positive=True
    )
    semantic_gross = _integer(
        semantics.get("source_gross_amount_wei"),
        "semantic source gross amount",
        positive=True,
    )
    if execution.route_kind == RESERVE_ERC20_DLN_NATIVE_OUT:
        source_kind = "erc20"
        source_address = execution.source_order_token
        if semantic_gross != source_amount:
            raise ApprovalError("direct source gross amount does not match plan intent")
    else:
        source_kind = "native"
        source_address = "0x0000000000000000000000000000000000000000"
    quoted_destination = _integer(
        semantics.get("destination_amount_wei"),
        "quoted destination amount",
        positive=True,
    )
    semantic_total_spend = _integer(
        semantics.get("total_spend_wei"), "semantic total spend", positive=True
    )
    transaction = execution.transaction
    total_spend = transaction["value"] + transaction["gas"] * transaction["max_fee_per_gas"]
    if semantic_total_spend != total_spend:
        raise ApprovalError("semantic total spend does not match transaction")
    calldata_digest = hashlib.sha256(bytes.fromhex(transaction["data"][2:])).hexdigest()
    if semantics.get("transaction_calldata_sha256") != calldata_digest:
        raise ApprovalError("semantic calldata digest does not match transaction")
    expires_at = plan_intent.get("expires_at")
    if not isinstance(expires_at, str):
        raise ApprovalError("plan expiry must be a string")
    policy_id = binding.get("policy_id")
    policy_version = binding.get("policy_version")
    policy_digest = binding.get("policy_digest")
    manifest_digest = binding.get("route_manifest_digest")
    if not isinstance(policy_id, str) or not OPAQUE_ID.fullmatch(policy_id):
        raise ApprovalError("policy_id must be an opaque identifier")
    if (
        isinstance(policy_version, bool)
        or not isinstance(policy_version, int)
        or policy_version <= 0
    ):
        raise ApprovalError("policy_version must be a positive integer")
    digest_pattern = re.compile(r"^sha256:[0-9a-f]{64}$")
    if not isinstance(policy_digest, str) or not digest_pattern.fullmatch(policy_digest):
        raise ApprovalError("policy_digest must be a sha256 digest")
    if not isinstance(manifest_digest, str) or not digest_pattern.fullmatch(manifest_digest):
        raise ApprovalError("route_manifest_digest must be a sha256 digest")
    return {
        "schema_version": 1,
        "action": "bridge",
        "route_id": execution.route_id,
        "route_kind": execution.route_kind,
        "source_chain_id": execution.source_chain_id,
        "destination_chain_id": execution.destination_chain_id,
        "source_asset_kind": source_kind,
        "source_asset_address": source_address,
        "source_gross_amount_wei": source_amount,
        "quoted_destination_amount_wei": quoted_destination,
        "minimum_destination_amount_wei": execution.minimum_output_wei,
        "max_transaction_spend_wei": total_spend,
        "recipient": execution.recipient,
        "signer": execution.signer,
        "nonce": transaction["nonce"],
        "transaction_target": transaction["to"],
        "transaction_value_wei": transaction["value"],
        "transaction_gas_limit": transaction["gas"],
        "transaction_max_fee_per_gas": transaction["max_fee_per_gas"],
        "transaction_max_priority_fee_per_gas": transaction[
            "max_priority_fee_per_gas"
        ],
        "transaction_calldata_sha256": "sha256:" + calldata_digest,
        "order_id": execution.order_id,
        "plan_expires_at": expires_at,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_digest": policy_digest,
        "route_manifest_digest": manifest_digest,
    }


def _reviewable_body(
    *,
    plan: Plan,
    authorization_id: object,
    actor: object,
    approved_at: object,
    expires_at: object,
) -> JSONObject:
    if not isinstance(authorization_id, str) or not OPAQUE_ID.fullmatch(authorization_id):
        raise ApprovalError("authorization_id must be an opaque identifier")
    if not isinstance(actor, str) or not OPAQUE_ID.fullmatch(actor):
        raise ApprovalError("actor must be an opaque identifier")
    if not isinstance(approved_at, str) or not isinstance(expires_at, str):
        raise ApprovalError("approval timestamps must be strings")
    approved = _timestamp(approved_at, "approved_at")
    expires = _timestamp(expires_at, "expires_at")
    if expires <= approved:
        raise ApprovalError("approval expiry must be after approval time")
    intent = approval_intent(plan)
    plan_expiry = _timestamp(cast(str, intent["plan_expires_at"]), "plan_expires_at")
    if expires > plan_expiry:
        raise ApprovalError("approval expiry must not exceed plan expiry")
    return {
        "schema_version": 3,
        "artifact_type": "approval",
        "plan_id": plan.plan_id,
        "authorization_id": authorization_id,
        "actor": actor,
        "approved_at": approved_at,
        "expires_at": expires_at,
        "intent": intent,
    }


def _parsed_reviewable_body(
    *,
    plan_id: object,
    authorization_id: object,
    actor: object,
    approved_at: object,
    expires_at: object,
    intent: object,
) -> JSONObject:
    if not isinstance(plan_id, str) or not plan_id.startswith("sha256:"):
        raise ApprovalError("plan_id must be a plan digest")
    if not isinstance(authorization_id, str) or not OPAQUE_ID.fullmatch(authorization_id):
        raise ApprovalError("authorization_id must be an opaque identifier")
    if not isinstance(actor, str) or not OPAQUE_ID.fullmatch(actor):
        raise ApprovalError("actor must be an opaque identifier")
    if not isinstance(approved_at, str) or not isinstance(expires_at, str):
        raise ApprovalError("approval timestamps must be strings")
    approved = _timestamp(approved_at, "approved_at")
    expires = _timestamp(expires_at, "expires_at")
    if expires <= approved:
        raise ApprovalError("approval expiry must be after approval time")
    if (
        not isinstance(intent, dict)
        or set(intent) != INTENT_KEYS
        or intent.get("schema_version") != 1
        or intent.get("action") != "bridge"
    ):
        raise ApprovalError("reviewable approval intent has an invalid schema")
    plan_expiry_value = intent.get("plan_expires_at")
    if not isinstance(plan_expiry_value, str):
        raise ApprovalError("reviewable approval plan expiry is invalid")
    if expires > _timestamp(plan_expiry_value, "plan_expires_at"):
        raise ApprovalError("approval expiry must not exceed plan expiry")
    _issuer(intent.get("signer"), "intent signer")
    return {
        "schema_version": 3,
        "artifact_type": "approval",
        "plan_id": plan_id,
        "authorization_id": authorization_id,
        "actor": actor,
        "approved_at": approved_at,
        "expires_at": expires_at,
        "intent": cast(JSONObject, intent),
    }


def _payload(body: JSONObject) -> bytes:
    """Return canonical, domain-separated bytes to be signed as EIP-191."""

    domain = (
        APPROVAL_DOMAIN
        if body.get("schema_version") == 3
        else LEGACY_APPROVAL_DOMAIN
    )
    return canonical_json({"domain": domain, "approval": body}).encode("utf-8")


def _recover_issuer(body: JSONObject, signature: object) -> str:
    if not isinstance(signature, str) or not SIGNATURE.fullmatch(signature):
        raise ApprovalError("approval signature must be a 65-byte 0x-prefixed hex value")
    try:
        recovered = Account.recover_message(
            encode_defunct(primitive=_payload(body)), signature=signature
        )
    except (TypeError, ValueError) as exc:
        raise ApprovalError("approval signature is invalid") from exc
    return _issuer(recovered, "recovered issuer")


def _identifier(body: JSONObject) -> str:
    # Identity is independent of ECDSA nonce/encoding. Signature recovery authenticates it.
    digest = hashlib.sha256(_payload(body)).hexdigest()
    return f"eip191:{digest}"


def _allowed_issuers(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values:
        raise ApprovalError("approval issuer allowlist is required")
    normalized = tuple(sorted(_issuer(value, "allowed issuer") for value in values))
    if len(set(normalized)) != len(normalized):
        raise ApprovalError("approval issuer allowlist must not contain duplicates")
    return normalized


@dataclass(frozen=True, slots=True)
class ApprovalSigningRequest:
    """Exact operator-signing request exported for an off-box signer."""

    plan_id: str
    authorization_id: str
    actor: str
    subject_signer: str
    approved_at: str
    expires_at: str
    allowed_issuers: tuple[str, ...]
    intent: JSONObject | None
    schema_version: int
    eip191_message_hex: str = field(repr=False)
    _document_json: str = field(repr=False)

    @classmethod
    def create(
        cls,
        *,
        plan_id: str,
        authorization_id: str,
        actor: str,
        subject_signer: str,
        approved_at: str,
        expires_at: str,
        allowed_issuers: frozenset[str],
    ) -> ApprovalSigningRequest:
        body = _body(
            plan_id=plan_id,
            authorization_id=authorization_id,
            actor=actor,
            subject_signer=subject_signer,
            approved_at=approved_at,
            expires_at=expires_at,
        )
        normalized_issuers = _allowed_issuers(tuple(allowed_issuers))
        message_hex = "0x" + _payload(body).hex()
        document: JSONObject = {
            **body,
            "artifact_type": "operator_approval_signing_request",
            "allowed_issuers": list(normalized_issuers),
            "eip191_message_hex": message_hex,
        }
        return cls(
            plan_id=cast(str, body["plan_id"]),
            authorization_id=cast(str, body["authorization_id"]),
            actor=cast(str, body["actor"]),
            subject_signer=cast(str, body["subject_signer"]),
            approved_at=cast(str, body["approved_at"]),
            expires_at=cast(str, body["expires_at"]),
            allowed_issuers=normalized_issuers,
            intent=None,
            schema_version=2,
            eip191_message_hex=message_hex,
            _document_json=canonical_json(document),
        )

    @classmethod
    def create_reviewable(
        cls,
        *,
        plan: Plan,
        authorization_id: str,
        actor: str,
        approved_at: str,
        expires_at: str,
    ) -> ApprovalSigningRequest:
        body = _reviewable_body(
            plan=plan,
            authorization_id=authorization_id,
            actor=actor,
            approved_at=approved_at,
            expires_at=expires_at,
        )
        message_hex = "0x" + _payload(body).hex()
        document: JSONObject = {
            **body,
            "artifact_type": "operator_approval_signing_request",
            "eip191_message_hex": message_hex,
        }
        intent = cast(JSONObject, body["intent"])
        return cls(
            plan_id=plan.plan_id,
            authorization_id=authorization_id,
            actor=actor,
            subject_signer=cast(str, intent["signer"]),
            approved_at=approved_at,
            expires_at=expires_at,
            allowed_issuers=(),
            intent=intent,
            schema_version=3,
            eip191_message_hex=message_hex,
            _document_json=canonical_json(document),
        )

    @classmethod
    def parse(cls, value: dict[str, object]) -> ApprovalSigningRequest:
        if value.get("schema_version") == 3:
            if set(value) != _REVIEWABLE_REQUEST_KEYS:
                raise ApprovalError("approval signing request has an invalid schema")
            if value.get("artifact_type") != "operator_approval_signing_request":
                raise ApprovalError("unsupported approval signing request schema")
            plan_id = value.get("plan_id")
            authorization_id = value.get("authorization_id")
            actor = value.get("actor")
            approved_at = value.get("approved_at")
            expires_at = value.get("expires_at")
            intent_value = value.get("intent")
            body = _parsed_reviewable_body(
                plan_id=plan_id,
                authorization_id=authorization_id,
                actor=actor,
                approved_at=approved_at,
                expires_at=expires_at,
                intent=intent_value,
            )
            message_hex = "0x" + _payload(body).hex()
            if value.get("eip191_message_hex") != message_hex:
                raise ApprovalError("approval signing request message mismatch")
            parsed_intent = cast(JSONObject, body["intent"])
            signer = parsed_intent.get("signer")
            if not isinstance(signer, str):
                raise ApprovalError("approval signing request signer is invalid")
            return cls(
                plan_id=cast(str, body["plan_id"]),
                authorization_id=cast(str, body["authorization_id"]),
                actor=cast(str, body["actor"]),
                subject_signer=_issuer(signer, "intent signer"),
                approved_at=cast(str, body["approved_at"]),
                expires_at=cast(str, body["expires_at"]),
                allowed_issuers=(),
                intent=parsed_intent,
                schema_version=3,
                eip191_message_hex=message_hex,
                _document_json=canonical_json(value),
            )
        if set(value) != _REQUEST_KEYS:
            raise ApprovalError("approval signing request has an invalid schema")
        if (
            value["schema_version"] != 2
            or value["artifact_type"] != "operator_approval_signing_request"
        ):
            raise ApprovalError("unsupported approval signing request schema")
        issuers = value["allowed_issuers"]
        if not isinstance(issuers, list):
            raise ApprovalError("approval signing request allowlist must be an array")
        request = cls.create(
            plan_id=cast(str, value["plan_id"]),
            authorization_id=cast(str, value["authorization_id"]),
            actor=cast(str, value["actor"]),
            subject_signer=cast(str, value["subject_signer"]),
            approved_at=cast(str, value["approved_at"]),
            expires_at=cast(str, value["expires_at"]),
            allowed_issuers=frozenset(cast(list[str], issuers)),
        )
        if value["allowed_issuers"] != list(request.allowed_issuers):
            raise ApprovalError("approval signing request allowlist is not canonical")
        if value["eip191_message_hex"] != request.eip191_message_hex:
            raise ApprovalError("approval signing request message mismatch")
        return request

    def verify_for(
        self,
        plan: Plan,
        *,
        configured_issuers: frozenset[str] | None = None,
        expected_subject_signer: str,
        require_reviewable: bool = False,
    ) -> None:
        if self.plan_id != plan.plan_id:
            raise ApprovalError("approval signing request is bound to a different plan")
        if self.subject_signer != _issuer(expected_subject_signer, "expected_subject_signer"):
            raise ApprovalError("approval signing request is bound to a different subject signer")
        if self.schema_version == 3:
            if self.intent != approval_intent(plan):
                raise ApprovalError("approval signing request intent does not match plan")
            return
        if require_reviewable:
            raise ApprovalError("legacy approval signing request cannot authorize execution")
        if configured_issuers is None:
            raise ApprovalError("approval issuer allowlist is required")
        if self.allowed_issuers != _allowed_issuers(tuple(configured_issuers)):
            raise ApprovalError("approval signing request issuer allowlist changed")

    def to_approval(self, *, signature: str, issuer: str | None = None) -> Approval:
        if self.schema_version == 3:
            body = self._reviewable_body()
            return Approval._create_reviewable_from_body(body, signature)
        if issuer is None:
            raise ApprovalError("legacy approval requires an issuer")
        return Approval.create(
            plan_id=self.plan_id,
            authorization_id=self.authorization_id,
            actor=self.actor,
            subject_signer=self.subject_signer,
            approved_at=self.approved_at,
            expires_at=self.expires_at,
            issuer=issuer,
            signature=signature,
        )

    def _reviewable_body(self) -> JSONObject:
        if self.schema_version != 3 or self.intent is None:
            raise ApprovalError("approval signing request is not reviewable")
        return {
            "schema_version": 3,
            "artifact_type": "approval",
            "plan_id": self.plan_id,
            "authorization_id": self.authorization_id,
            "actor": self.actor,
            "approved_at": self.approved_at,
            "expires_at": self.expires_at,
            "intent": self.intent,
        }

    def to_dict(self) -> JSONObject:
        parsed = json.loads(self._document_json)
        if not isinstance(parsed, dict):
            raise AssertionError("canonical approval request must decode to an object")
        return cast(JSONObject, parsed)


@dataclass(frozen=True, slots=True)
class Approval:
    approval_id: str
    plan_id: str
    authorization_id: str
    actor: str
    subject_signer: str
    approved_at: str
    expires_at: str
    issuer: str
    signature: str = field(repr=False)
    intent: JSONObject | None
    schema_version: int
    _document_json: str = field(repr=False)

    @classmethod
    def signing_payload(
        cls,
        *,
        plan_id: str,
        authorization_id: str,
        actor: str,
        subject_signer: str,
        approved_at: str,
        expires_at: str,
    ) -> bytes:
        """Return exact bytes an allowed operator must EIP-191 sign externally."""

        return _payload(
            _body(
                plan_id=plan_id,
                authorization_id=authorization_id,
                actor=actor,
                subject_signer=subject_signer,
                approved_at=approved_at,
                expires_at=expires_at,
            )
        )

    @classmethod
    def signing_payload_hex(
        cls,
        *,
        plan_id: str,
        authorization_id: str,
        actor: str,
        subject_signer: str,
        approved_at: str,
        expires_at: str,
    ) -> str:
        """Return the detached EIP-191 message bytes as 0x-prefixed hex."""

        return (
            "0x"
            + cls.signing_payload(
                plan_id=plan_id,
                authorization_id=authorization_id,
                actor=actor,
                subject_signer=subject_signer,
                approved_at=approved_at,
                expires_at=expires_at,
            ).hex()
        )

    @classmethod
    def signing_payload_reviewable(
        cls,
        *,
        plan: Plan,
        authorization_id: str,
        actor: str,
        approved_at: str,
        expires_at: str,
    ) -> bytes:
        return _payload(
            _reviewable_body(
                plan=plan,
                authorization_id=authorization_id,
                actor=actor,
                approved_at=approved_at,
                expires_at=expires_at,
            )
        )

    @classmethod
    def signing_payload_hex_reviewable(
        cls,
        *,
        plan: Plan,
        authorization_id: str,
        actor: str,
        approved_at: str,
        expires_at: str,
    ) -> str:
        return "0x" + cls.signing_payload_reviewable(
            plan=plan,
            authorization_id=authorization_id,
            actor=actor,
            approved_at=approved_at,
            expires_at=expires_at,
        ).hex()

    @classmethod
    def create(
        cls,
        *,
        plan_id: str,
        authorization_id: str,
        actor: str,
        subject_signer: str,
        approved_at: str,
        expires_at: str,
        issuer: str,
        signature: str,
    ) -> Approval:
        body = _body(
            plan_id=plan_id,
            authorization_id=authorization_id,
            actor=actor,
            subject_signer=subject_signer,
            approved_at=approved_at,
            expires_at=expires_at,
        )
        normalized_issuer = _issuer(issuer)
        recovered = _recover_issuer(body, signature)
        if recovered != normalized_issuer:
            raise ApprovalError("approval issuer does not match signature")
        approval_id = _identifier(body)
        document: JSONObject = {
            **body,
            "issuer": normalized_issuer,
            "signature": signature,
            "approval_id": approval_id,
        }
        return cls(
            approval_id=approval_id,
            plan_id=plan_id,
            authorization_id=authorization_id,
            actor=actor,
            subject_signer=cast(str, body["subject_signer"]),
            approved_at=approved_at,
            expires_at=expires_at,
            issuer=normalized_issuer,
            signature=signature,
            intent=None,
            schema_version=2,
            _document_json=canonical_json(document),
        )

    @classmethod
    def create_reviewable(
        cls,
        *,
        plan: Plan,
        authorization_id: str,
        actor: str,
        approved_at: str,
        expires_at: str,
        signature: str,
    ) -> Approval:
        body = _reviewable_body(
            plan=plan,
            authorization_id=authorization_id,
            actor=actor,
            approved_at=approved_at,
            expires_at=expires_at,
        )
        return cls._create_reviewable_from_body(body, signature)

    @classmethod
    def _create_reviewable_from_body(
        cls,
        body: JSONObject,
        signature: str,
    ) -> Approval:
        if body.get("schema_version") != 3 or set(body) != {
            "schema_version",
            "artifact_type",
            "plan_id",
            "authorization_id",
            "actor",
            "approved_at",
            "expires_at",
            "intent",
        }:
            raise ApprovalError("reviewable approval body has an invalid schema")
        body = _parsed_reviewable_body(
            plan_id=body.get("plan_id"),
            authorization_id=body.get("authorization_id"),
            actor=body.get("actor"),
            approved_at=body.get("approved_at"),
            expires_at=body.get("expires_at"),
            intent=body.get("intent"),
        )
        recovered = _recover_issuer(body, signature)
        approval_id = _identifier(body)
        document: JSONObject = {
            **body,
            "issuer": recovered,
            "signature": signature,
            "approval_id": approval_id,
        }
        intent = body.get("intent")
        if not isinstance(intent, dict) or set(intent) != INTENT_KEYS:
            raise ApprovalError("reviewable approval intent has an invalid schema")
        return cls(
            approval_id=approval_id,
            plan_id=cast(str, body["plan_id"]),
            authorization_id=cast(str, body["authorization_id"]),
            actor=cast(str, body["actor"]),
            subject_signer=_issuer(intent.get("signer"), "intent signer"),
            approved_at=cast(str, body["approved_at"]),
            expires_at=cast(str, body["expires_at"]),
            issuer=recovered,
            signature=signature,
            intent=intent,
            schema_version=3,
            _document_json=canonical_json(document),
        )

    @classmethod
    def parse(cls, value: dict[str, object]) -> Approval:
        if value.get("schema_version") == 3:
            if set(value) != _REVIEWABLE_ARTIFACT_KEYS:
                raise ApprovalError("approval document has an invalid schema")
            if value.get("artifact_type") != "approval":
                raise ApprovalError("unsupported approval schema")
            intent = value.get("intent")
            if not isinstance(intent, dict) or set(intent) != INTENT_KEYS:
                raise ApprovalError("reviewable approval intent has an invalid schema")
            body = _parsed_reviewable_body(
                plan_id=value.get("plan_id"),
                authorization_id=value.get("authorization_id"),
                actor=value.get("actor"),
                approved_at=value.get("approved_at"),
                expires_at=value.get("expires_at"),
                intent=intent,
            )
            expected_id = _identifier(body)
            if value.get("approval_id") != expected_id:
                raise ApprovalError("approval_id mismatch")
            signature = value.get("signature")
            if not isinstance(signature, str):
                raise ApprovalError("approval signature must be a string")
            approval = cls._create_reviewable_from_body(body, signature)
            if value.get("issuer") != approval.issuer:
                raise ApprovalError("approval issuer does not match signature")
            return approval
        if set(value) != _ARTIFACT_KEYS:
            raise ApprovalError("approval document has an invalid schema")
        body = _body(
            plan_id=value["plan_id"],
            authorization_id=value["authorization_id"],
            actor=value["actor"],
            subject_signer=value["subject_signer"],
            approved_at=value["approved_at"],
            expires_at=value["expires_at"],
        )
        if value["schema_version"] != 2 or value["artifact_type"] != "approval":
            raise ApprovalError("unsupported approval schema")
        signature = value["signature"]
        if not isinstance(signature, str):
            raise ApprovalError("approval signature must be a string")
        expected_id = _identifier(body)
        if not isinstance(value["approval_id"], str) or value["approval_id"] != expected_id:
            raise ApprovalError("approval_id mismatch")
        return cls.create(
            plan_id=cast(str, body["plan_id"]),
            authorization_id=cast(str, body["authorization_id"]),
            actor=cast(str, body["actor"]),
            subject_signer=cast(str, body["subject_signer"]),
            approved_at=cast(str, body["approved_at"]),
            expires_at=cast(str, body["expires_at"]),
            issuer=cast(str, value["issuer"]),
            signature=signature,
        )

    def verify_for(
        self,
        plan: Plan,
        *,
        allowed_issuers: frozenset[str],
        expected_subject_signer: str,
        at: datetime | None = None,
        require_reviewable: bool = False,
    ) -> None:
        if not allowed_issuers:
            raise ApprovalError("approval issuer allowlist is required")
        if self.plan_id != plan.plan_id:
            raise ApprovalError("approval is bound to a different plan")
        if self.subject_signer != _issuer(expected_subject_signer, "expected_subject_signer"):
            raise ApprovalError("approval is bound to a different subject signer")
        if self.schema_version == 3:
            expected_intent = approval_intent(plan)
            if self.intent != expected_intent:
                raise ApprovalError("approval intent does not match plan")
            body: JSONObject = {
                "schema_version": 3,
                "artifact_type": "approval",
                "plan_id": self.plan_id,
                "authorization_id": self.authorization_id,
                "actor": self.actor,
                "approved_at": self.approved_at,
                "expires_at": self.expires_at,
                "intent": expected_intent,
            }
        else:
            if require_reviewable:
                raise ApprovalError("legacy approval cannot authorize execution")
            body = _body(
                plan_id=self.plan_id,
                authorization_id=self.authorization_id,
                actor=self.actor,
                subject_signer=self.subject_signer,
                approved_at=self.approved_at,
                expires_at=self.expires_at,
            )
        if _recover_issuer(body, self.signature) != self.issuer:
            raise ApprovalError("approval issuer does not match signature")
        normalized_allowlist = frozenset(
            _issuer(value, "allowed issuer") for value in allowed_issuers
        )
        if self.issuer not in normalized_allowlist:
            raise ApprovalError("approval issuer is not allowed")
        now = at or datetime.now(UTC)
        if now.tzinfo is None:
            raise ApprovalError("verification time must be timezone-aware")
        if now < _timestamp(self.approved_at, "approved_at"):
            raise ApprovalError("approval is not yet valid")
        if now >= _timestamp(self.expires_at, "expires_at"):
            raise ApprovalError("approval expired")

    def to_dict(self) -> JSONObject:
        parsed = json.loads(self._document_json)
        if not isinstance(parsed, dict):
            raise AssertionError("canonical approval must decode to an object")
        return cast(JSONObject, parsed)
