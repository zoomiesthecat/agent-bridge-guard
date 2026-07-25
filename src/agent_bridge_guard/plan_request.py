"""Strict user intent input for deBridge plan creation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from eth_utils import is_address, to_checksum_address  # type: ignore[attr-defined]

from .artifacts import read_json_object

OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
BASE_UNITS = re.compile(r"^[1-9][0-9]*$")
FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "route_id",
        "source_chain_alias",
        "destination_chain_alias",
        "amount_wei",
        "minimum_output_wei",
        "signer",
        "recipient",
        "expires_at",
    }
)


class PlanRequestError(ValueError):
    """Plan request is incomplete or ambiguous."""


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not OPAQUE_ID.fullmatch(value):
        raise PlanRequestError(f"{label} must be an opaque identifier")
    return value


def _amount(value: object, label: str) -> int:
    if not isinstance(value, str) or not BASE_UNITS.fullmatch(value):
        raise PlanRequestError(f"{label} must be a positive decimal string")
    return int(value)


def _address(value: object, label: str) -> str:
    if not isinstance(value, str) or not is_address(value):
        raise PlanRequestError(f"{label} must be an EVM address")
    return cast(str, to_checksum_address(value))


def _expiry(value: object) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PlanRequestError("expires_at must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PlanRequestError("expires_at must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise PlanRequestError("expires_at must be an ISO-8601 UTC timestamp")
    return value


@dataclass(frozen=True, slots=True)
class PlanRequest:
    request_id: str
    route_id: str
    source_chain_alias: str
    destination_chain_alias: str
    amount_wei: int
    minimum_output_wei: int
    signer: str
    recipient: str
    expires_at: str

    @classmethod
    def load(cls, path: str | Path) -> PlanRequest:
        try:
            document = read_json_object(path)
        except Exception as exc:
            raise PlanRequestError("plan request cannot be read") from exc
        if set(document) != FIELDS or document.get("schema_version") != 2:
            raise PlanRequestError("plan request fields do not match schema")
        amount = _amount(document.get("amount_wei"), "amount_wei")
        minimum = _amount(document.get("minimum_output_wei"), "minimum_output_wei")
        return cls(
            request_id=_identifier(document.get("request_id"), "request_id"),
            route_id=_identifier(document.get("route_id"), "route_id"),
            source_chain_alias=_identifier(
                document.get("source_chain_alias"),
                "source_chain_alias",
            ),
            destination_chain_alias=_identifier(
                document.get("destination_chain_alias"),
                "destination_chain_alias",
            ),
            amount_wei=amount,
            minimum_output_wei=minimum,
            signer=_address(document.get("signer"), "signer"),
            recipient=_address(document.get("recipient"), "recipient"),
            expires_at=_expiry(document.get("expires_at")),
        )
