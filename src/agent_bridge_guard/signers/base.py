"""Shared signing contract and EIP-1559 transaction normalization."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Protocol, TypedDict, cast, runtime_checkable

from eth_utils import is_address, to_checksum_address  # type: ignore[attr-defined]


class EIP1559Transaction(TypedDict):
    chain_id: int
    nonce: int
    to: str
    value: int
    data: str
    gas: int
    max_fee_per_gas: int
    max_priority_fee_per_gas: int


@dataclass(frozen=True, slots=True)
class SignedTransaction:
    """A raw transaction ready for a broadcaster, bound to its recovered signer."""

    raw_transaction: bytes = dataclass_field(repr=False)
    transaction_hash: str
    signer_address: str


@runtime_checkable
class Signer(Protocol):
    """Signs one fully specified EIP-1559 transaction without broadcasting it."""

    preparation_replay_safe: bool

    @property
    def address(self) -> str: ...

    def sign_transaction(self, transaction: Mapping[str, object]) -> SignedTransaction: ...


_FIELDS = frozenset(EIP1559Transaction.__annotations__)
_INTEGER_FIELDS = _FIELDS - {"to", "data"}


def normalize_transaction(transaction: Mapping[str, object]) -> EIP1559Transaction:
    """Validate and canonicalize the only transaction shape this boundary signs."""

    supplied = frozenset(transaction)
    if supplied != _FIELDS:
        missing = ", ".join(sorted(_FIELDS - supplied))
        unexpected = ", ".join(sorted(supplied - _FIELDS))
        parts = [
            part
            for part in (
                f"missing: {missing}" if missing else "",
                f"unexpected: {unexpected}" if unexpected else "",
            )
            if part
        ]
        raise ValueError("invalid EIP-1559 transaction fields (" + "; ".join(parts) + ")")

    numbers: dict[str, int] = {}
    for field in _INTEGER_FIELDS:
        value = transaction[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{field} must be a non-negative integer")
        numbers[field] = value
    if numbers["gas"] == 0:
        raise ValueError("gas must be greater than zero")
    if numbers["max_fee_per_gas"] < numbers["max_priority_fee_per_gas"]:
        raise ValueError("max_fee_per_gas must be at least max_priority_fee_per_gas")

    to = transaction["to"]
    if not isinstance(to, str) or not is_address(to):
        raise ValueError("to must be an EVM address")
    data = transaction["data"]
    if not isinstance(data, str) or not data.startswith("0x"):
        raise ValueError("data must be a 0x-prefixed hex string")
    try:
        bytes.fromhex(data[2:])
    except ValueError as error:
        raise ValueError("data must be a 0x-prefixed hex string") from error
    return {
        "chain_id": numbers["chain_id"],
        "nonce": numbers["nonce"],
        "to": cast(str, to_checksum_address(to)),
        "value": numbers["value"],
        "data": "0x" + data[2:].lower(),
        "gas": numbers["gas"],
        "max_fee_per_gas": numbers["max_fee_per_gas"],
        "max_priority_fee_per_gas": numbers["max_priority_fee_per_gas"],
    }


def eth_account_transaction(transaction: EIP1559Transaction) -> dict[str, object]:
    """Translate the domain transaction exactly once at the eth-account boundary."""

    return {
        "type": 2,
        "chainId": transaction["chain_id"],
        "nonce": transaction["nonce"],
        "to": transaction["to"],
        "value": transaction["value"],
        "data": transaction["data"],
        "gas": transaction["gas"],
        "maxFeePerGas": transaction["max_fee_per_gas"],
        "maxPriorityFeePerGas": transaction["max_priority_fee_per_gas"],
    }
