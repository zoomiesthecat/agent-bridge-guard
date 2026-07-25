"""Offline hand-off signing that imports only an exactly matching raw transaction."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import cast

from eth_account import Account
from eth_account.typed_transactions import TypedTransaction  # type: ignore[attr-defined]
from eth_utils import keccak, to_checksum_address  # type: ignore[attr-defined]
from hexbytes import HexBytes

from .base import EIP1559Transaction, SignedTransaction, normalize_transaction

_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class DetachedSigner:
    """Exports canonical requests and verifies an externally-produced EIP-1559 signature."""

    def __init__(self, expected_address: str) -> None:
        self._expected_address = to_checksum_address(expected_address)

    @property
    def address(self) -> str:
        return self._expected_address

    def export_unsigned_transaction(self, transaction: Mapping[str, object]) -> str:
        return json.dumps(normalize_transaction(transaction), sort_keys=True, separators=(",", ":"))

    def import_signed_transaction(
        self, transaction: Mapping[str, object], raw_transaction: bytes | str
    ) -> SignedTransaction:
        expected = normalize_transaction(transaction)
        raw = HexBytes(raw_transaction)
        try:
            decoded = cast(Mapping[str, object], TypedTransaction.from_bytes(raw).as_dict())
            actual = self._decoded_transaction(decoded)
            signer = Account.recover_transaction(raw)
        except Exception as error:
            raise ValueError("invalid signed EIP-1559 transaction") from error
        if actual != expected:
            raise ValueError("signed transaction does not match the unsigned request")
        if cast(str, to_checksum_address(signer)) != self.address:
            raise ValueError("signed transaction signer does not match expected address")
        return SignedTransaction(
            raw_transaction=bytes(raw),
            transaction_hash="0x" + keccak(raw).hex(),
            signer_address=signer,
        )

    @staticmethod
    def _decoded_transaction(decoded: Mapping[str, object]) -> EIP1559Transaction:
        if decoded.get("type") != 2:
            raise ValueError("transaction is not EIP-1559")
        to = decoded.get("to")
        data = decoded.get("data")
        if not isinstance(to, bytes) or not isinstance(data, bytes):
            raise ValueError("invalid EIP-1559 fields")
        access_list = decoded.get("accessList")
        if not isinstance(access_list, (list, tuple)) or access_list:
            raise ValueError("EIP-1559 accessList must be empty")
        y_parity = decoded.get("v")
        r = decoded.get("r")
        s = decoded.get("s")
        if not isinstance(y_parity, int) or isinstance(y_parity, bool) or y_parity not in (0, 1):
            raise ValueError("invalid EIP-1559 yParity")
        if not isinstance(r, int) or isinstance(r, bool) or not 1 <= r < _SECP256K1_N:
            raise ValueError("invalid EIP-1559 r")
        if not isinstance(s, int) or isinstance(s, bool) or not 1 <= s <= _SECP256K1_N // 2:
            raise ValueError("invalid EIP-1559 s")
        candidate: dict[str, object] = {
            "chain_id": decoded.get("chainId"),
            "nonce": decoded.get("nonce"),
            "to": to_checksum_address(to),
            "value": decoded.get("value"),
            "data": "0x" + data.hex(),
            "gas": decoded.get("gas"),
            "max_fee_per_gas": decoded.get("maxFeePerGas"),
            "max_priority_fee_per_gas": decoded.get("maxPriorityFeePerGas"),
        }
        return normalize_transaction(candidate)
