"""A local encrypted-keystore signer with strict file hygiene."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from eth_account import Account

from ..artifacts import read_private_bytes
from .base import SignedTransaction, eth_account_transaction, normalize_transaction


def _private_file(path: Path, name: str) -> None:
    if not path.is_absolute():
        raise ValueError(f"{name} path must be absolute")
    if path.is_symlink():
        raise ValueError(f"{name} must not be a symlink")
    try:
        details = path.stat()
    except OSError as error:
        raise ValueError(f"{name} is unavailable") from error
    if not stat.S_ISREG(details.st_mode):
        raise ValueError(f"{name} must be a regular file")
    if details.st_uid != os.getuid():
        raise PermissionError(f"{name} must be owned by the current user")
    if stat.S_IMODE(details.st_mode) != 0o600:
        raise PermissionError(f"{name} permissions must be 0600")


class LocalKeystoreSigner:
    """Decrypt a user-owned `eth-account` keystore without involving a subprocess."""

    preparation_replay_safe = True

    def __init__(self, keystore_path: Path, password_path: Path) -> None:
        _private_file(keystore_path, "keystore")
        _private_file(password_path, "password")
        try:
            encrypted = read_private_bytes(
                keystore_path,
                max_bytes=2 * 1024 * 1024,
            ).decode("utf-8")
            password = read_private_bytes(
                password_path,
                max_bytes=64 * 1024,
            ).decode("utf-8").rstrip("\r\n")
            private_key = Account.decrypt(encrypted, password)
            self._account = Account.from_key(private_key)
        except Exception as error:
            # The dependency can include decrypt inputs in error strings; never relay them.
            raise ValueError("keystore decryption failed") from error

    @property
    def address(self) -> str:
        return cast(str, self._account.address)

    def sign_transaction(self, transaction: Mapping[str, object]) -> SignedTransaction:
        normalized = normalize_transaction(transaction)
        signed = self._account.sign_transaction(eth_account_transaction(normalized))
        raw = bytes(signed.raw_transaction)
        return SignedTransaction(
            raw_transaction=raw,
            transaction_hash="0x" + signed.hash.hex(),
            signer_address=self.address,
        )
