from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.typed_transactions import TypedTransaction
from hexbytes import HexBytes

from agent_bridge_guard.signers import (
    DetachedSigner,
    LocalKeystoreSigner,
    SignedTransaction,
    TurnkeySigner,
)

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def transaction() -> dict[str, object]:
    return {
        "chain_id": 42161,
        "nonce": 7,
        "to": "0x1111111111111111111111111111111111111111",
        "value": 42,
        "data": "0x1234",
        "gas": 800_000,
        "max_fee_per_gas": 30_000_000,
        "max_priority_fee_per_gas": 1_000_000,
    }


def keystore(tmp_path: Path, password: str) -> tuple[Path, Path, str]:
    account = Account.create()
    keyfile = tmp_path / "signer.json"
    password_file = tmp_path / "signer.password"
    keyfile.write_text(json.dumps(Account.encrypt(account.key, password)), encoding="utf-8")
    password_file.write_text(password, encoding="utf-8")
    os.chmod(keyfile, 0o600)
    os.chmod(password_file, 0o600)
    return keyfile, password_file, account.address


def test_local_keystore_signs_exact_eip1559_transaction(tmp_path: Path) -> None:
    keyfile, password_file, address = keystore(tmp_path, "test-password")

    signer = LocalKeystoreSigner(keyfile, password_file)
    signed = signer.sign_transaction(transaction())

    assert isinstance(signed, SignedTransaction)
    assert signed.signer_address == address
    assert signed.transaction_hash.startswith("0x")
    assert Account.recover_transaction(signed.raw_transaction) == address


def test_local_keystore_rejects_relative_or_insecure_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keyfile, password_file, _ = keystore(tmp_path, "test-password")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="absolute"):
        LocalKeystoreSigner(Path(keyfile.name), password_file)

    os.chmod(password_file, 0o644)
    with pytest.raises(PermissionError, match="0600"):
        LocalKeystoreSigner(keyfile, password_file)


def test_local_keystore_rejects_symlinked_parent_directory(tmp_path: Path) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    keyfile, password_file, _ = keystore(private_root, "test-password")
    linked_root = tmp_path / "linked-private"
    linked_root.symlink_to(private_root, target_is_directory=True)

    with pytest.raises(ValueError, match="keystore decryption failed"):
        LocalKeystoreSigner(
            linked_root / keyfile.name,
            linked_root / password_file.name,
        )


def test_detached_round_trip_verifies_every_bound_field(tmp_path: Path) -> None:
    keyfile, password_file, address = keystore(tmp_path, "test-password")
    local = LocalKeystoreSigner(keyfile, password_file)
    detached = DetachedSigner(expected_address=address)
    request = detached.export_unsigned_transaction(transaction())
    signed = local.sign_transaction(json.loads(request))

    imported = detached.import_signed_transaction(transaction(), signed.raw_transaction)

    assert imported.signer_address == address
    assert imported.transaction_hash == signed.transaction_hash


def test_detached_accepts_canonical_low_s_signature(tmp_path: Path) -> None:
    keyfile, password_file, address = keystore(tmp_path, "test-password")
    signed = LocalKeystoreSigner(keyfile, password_file).sign_transaction(transaction())

    decoded = TypedTransaction.from_bytes(HexBytes(signed.raw_transaction)).as_dict()
    assert 1 <= decoded["s"] <= SECP256K1_N // 2

    imported = DetachedSigner(expected_address=address).import_signed_transaction(
        transaction(), signed.raw_transaction
    )

    assert imported.transaction_hash == signed.transaction_hash


def test_detached_rejects_nonempty_access_list(tmp_path: Path) -> None:
    account = Account.create()
    signed = Account.sign_transaction(
        {
            "type": 2,
            "chainId": 42161,
            "nonce": 7,
            "to": "0x1111111111111111111111111111111111111111",
            "value": 42,
            "data": "0x1234",
            "gas": 800_000,
            "maxFeePerGas": 30_000_000,
            "maxPriorityFeePerGas": 1_000_000,
            "accessList": [
                {"address": "0x2222222222222222222222222222222222222222", "storageKeys": []}
            ],
        },
        account.key,
    )

    with pytest.raises(ValueError, match="invalid signed EIP-1559 transaction"):
        DetachedSigner(expected_address=account.address).import_signed_transaction(
            transaction(), signed.raw_transaction
        )


def test_detached_rejects_high_s_signature_mutation(tmp_path: Path) -> None:
    keyfile, password_file, address = keystore(tmp_path, "test-password")
    signed = LocalKeystoreSigner(keyfile, password_file).sign_transaction(transaction())
    decoded = TypedTransaction.from_bytes(HexBytes(signed.raw_transaction)).as_dict()
    decoded["v"] = 1 - decoded["v"]
    decoded["s"] = SECP256K1_N - decoded["s"]
    high_s_raw = bytes(TypedTransaction.from_dict(decoded).encode())

    assert Account.recover_transaction(high_s_raw) == address
    with pytest.raises(ValueError, match="invalid signed EIP-1559 transaction"):
        DetachedSigner(expected_address=address).import_signed_transaction(
            transaction(), high_s_raw
        )


@pytest.mark.parametrize("field,value", [("nonce", 8), ("value", 43), ("data", "0x")])
def test_detached_rejects_signed_transaction_with_any_changed_bound_field(
    tmp_path: Path, field: str, value: object
) -> None:
    keyfile, password_file, address = keystore(tmp_path, "test-password")
    local = LocalKeystoreSigner(keyfile, password_file)
    original = transaction()
    altered = {**original, field: value}
    signed = local.sign_transaction(altered)

    with pytest.raises(ValueError, match="does not match"):
        DetachedSigner(expected_address=address).import_signed_transaction(
            original, signed.raw_transaction
        )


def test_secret_canary_never_appears_in_signer_errors(tmp_path: Path) -> None:
    canary = "DO_NOT_LEAK_SIGNER_PASSWORD"
    keyfile, password_file, _ = keystore(tmp_path, canary)
    password_file.write_text("wrong-" + canary, encoding="utf-8")

    with pytest.raises(ValueError) as error:
        LocalKeystoreSigner(keyfile, password_file)

    assert canary not in str(error.value)


def test_turnkey_credential_errors_do_not_echo_secret_canary() -> None:
    canary = "DO_NOT_LEAK_TURNKEY_PRIVATE_KEY"

    with pytest.raises(ValueError) as error:
        TurnkeySigner.from_environment({"TURNKEY_API_PRIVATE_KEY": canary})

    assert canary not in str(error.value)
