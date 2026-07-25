import json
from dataclasses import FrozenInstanceError

import pytest

from agent_bridge_guard.rpc import (
    NeedsReconciliationError,
    ReorgDetectedError,
    RpcClient,
    RpcConfigurationError,
    RpcDisagreementError,
    RpcPool,
    RpcProtocolError,
    RpcRemoteError,
    TransactionFailedError,
    wait_for_final_receipt,
)

HASH = "0x" + "ab" * 32
BLOCK_HASH = "0x" + "cd" * 32


def replies(*values: object):
    values = list(values)

    def transport(_url: str, body: bytes, _timeout: float) -> bytes:
        request = json.loads(body)
        value = values.pop(0)
        if isinstance(value, bytes):
            return value
        return json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": value}).encode()

    return transport


def receipt(
    *, block_hash: str = BLOCK_HASH, status: str = "0x1", logs: list[object] | None = None
) -> dict[str, object]:
    return {
        "transactionHash": HASH,
        "status": status,
        "blockNumber": "0xa",
        "blockHash": block_hash,
        "logs": [] if logs is None else logs,
    }


def test_rejects_unsafe_or_credentialed_endpoints() -> None:
    with pytest.raises(RpcConfigurationError):
        RpcClient("http://example.test")
    with pytest.raises(RpcConfigurationError):
        RpcClient("https://user:secret@example.test")
    RpcClient("http://localhost:8545", allow_insecure_localhost=True)


def test_client_configuration_cannot_change_after_initialization() -> None:
    rpc = RpcClient("https://rpc.example.test", transport=replies("0x1"))

    with pytest.raises(FrozenInstanceError):
        rpc.endpoint = "https://other.example.test"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        rpc.transport = None  # type: ignore[misc]

    assert rpc.chain_id() == 1


def test_client_methods_encode_rpc_and_validate_results() -> None:
    rpc = RpcClient(
        "https://rpc.example.test/private-token",
        transport=replies(
            "0xa4b1", "0x7", HASH, {"hash": HASH}, None, "0x10", {"hash": BLOCK_HASH}
        ),
    )
    assert rpc.chain_id() == 42161
    assert rpc.transaction_count("0xabc") == 7
    assert rpc.send_raw_transaction("0x1234") == HASH
    assert rpc.transaction_by_hash(HASH) == {"hash": HASH}
    assert rpc.receipt(HASH) is None
    assert rpc.block_number() == 16
    assert rpc.block(16) == {"hash": BLOCK_HASH}


def test_strict_response_schema_and_limits_are_enforced_without_endpoint_leakage() -> None:
    rpc = RpcClient(
        "https://rpc.example.test/private-token",
        transport=replies(b'{"jsonrpc":"2.0","id":99,"result":"0x1"}'),
    )
    with pytest.raises(RpcProtocolError) as error:
        rpc.chain_id()
    assert "private-token" not in str(error.value)

    oversized = RpcClient(
        "https://rpc.example.test", max_response_bytes=2, transport=replies("0x1")
    )
    with pytest.raises(RpcProtocolError, match="byte limit"):
        oversized.chain_id()

    limited_request = RpcClient(
        "https://rpc.example.test", max_request_bytes=4, transport=replies("0x1")
    )
    with pytest.raises(RpcProtocolError, match="byte limit"):
        limited_request.chain_id()


def test_client_repr_and_remote_errors_do_not_retain_endpoint_bearing_secrets() -> None:
    endpoint = "https://rpc.example.test/private-token"
    rpc = RpcClient(endpoint, transport=replies("0x1"))
    assert endpoint not in repr(rpc)

    def remote_error(_url: str, body: bytes, _timeout: float) -> bytes:
        request = json.loads(body)
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request["id"],
                "error": {"code": -32000, "message": f"failed at {endpoint}"},
            }
        ).encode()

    with pytest.raises(RpcRemoteError) as error:
        RpcClient(endpoint, transport=remote_error).chain_id()
    assert endpoint not in str(error.value)
    assert endpoint not in vars(error.value).values()


def test_pool_checks_both_chain_ids() -> None:
    primary = RpcClient("https://one.example.test", transport=replies("0xa4b1"))
    secondary = RpcClient("https://two.example.test", transport=replies("0x1"))
    with pytest.raises(RpcDisagreementError) as error:
        RpcPool(primary, secondary, 42161)
    assert error.value.state == "NEEDS_RECONCILIATION"


def test_waits_for_final_successful_canonical_receipt() -> None:
    rpc = RpcClient(
        "https://rpc.example.test",
        transport=replies(None, receipt(), "0xb", receipt(), {"hash": BLOCK_HASH}),
    )
    sleeps: list[float] = []
    assert wait_for_final_receipt(rpc, HASH, 1, sleep=sleeps.append, max_polls=4) == receipt()
    assert sleeps == [1.0]


def test_pool_finality_requires_secondary_receipt_and_canonical_block_agreement() -> None:
    primary = RpcClient(
        "https://one.example.test",
        transport=replies("0xa4b1", receipt(), "0xa", receipt(), {"hash": BLOCK_HASH}),
    )
    secondary = RpcClient(
        "https://two.example.test",
        transport=replies("0xa4b1", "0xa", receipt(), {"hash": BLOCK_HASH}),
    )
    pool = RpcPool(primary, secondary, 42161)
    assert wait_for_final_receipt(pool, HASH, 0, max_polls=2) == receipt()


def test_pool_finality_never_verifies_secondary_receipt_disagreement() -> None:
    primary = RpcClient(
        "https://one.example.test",
        transport=replies("0xa4b1", receipt(), "0xa", receipt(), {"hash": BLOCK_HASH}),
    )
    secondary = RpcClient(
        "https://two.example.test",
        transport=replies("0xa4b1", "0xa", receipt(block_hash="0x" + "ef" * 32)),
    )
    pool = RpcPool(primary, secondary, 42161)
    with pytest.raises(RpcDisagreementError) as error:
        wait_for_final_receipt(pool, HASH, 0, max_polls=2)
    assert error.value.state == "NEEDS_RECONCILIATION"


def test_pool_finality_rejects_forged_primary_log_when_secondary_is_honest() -> None:
    honest_log = {
        "address": "0x" + "12" * 20,
        "topics": ["0x" + "34" * 32],
        "data": "0x5678",
        "logIndex": "0x0",
        "transactionHash": "0x" + "AB" * 32,
        "blockHash": "0x" + "CD" * 32,
        "blockNumber": "0xA",
        "removed": False,
    }
    forged_log = {**honest_log, "data": "0xdead"}
    primary = RpcClient(
        "https://one.example.test",
        transport=replies(
            "0xa4b1",
            receipt(logs=[forged_log]),
            "0xa",
            receipt(logs=[forged_log]),
            {"hash": BLOCK_HASH},
        ),
    )
    secondary = RpcClient(
        "https://two.example.test",
        transport=replies("0xa4b1", "0xa", receipt(logs=[honest_log]), {"hash": BLOCK_HASH}),
    )
    pool = RpcPool(primary, secondary, 42161)

    with pytest.raises(RpcDisagreementError) as error:
        wait_for_final_receipt(pool, HASH, 0, max_polls=2)

    assert error.value.state == "NEEDS_RECONCILIATION"


def test_pool_finality_accepts_matching_normalized_ordered_logs() -> None:
    primary_log = {
        "address": "0x" + "12" * 20,
        "topics": ["0x" + "34" * 32],
        "data": "0x5678",
        "logIndex": "0x0",
        "transactionHash": HASH,
        "blockHash": BLOCK_HASH,
        "blockNumber": "0xa",
        "removed": False,
    }
    secondary_log = {
        **primary_log,
        "address": "0x" + "12".upper() * 20,
        "topics": ["0x" + "34".upper() * 32],
        "data": "0x" + "5678".upper(),
        "logIndex": "0x00",
        "transactionHash": "0x" + "AB" * 32,
        "blockHash": "0x" + "CD" * 32,
        "blockNumber": "0x0A",
    }
    primary = RpcClient(
        "https://one.example.test",
        transport=replies(
            "0xa4b1",
            receipt(logs=[primary_log]),
            "0xa",
            receipt(logs=[primary_log]),
            {"hash": BLOCK_HASH},
        ),
    )
    secondary = RpcClient(
        "https://two.example.test",
        transport=replies(
            "0xa4b1", "0xa", receipt(logs=[secondary_log]), {"hash": BLOCK_HASH}
        ),
    )
    pool = RpcPool(primary, secondary, 42161)

    assert wait_for_final_receipt(pool, HASH, 0, max_polls=2) == receipt(logs=[primary_log])


def test_pool_finality_requires_secondary_confirmation_depth() -> None:
    primary = RpcClient(
        "https://one.example.test",
        transport=replies("0xa4b1", receipt(), "0xb", receipt(), {"hash": BLOCK_HASH}),
    )
    secondary = RpcClient("https://two.example.test", transport=replies("0xa4b1", "0xa"))
    pool = RpcPool(primary, secondary, 42161)
    with pytest.raises(RpcDisagreementError) as error:
        wait_for_final_receipt(pool, HASH, 1, max_polls=2)
    assert error.value.state == "NEEDS_RECONCILIATION"


def test_finality_never_verifies_failed_or_reorged_receipts() -> None:
    failed_receipt = receipt(status="0x0")
    failed = RpcClient(
        "https://rpc.example.test",
        transport=replies(failed_receipt, "0xa", failed_receipt, {"hash": BLOCK_HASH}),
    )
    with pytest.raises(TransactionFailedError) as error:
        wait_for_final_receipt(failed, HASH, 0, max_polls=1)
    assert error.value.receipt == failed_receipt

    reorged = RpcClient(
        "https://rpc.example.test",
        transport=replies(receipt(), "0xa", receipt(block_hash="0x" + "ef" * 32)),
    )
    with pytest.raises(ReorgDetectedError) as error:
        wait_for_final_receipt(reorged, HASH, 0, max_polls=2)
    assert error.value.state == "NEEDS_RECONCILIATION"


def test_failed_receipt_requires_pool_quorum_and_canonical_finality() -> None:
    failed_receipt = receipt(status="0x0")
    primary = RpcClient(
        "https://one.example.test",
        transport=replies("0xa4b1", failed_receipt, "0xb", failed_receipt, {"hash": BLOCK_HASH}),
    )
    secondary = RpcClient(
        "https://two.example.test",
        transport=replies("0xa4b1", "0xb", failed_receipt, {"hash": BLOCK_HASH}),
    )
    pool = RpcPool(primary, secondary, 42161)

    with pytest.raises(TransactionFailedError) as error:
        wait_for_final_receipt(pool, HASH, 1, max_polls=2)

    assert error.value.receipt == failed_receipt


def test_failed_receipt_disagreement_does_not_become_terminal_failure() -> None:
    primary = RpcClient(
        "https://one.example.test",
        transport=replies(
            "0xa4b1", receipt(status="0x0"), "0xb", receipt(status="0x0"), {"hash": BLOCK_HASH}
        ),
    )
    secondary = RpcClient(
        "https://two.example.test",
        transport=replies("0xa4b1", "0xb", receipt(status="0x1")),
    )
    pool = RpcPool(primary, secondary, 42161)

    with pytest.raises(RpcDisagreementError):
        wait_for_final_receipt(pool, HASH, 1, max_polls=2)


def test_finality_poll_limit_requires_reconciliation() -> None:
    rpc = RpcClient("https://rpc.example.test", transport=replies(None, None))
    with pytest.raises(NeedsReconciliationError) as error:
        wait_for_final_receipt(rpc, HASH, 1, max_polls=2, sleep=lambda _: None)
    assert error.value.state == "NEEDS_RECONCILIATION"
