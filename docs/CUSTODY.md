# Custody integrations

Agent Bridge Guard separates exact EIP-1559 signing from broadcast. A signer
receives one fully specified transaction; it never selects a route or creates
an allowance transaction.

## Local encrypted keystore

This is a bounded hot-wallet mode, not a hostile-agent containment boundary.
Keystore and password files must be absolute, owner-owned regular files,
non-symlinks, and mode `0600`. Encryption at rest does not protect a running
same-UID process: a malicious agent under that UID can read or invoke the key.

Run the executor under a separate UID/service with filesystem and RPC access
limited to the execution boundary, or use a detached/remote signer, when the
planning agent must be contained from signing authority.

## Detached external signer

This is the enabled key-off-host path. The importer requires an exact EIP-1559
type-2 transaction with an empty access list, canonical y-parity and low-s
signature, and every planned field plus recovered signer equal to the approved
operation. A detached import is replayable only for the same exact raw bytes;
different bytes receive a distinct preparation fingerprint.

## TWAK

TWAK is status-only. The adapter accepts an operator-pinned absolute executable
and invokes only `wallet status --json` through an FD-pinned executable
boundary, with a bounded timeout and allowlisted status environment. It does
not pass a wallet password, inherit the agent environment, install packages,
sign raw transactions, or enable bridge execution.

## Turnkey

Turnkey is alpha capability plumbing only. The adapter reports an unavailable
experimental capability and transaction signing is disabled. Do not treat an
API stamping key or an SDK installation as authorization to execute a route.

## Next custody work

Any future remote signer needs exact-byte vectors, canonical secp256k1 parity
handling, policy-denial tests, replay behavior, and a containment review before
it may be marked replay-safe or enabled for live execution.
