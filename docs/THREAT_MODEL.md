# Threat model

## Protected assets

- The exact approved direct-reserve transaction, its signing authority, and its nonce.
- Operator policy, route manifests, reviewable approvals, and verifier-produced proofs.
- Private RPC and custody configuration plus the durable operation record.

## Supported boundary

The supported runtime route is deBridge `reserve_erc20_dln_native_out`: an exact
ERC-20 gross input with a manually established allowance. The guard never creates
an ERC-20 approval transaction. Legacy Kyber/native-swap route construction is
quarantined and cannot authorize production execution.

## Threats and controls

| Threat | Control |
| --- | --- |
| Route, quote, or plan drift | Protected policy and reviewed manifest bind the direct route, token, DLN proxy, code hash, fee, limits, and exact calldata. |
| Agent self-authorizes | The trusted policy is operator/root-owned, runtime-nonwritable, absolute, non-symlinked, and checked before and after descriptor open. Runtime must not be root. |
| Approval replay or misleading approval | A schema-v3 reviewable approval binds the exact plan and human-readable execution intent, issuer, actor, and validity window. |
| Authorization changes during execution | Authorization is reloaded and revalidated at reservation, before signing/import persistence, before first send, and before any resend. |
| Concurrent preparation or stale worker | SQLite claim token, kind/fingerprint, phase, and lease fence preparation; only the live token can persist bytes or a pre-broadcast failure. |
| Broadcast crash or ambiguity | Persist exact signed bytes before send; reconcile or resend only those bytes. Read-only resume never sends. |
| RPC spoof or reorg | Two endpoint corroboration, receipt identity checks, confirmation depth, and canonical-block checks. This is corroboration, not Byzantine fault tolerance: common upstream/provider compromise remains possible. |
| Forged receipt mapping | Only typed verifier-produced source and destination proof capabilities may advance proof-bearing state. |
| SQLite alteration | Private paths, transactions, and fsync reduce accidental/racing writes. SQLite is not tamper-evident; an attacker with database write access can still alter it. |
| Local key compromise | A same-UID malicious agent can read or invoke local signing material; local keystore mode is not containment. Use a separate executor UID/service or a remote/detached signer where containment matters. |
| Secret leakage | Signer adapters resolve secrets internally; secrets, raw signed transactions, and private RPC URLs are excluded from argv, artifacts, and diagnostics. |

## Custody boundaries

Local encrypted keystores suit bounded hot wallets only. Detached signing keeps
the EVM key off the runtime host and validates every imported EIP-1559 field,
canonical signature shape, and recovered signer. Turnkey is alpha capability
plumbing only: transaction signing is disabled. TWAK is FD-pinned status-only
inspection; it does not sign or broadcast.

## Reporting

Private plans and operation databases are owner-only. Public receipts omit raw
calldata, signed bytes, secret paths, RPC URLs, approvals, and idempotency keys.
