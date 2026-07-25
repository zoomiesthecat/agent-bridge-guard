# Product contract

## Outcome

Provide one auditable machine interface:

```text
route digest -> protected policy -> plan
  -> reviewable off-box approval
  -> local or detached signing
  -> persist exact bytes -> submit/reconcile
  -> source finality -> destination discovery/proof -> redacted receipt
```

This project is an execution guard, not a bridge, wallet, solver, allowance
manager, or route aggregator.

## Production-candidate scope

- Python library and JSON-first CLI; no hosted service.
- One deBridge route: reserve ERC-20 direct `createSaltedOrder` to native
  destination output.
- Exact pre-existing gross ERC-20 allowance; the guard never creates an
  approval transaction.
- Operator-protected policy containing approval issuers, authorized canonical
  route-manifest digests, and confirmation thresholds.
- Schema-v2 immutable plan containing policy identity and full canonical
  manifest snapshot.
- Schema-v3 approval signing material, reviewable Plan-derived intent.
- Local encrypted Web3 keystore and generic detached EIP-1559 signing.
- SQLite operation ledger, token-fenced preparation, and versioned artifacts.
- Exact signed bytes persisted before broadcast.
- Read-only recovery by default; `--go` permits only checked exact-byte send.
- Two-endpoint RPC corroboration, finality, and canonical block recheck.
- Tracking-assisted candidate discovery followed by exact destination
  `FulfilledOrder` verification.
- Library-only TWAK readiness boundary; bridge signing disabled.
- Turnkey alpha boundary; live signing disabled.

## Quarantined or unsupported

- The historical native-input/Kyber source-aggregator route.
- Alternate aggregators, routers, selectors, and opaque source swap payloads.
- Affiliate fees, referrals, permits, destination hooks, and arbitrary calls.
- Guard-created ERC-20 approvals or unlimited allowance management.
- Browser UI and best-route aggregation.
- Hosted multi-user custody.
- Automatic replacement, gas bumping, or guessing whether an ambiguous send failed.
- Safe, WalletConnect, AWS KMS, Turnkey, or TWAK live execution in `0.1`.
- Automated cancellation/refund. It remains fail-closed until destination
  `SentOrderCancel` and source `ClaimedOrderCancel` are fully decoded and bound.

## Custody contract

Local encrypted-keystore mode is a bounded hot-wallet mode. File permissions
protect against other OS users and mistakes, not a malicious same-UID agent.
Hostile-agent containment requires a separate executor UID/service or a
policy-enforcing remote/detached signer.

Approval signing and transaction signing are separate capabilities. Neither
may infer permission from the other.

## Durable state contract

```text
RESERVED
BROADCAST_PREPARED
BROADCAST_ATTEMPTED
SUBMISSION_UNKNOWN
SOURCE_PENDING
SOURCE_FINAL
ORDER_PENDING
DESTINATION_PENDING
VERIFIED
```

Exceptional or terminal states:

```text
FAILED_PRE_BROADCAST
SOURCE_FAILED
NEEDS_RECONCILIATION
CANCELLED_CONFIRMED
```

`SOURCE_FAILED` requires a canonical sufficiently confirmed receipt with status
`0`, corroborated by both configured source RPCs. `CANCELLED_CONFIRMED` exists
in the schema but no `0.1` command can enter it.

Anything after an attempted broadcast that cannot be proven failed is not a new
execution opportunity. A resend uses only the exact persisted bytes and requires
fresh authorization plus direct-route preflight.

## Proof contract

Caller-supplied mappings cannot enter proof-bearing states. Receipt verifier
factories produce typed source success/failure and destination fulfillment
capabilities bound to the exact Plan. The store validates those capabilities
before an atomic transition.

This prevents accidental API bypass. It is not a same-UID tamper boundary:
SQLite is local crash-safe state, not a signed or tamper-evident ledger. Two
configured RPC endpoints are corroboration, not Byzantine independence.

## Release blockers

Do not publish a production-candidate release while any of these are true:

1. A bound execution can authorize a legacy source-aggregator route.
2. The trusted policy is root-run, runtime-owned, symlinked, group/world writable,
   or below a runtime-writable ancestor.
3. A copied policy/manifest digest can authorize altered material intent.
4. A legacy or display-only approval can reach signing or broadcast.
5. Under- or over-allowance can pass direct-route preflight.
6. One idempotency key can bind different plans or approvals.
7. Concurrent preparation can persist multiple signed transactions for one operation.
8. Crash recovery can create or sign a replacement transaction.
9. Read-only `resume` can send.
10. A send or resend can occur without fresh authorization and source preflight.
11. Detached import can alter any signer or EIP-1559 transaction field.
12. Plan mutation can survive Plan-ID verification.
13. Secret canaries appear in argv, output, artifacts, or diagnostics.
14. A proof-bearing state can be manufactured from a caller mapping.
15. Destination verification omits proxy, topic, order, signer, chain, receiver,
    token, amount, authority, taker, or external-call binding.
16. A clean built wheel cannot import and run the CLI.
17. Dependency/secret scans or independent security review retain a blocker.

## Release levels

- `0.x`: alpha production candidate; schemas may change; fixture/local proof only.
- `1.0`: stable schemas, independent review, and a bounded maintainer canary
  using the exact published wheel and supported direct route.
