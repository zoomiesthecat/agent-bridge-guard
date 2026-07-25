# Task queue

## Release gate

- [x] Independent security review returns no release blocker.
- [x] Independent architecture/recovery review returns no release blocker.
- [x] `AGENT_BRIDGE_GUARD_REQUIRE_AUDIT=1 bin/check full` passes.
- [ ] Public GitHub CI passes from the clean published commit.
- [ ] Bounded released-wheel canary after publication; required for `1.0`, not CI.

## Ready

- [ ] Decode and bind destination `SentOrderCancel` plus source
      `ClaimedOrderCancel`; expose cancellation only after full refund proof.
- [ ] Add Safe proposal adapter after a contract-wallet deBridge canary.
- [ ] Add AWS KMS signer after exact transaction-vector and parity tests.
- [ ] Add multi-provider routing only after the direct deBridge lifecycle is stable.

## Quarantined

- [ ] Native-input/Kyber source aggregation: keep rejected until every nested
      call/approval/fee/permit target is decoded, policy-bound, adversarially
      tested, and independently reviewed.
- [ ] TWAK live execution: keep disabled until it exposes exact raw transaction
      signing with replay-safe request identity and no secret in process argv.
- [ ] Turnkey live execution: keep disabled until the supported SDK is pinned,
      policy denial/idempotent activity retrieval are implemented, and exact
      signed-transaction vectors pass.

## Done

- [x] Direct reserve ERC-20 `createSaltedOrder` route with strict calldata semantics.
- [x] Exact gross manual allowance, dual-endpoint preflight, and no approval transaction.
- [x] Protected policy with canonical manifest authorization and confirmation policy.
- [x] Schema-v2 bound plans and schema-v3 reviewable operator approvals.
- [x] Local encrypted-keystore and generic detached EIP-1559 signing.
- [x] Token-fenced preparation, exact-byte persistence, and default no-send resume.
- [x] Typed verifier capabilities for source/destination proof-bearing transitions.
- [x] TWAK SHA-256/FD-pinned password-free readiness probe.
- [x] Turnkey capability boundary with live signing disabled.
