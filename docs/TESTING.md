# Testing

## Commands

- Targeted: `bin/check targeted`
- Full: `bin/check full`
- Isolated wheel smoke: `bin/smoke dist/agent_bridge_guard-*.whl`
- Secret scan: `gitleaks detect --config gitleaks.toml --no-git --source .`

## What the gates prove

`bin/check targeted` runs Ruff, strict mypy, and unit tests through locked
dependencies. `bin/check full` adds branch coverage, wheel/sdist build,
dependency audit, and isolated wheel smoke. None proves live funds, external
custody behavior, solver availability, or Byzantine fault tolerance from two
RPC endpoints.

Regression coverage should exercise:

- direct reserve ERC-20 route authorization, exact gross input, and no guard-made
  approval transaction;
- policy path ownership/runtime non-writability and schema-v3 reviewable approval
  binding;
- authorization reload before reserve, prepare persistence, first send, and
  resend, including read-only resume never sending;
- fenced concurrent preparation, stale-claim failure resistance, and exact-byte
  recovery;
- verifier-produced source/destination proofs and canonical two-endpoint
  corroboration;
- signer canonicality, detached field/recovered-address binding, and no secret
  disclosure.

Use fixture transports and injected failure points. Do not add tests that touch
a live RPC, wallet, funded account, or provider. A maintainer live canary is a
separate controlled-release activity, not CI evidence.
