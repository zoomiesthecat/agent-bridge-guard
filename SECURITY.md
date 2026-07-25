# Security policy

Agent Bridge Guard moves funds. Treat every `0.x` build as an unaudited alpha
production candidate. Use bounded wallets, exact allowances, operator-protected
policy, and independently reviewed route manifests.

## Report privately

Use a [GitHub private security advisory](https://github.com/zoomiesthecat/agent-bridge-guard/security/advisories/new).
Do not open a public issue containing credentials, keystores, passwords, raw
keys, approval signatures, signed-but-unbroadcast transactions, private RPC
endpoints, or private operation artifacts.

Include the affected version/commit, minimal reproduction, impact, and a
redacted proof. Never attach real custody material.

## Supported versions

Security fixes target the latest `0.1.x` release. Older prerelease commits are
not supported. A supported version does not imply that a provider, route, RPC,
signer, or custody policy is safe for a particular amount.

## Trust boundary

- The protected policy must be owned outside the non-root runtime UID and must
  not be writable through any runtime-accessible ancestor.
- Local key/password mode `0600` protects against other OS users, not a malicious
  same-UID process.
- Use off-box operator approval plus detached/remote transaction signing, or a
  separate executor UID/service, when hostile-agent containment matters.
- Public receipts are redacted local evidence, not signed trustless attestations.
  The SQLite ledger is not tamper-evident and two RPC URLs may share an upstream.
- TWAK is readiness-only. Turnkey live transaction signing is disabled.

The automated suite contains no funded-wallet canary or live-chain fixture.
