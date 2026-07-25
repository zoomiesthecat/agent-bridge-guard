# System

## Purpose

Agent Bridge Guard durably authorizes, prepares, broadcasts, reconciles, and
proves one supported direct deBridge reserve operation. It does not provide
liquidity, custody infrastructure, ERC-20 allowance management, or a generic
route executor.

## Execution boundary

The executable route is `reserve_erc20_dln_native_out`. The operator manually
sets the exact required ERC-20 allowance beforehand; the guard validates gross
input and never emits an approval transaction. Legacy Kyber/native-swap routes
are quarantined from production authorization.

An operator/root-owned trusted policy authorizes reviewed manifest digests and
approval issuers. The runtime cannot write it: its path is absolute,
non-symlinked, checked across descriptor open, owned by another UID, and rejects
runtime-writable ancestors. A route file may be runtime-owned; it has no
authority unless its canonical digest is present in the protected policy.
Schema-v3 reviewable approvals bind exact plan intent. Authorization reloads and
revalidates at reservation, before local signing or detached persistence, before
first send, and before a resend.

SQLite stores idempotency, nonce reservation, persisted approval where eligible,
preparation claims, exact signed bytes, and lifecycle events. Preparation uses
a token-fenced claim with a kind/fingerprint, phase, and lease. SQLite is
durable private state, not tamper-evident audit storage.

## Finality and evidence

Source and destination transitions accept typed proof capabilities created by
the receipt verifier, never caller-supplied evidence mappings. Two RPC endpoints
corroborate simulation, receipt, nonce, and canonical-block observations. They
do not provide Byzantine fault tolerance or protect against a shared upstream.

## Commands

```bash
uv run --locked --all-extras agent-bridge-guard --help
uv run --locked --all-extras python -m build --no-isolation
bin/smoke dist/agent_bridge_guard-*.whl
```

The smoke lane builds and imports an isolated wheel without signing,
broadcasting, or contacting a provider. Do not delete or roll back an in-flight
operation database; use read-only status or resume the exact operation.
