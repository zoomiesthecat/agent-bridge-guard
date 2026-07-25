# Agent Bridge Guard

Crash-safe cross-chain execution for autonomous agents and operators.

Agent Bridge Guard is not another bridge UI. It wraps one reviewed deBridge
route with controls a machine needs before it can move funds:

- operator-protected policy and a canonical route-manifest digest;
- immutable plans and schema-v3 approvals that sign reviewable material intent;
- exact signer, chain, nonce, recipient, token, amount, calldata, fee, and gas checks;
- exact pre-existing ERC-20 allowance verified through two RPC endpoints;
- atomic nonce reservation and token-fenced transaction preparation;
- exact signed bytes persisted before broadcast;
- read-only crash recovery by default and exact-byte resend only after fresh checks;
- canonical source receipt and exact destination `FulfilledOrder` proof;
- owner-only private artifacts and a redacted public receipt.

## Supported route

Version `0.1.x` authorizes one route shape:

```text
reserve ERC-20 on source
  -> pinned deBridge DLN proxy createSaltedOrder
  -> native asset on destination
```

The direct calldata is decoded and checked field by field. The source token,
gross base-unit amount, DLN proxy and implementation code hash, destination
chain and receiver, authorities, allowed taker, fixed fee, protocol fee,
metadata, gas, and deterministic order ID are all bound.

Affiliate fees, referral codes, permits, destination hooks, arbitrary calls,
automatic replacement transactions, and guard-created ERC-20 approvals are
rejected.

The older native-input/Kyber source-aggregator route is quarantined. It remains
parseable only for legacy evidence and tests; a protected-policy execution
cannot authorize it.

## Who it is for

The main users are agents, treasury bots, keepers, and automated runbooks. A
browser bridge is usually better for a person making one transfer. This tool is
useful when a process must prove its intent, survive a crash, avoid accidental
duplicate signing, and leave machine-readable evidence.

Keys do not need to live on the agent box. The detached flow exports one exact
unsigned EIP-1559 transaction, accepts canonical signed bytes from hardware,
manual, or remote custody, recovers the signer, and compares every field before
persistence.

## Security status

`0.1.x` is an alpha production candidate, not an audited stable release.
Use a bounded wallet and an independently reviewed manifest.

| Custody mode | Key on agent host | Status |
| --- | --- | --- |
| Encrypted Web3 keystore | Yes | Enabled; bounded hot-wallet mode |
| Detached hardware/manual/remote signer | No | Enabled; recommended separation |
| Turnkey | No EVM key; API stamper may be on host | Alpha adapter; signing disabled |
| Trust Wallet Agent SDK (TWAK) | TWAK-managed | FD-pinned readiness probe only |

An encrypted key and password owned by the same Unix UID protect against other
users and accidental disclosure. They do not contain a malicious same-UID
agent. Use a separate executor UID/service or a policy-enforcing remote signer
when hostile-agent separation matters.

## Install from source

```bash
git clone https://github.com/zoomiesthecat/agent-bridge-guard.git
cd agent-bridge-guard
uv sync --locked --all-extras
source .venv/bin/activate
agent-bridge-guard --help
```

The commands below assume that virtual environment remains active. Automated
checks never contact a provider, RPC, wallet, or funded account.

## Bootstrap private artifacts and protected policy

The mutable runtime configuration, request, route manifest, and artifacts are
owner-only. The trusted policy is different: it must be owned by an operator UID
other than the non-root runtime UID and live below ancestors the runtime cannot
write.

```bash
install -d -m 0700 /absolute/private
install -m 0600 examples/config.toml.example /absolute/private/config.toml
install -m 0600 examples/plan.request.example.json /absolute/private/request.json
install -m 0600 examples/route.manifest.example.json /absolute/private/route.json
install -d -m 0700 /absolute/private/artifacts
```

Replace every placeholder. The request `amount_wei` is the reserve token's gross
base-unit amount despite the historical field name. Keep its expiry inside the
manifest's short lifetime.

Get the canonical route digest:

```bash
agent-bridge-guard route-digest \
  --route /absolute/private/route.json
```

Put that digest, the off-box approval issuer, and chain confirmation policy into
`examples/trusted-policy.example.json`, then install the resulting policy with
operator/root ownership. For example:

```bash
sudo install -d -o root -g root -m 0755 /etc/agent-bridge-guard
sudo install -o root -g root -m 0644 \
  /absolute/operator/trusted-policy.json \
  /etc/agent-bridge-guard/trusted-policy.json
```

The runtime itself must not run as root. Confirm the policy/manifest binding:

```bash
agent-bridge-guard policy-check \
  --policy /etc/agent-bridge-guard/trusted-policy.json \
  --route /absolute/private/route.json
```

The route file may be runtime-readable and owner-only; its contents are trusted
only when its canonical digest matches the operator-protected policy.

## Set the exact allowance

Before planning, use the wallet or custody system of your choice to set:

```text
allowance(execution wallet, pinned source DLN proxy) == gross source amount
```

The guard never constructs, signs, or sends `approve`. Both insufficient and
larger standing allowances fail preflight. The balance, allowance, fixed fee,
transfer fee, proxy implementation, exact call simulation, gas, nonce, and
native fee balance must agree across both configured source RPC endpoints.

## Plan

```bash
agent-bridge-guard plan \
  --config /absolute/private/config.toml \
  --policy /etc/agent-bridge-guard/trusted-policy.json \
  --request /absolute/private/request.json \
  --route /absolute/private/route.json \
  --artifacts /absolute/private/artifacts \
  --name plan.json
```

Planning requests a fresh direct deBridge transaction, rejects alternate source
aggregators, performs the two-endpoint preflight, and writes a schema-v2 plan
containing the policy identity and complete canonical manifest snapshot.

## Obtain an off-box operator approval

```bash
ABG_APPROVAL_EXPIRES_AT="$(date -u -d '+20 seconds' +%Y-%m-%dT%H:%M:%SZ)"

agent-bridge-guard approval-request \
  --policy /etc/agent-bridge-guard/trusted-policy.json \
  --plan /absolute/private/artifacts/plan.json \
  --artifacts /absolute/private/artifacts \
  --name approval-request.json \
  --authorization-id ticket-123 \
  --actor operator-1 \
  --expires-at "$ABG_APPROVAL_EXPIRES_AT"
```

Review the schema-v3 `intent` off-box. EIP-191 sign the exact
`eip191_message_hex` bytes and return only the 65-byte `0x` signature in an
owner-only file.

```bash
agent-bridge-guard approve \
  --policy /etc/agent-bridge-guard/trusted-policy.json \
  --plan /absolute/private/artifacts/plan.json \
  --request /absolute/private/artifacts/approval-request.json \
  --signature-file /absolute/private/operator-signature.txt \
  --artifacts /absolute/private/artifacts \
  --name approval.json
```

The issuer is recovered from the signature and checked against the protected
policy. There is no caller-supplied `--issuer`.

## Execute with a local encrypted keystore

The keystore and password files must be absolute, owner-owned regular
non-symlink files with mode `0600`.

```bash
agent-bridge-guard execute \
  --config /absolute/private/config.toml \
  --policy /etc/agent-bridge-guard/trusted-policy.json \
  --plan /absolute/private/artifacts/plan.json \
  --approval /absolute/private/artifacts/approval.json \
  --keystore /absolute/private/signer.json \
  --password-file /absolute/private/signer.password \
  --idempotency-key ticket-123-attempt-1 \
  --go
```

Authorization and direct-route preflight run again immediately before signing
and before the first send.

## Execute with an external signer

```bash
agent-bridge-guard export-detached \
  --policy /etc/agent-bridge-guard/trusted-policy.json \
  --plan /absolute/private/artifacts/plan.json \
  --approval /absolute/private/artifacts/approval.json \
  --artifacts /absolute/private/artifacts
```

Sign the exported transaction with the expected wallet. Save only the canonical
raw type-2 transaction in an owner-only file:

```bash
chmod 0600 /absolute/private/signed-transaction.txt

agent-bridge-guard prepare-external \
  --config /absolute/private/config.toml \
  --policy /etc/agent-bridge-guard/trusted-policy.json \
  --plan /absolute/private/artifacts/plan.json \
  --approval /absolute/private/artifacts/approval.json \
  --signed-file /absolute/private/signed-transaction.txt \
  --idempotency-key ticket-123-attempt-1

agent-bridge-guard resume \
  --config /absolute/private/config.toml \
  --policy /etc/agent-bridge-guard/trusted-policy.json \
  --operation OPERATION_ID \
  --go
```

Detached import rejects noncanonical parity/high-s signatures, nonempty access
lists, a different signer, or any altered transaction field.

## Reconcile and prove

`resume` is read-only unless `--go` is present:

```bash
agent-bridge-guard resume \
  --config /absolute/private/config.toml \
  --policy /etc/agent-bridge-guard/trusted-policy.json \
  --operation OPERATION_ID

agent-bridge-guard refresh-source \
  --config /absolute/private/config.toml \
  --policy /etc/agent-bridge-guard/trusted-policy.json \
  --operation OPERATION_ID

agent-bridge-guard verify-destination \
  --config /absolute/private/config.toml \
  --policy /etc/agent-bridge-guard/trusted-policy.json \
  --operation OPERATION_ID
```

Tracking data only discovers a candidate destination transaction. Verification
requires canonical finality and exactly one fully matching `FulfilledOrder`
event.

```bash
agent-bridge-guard status \
  --config /absolute/private/config.toml \
  --operation OPERATION_ID

agent-bridge-guard receipt \
  --config /absolute/private/config.toml \
  --operation OPERATION_ID \
  --artifacts /absolute/private/artifacts
```

Public receipts are redacted, locally corroborated evidence. They are not
trustless attestations: two endpoints may share an upstream, and the local
SQLite ledger is not tamper-evident.

Important stop states are `SUBMISSION_UNKNOWN`, `NEEDS_RECONCILIATION`,
`TRACKING_PENDING`, and `SOURCE_FAILED`. They are not permission to create a
replacement operation.

## Optional custody adapters

- TWAK: library-only, SHA-256/FD-pinned `wallet status --json`; no bridge signing.
- Turnkey: alpha capability boundary; live signing is deliberately disabled.
- Any other wallet: use the enabled detached flow when it can return the exact
  canonical EIP-1559 bytes for the exported transaction.

## Verification

```bash
bin/check targeted
AGENT_BRIDGE_GUARD_REQUIRE_AUDIT=1 bin/check full
```

The full gate adds branch coverage, package build, locked dependency audit, and
clean-wheel smoke. A `1.0` release additionally requires stable schemas,
independent review, and a bounded canary using the exact published wheel.

See the [product contract](docs/PRODUCT.md), [system design](docs/SYSTEM.md),
[threat model](docs/THREAT_MODEL.md), [custody integrations](docs/CUSTODY.md),
[route manifests](docs/ROUTES.md), [testing contract](docs/TESTING.md), and
[security policy](SECURITY.md).
