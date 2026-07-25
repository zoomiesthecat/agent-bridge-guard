<!-- Summary: repository-specific conventions that are not already mechanically enforced. Prefer linters and formatters for enforceable rules. -->

# Coding Conventions

- Follow existing local patterns before adding abstractions.
- Prefer deletion and reuse over new layers.
- Validate at system boundaries; do not scatter defensive checks internally.
- Add dependencies only with an explicit need and review.
- Keep this file limited to rules that materially change implementation decisions.
- Domain amounts are integer base units. Never use binary floating point.
- Persist state before external side effects. Ambiguity stops autonomous retry.
- Provider, signer, broadcaster, RPC, and store boundaries use typed protocols.
- Private artifacts default to `0600`; their parent roots default to `0700`.
- JSON output uses stable `code`, `state`, `data`, and `error` fields.
- Public examples use aliases and `.example` names only. Never add a usable RPC URL,
  wallet address, API credential, key material, or a funded transaction artifact.
- `bin/check full` is the release gate: it must stay deterministic and must not contact
  chains, quote APIs, custody systems, or move funds.
