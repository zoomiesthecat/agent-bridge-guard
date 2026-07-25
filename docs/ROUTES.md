# Route manifests

## Supported route

Production execution supports only deBridge
`reserve_erc20_dln_native_out`. Legacy Kyber/native-in-swap route construction
is quarantined and must not appear in a trusted policy or executable plan.

The source wallet must hold the ERC-20 gross input and have an exact
gross-input allowance set for the reviewed DLN proxy. Both smaller and larger
allowances fail preflight. Agent Bridge Guard does not create, increase, or
replace ERC-20 approvals. Establishing or changing an allowance is a separate
manual custody action.

## What a manifest binds

A reviewed manifest is authorized by a protected policy and binds the direct
source reserve token, DLN proxy and implementation code hash, expected transfer
fee, source/destination chains, destination proxy and event topic, allowed
takers, exact limits, and route identifier. It is never fetched or inferred at
runtime.

The plan preserves the gross input, exact protocol-fee accounting, exact direct
calldata, bounded fixed native fee, gas cap, total-spend cap, and deterministic
order identity. Affiliate fees, referral data, permits, arbitrary hooks, and
external calls are rejected.

Before preparation and before each send/resend, the engine reloads policy and
manifest authorization and runs the direct-route two-endpoint preflight. The
preflight corroborates RPC responses; it does not make two RPC providers a
Byzantine quorum.

Keep the trusted policy outside the runtime-writable tree. A private route file
may be runtime-owned because authorization recomputes its canonical digest and
requires the protected policy's exact `(route_id, digest)` binding. For simpler
operations, install reviewed manifests read-only too. Every route update requires
operator review and a new protected-policy digest binding.
