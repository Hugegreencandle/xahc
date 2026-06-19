---
name: evernode-dapp
description: Scaffold and reason about an Evernode dApp — a HotPocket smart-contract instance hosted on Evernode and settled on Xahau via Hooks. Covers the HotPocket contract model (consensus, NPL, WebSocket clients, persisted state), the SDKs (hpdevkit/evdevkit/HotPocket SDK), host leasing via Sashimono, and where a Xahau Hook fits as the on-ledger settlement/governance layer. Use when the user says "/evernode-dapp", "build an Evernode app", "scaffold a HotPocket contract", "host a dApp on Evernode", or asks how Evernode/HotPocket relates to Xahau Hooks.
---

# evernode-dapp — build a HotPocket dApp on Evernode

Evernode is a decentralized hosting marketplace; **HotPocket** is the smart-contract/consensus
engine that runs dApp instances on leased hosts, settled on **Xahau via Hooks**. This is a
DIFFERENT layer from a Hook: a Hook is on-ledger transaction logic; a HotPocket contract is an
off-ledger consensus app that *uses* Xahau (and Hooks) for payments, leasing, and governance.

## Know the layers (don't conflate)
- **Hook** = code that runs inside `xahaud` on a transaction (deterministic, tiny, proven with the
  xahc trifecta). On-ledger.
- **HotPocket dApp** = a containerized app replicated across Evernode hosts under consensus; clients
  connect over WebSocket; nodes coordinate via NPL (Node Party Line); state persisted under
  consensus. Off-ledger, leased compute.
- **Sashimono** = host-side software that registers a host, leases compute, heartbeats to Xahau.
- The Xahau **Hook** is the settlement/governance seam: leasing payments, reputation/governance.

## Sources (cite, don't guess)
- Evernode docs: https://docs.evernode.org (HotPocket model, SDKs, host setup)
- Reference §16: `~/Desktop/xahc-prover/docs/XAHAU-DEV-REFERENCE.md` (grep "Evernode")
- SDKs: `hpdevkit` (local dev cluster), `evdevkit` (deploy to Evernode), HotPocket SDK, All-in-One.
- For the on-ledger settlement Hook: use `xahau-hook` (write) + `xahau-audit` (prove it safe).

## Sequence
1. **Decide what belongs where.** Consensus/compute/state/real-time client IO → HotPocket contract.
   Value settlement, leasing payment rules, governance/authority → a Xahau Hook. Be explicit about
   the split; it's the most common design mistake.
2. **Confirm the current SDK/flow from docs.evernode.org** before scaffolding — the SDK surface and
   testnet (Evernode testnet runs on the XRPL Hooks v3 testnet) change; don't rely on memory. Pull
   the live quickstart.
3. **Scaffold the contract** with `hpdevkit` (local multi-node cluster for dev), implement the
   contract entry (handle client inputs, NPL messages, persist state under consensus). Keep
   anything that must be DETERMINISTIC across nodes free of wall-clock/RNG/unseeded entropy/
   host-specific IO/locale — the same determinism discipline Hooks require (the prover's
   banned-entropy rules: `~/Desktop/xahc-prover/CLAUDE.md` + the canonicalizer spec).
4. **Wire the Xahau settlement layer.** If the dApp takes payments / leases / governs on-ledger,
   author that Hook with `xahau-hook` and PROVE it with `xahau-audit` (e.g. payment limits,
   authz, conservation). The dApp trusts the proven Hook for its money rules.
5. **Deploy** to Evernode with `evdevkit` (acquire a lease via Sashimono, push the instance). Verify
   the live instance + the on-ledger Hook separately.

## Notes
- The xahc trifecta proves the HOOK, not the HotPocket app. For the app's determinism, apply the
  same no-entropy rules but verify by differential replay across nodes (HotPocket's own consensus),
  not by xahc-prover (which targets WASM hooks).
- This skill is guidance + scaffolding pointers; confirm exact SDK commands against the live docs.
- Relationship to EverArcade-style worlds: a persistent-world runtime is a HotPocket dApp whose
  state-commitment/settlement can be the provable Hook seam — the determinism + canonicalization
  story is the same one the prover formalizes.
