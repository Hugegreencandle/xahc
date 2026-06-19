---
name: xahau-mcp-simulate
description: Predict what a Xahau transaction will DO before signing — keyless, no deploy. Uses the xahau-mcp server's simulate tools: simulate_transaction (pre-sign flight simulator — runs every hook an unsigned tx would trigger as real bytecode against live state: per-hook accept/rollback, decoded emits, state writes, scam score), execute_hook (run real hook bytecode in a local VM with no node), simulate_hook_trigger (which hooks fire, strong vs weak), what_if (replay a historical tx with overrides). Use when the user says "/xahau-mcp-simulate", "what will this tx do", "simulate this transaction before signing", "what hooks will this trigger", "run this hook without deploying", or "preview a tx's effects".
---

# xahau-mcp-simulate — see a Xahau tx's fate before signing (keyless)

xahau-mcp is the **simulate** stage of the toolchain (write → **simulate one tx** → prove all
inputs). It answers "what will this transaction actually do?" by running the **real hook bytecode**
against **live ledger state** — without signing, without deploying, without key custody. This is the
surface a wallet shows on its sign screen ("what will this do?") — the Xaman pre-sign panel use case.

## Requires the xahau-mcp server
These are **MCP tools**, so the `xahau-mcp` server must be connected (or run locally — see its
repo: `github.com/Hugegreencandle/xahau-mcp`; Docker + stdio/HTTP). The agent then calls the tools.

## Which tool
- **`simulate_transaction`** — the PRE-SIGN FLIGHT SIMULATOR. Give it an UNSIGNED tx; it runs the
  originator + stakeholder hook chains (canonical order) as real bytecode against live state and
  returns per-hook **accept/rollback**, decoded **emitted** transactions, simulated **state writes**,
  static engine preflights, and a scam score. The default "what will this do?" answer.
- **`execute_hook`** — run a hook's **real CreateCode WASM** in a local VM (no `xahaud` node) over a
  simulated tx + ledger state → actual accept/rollback, return code/string, state writes, emits, call
  trace. Use to exercise a hook you haven't deployed. (`resolveKeylets:true` pre-fetches the ledger
  objects + foreign state the hook reads, iteratively, then re-runs.)
- **`simulate_hook_trigger`** — static (no RPC, no bytecode) prediction of WHICH accounts' hooks a tx
  would invoke, **strong (can rollback) vs weak**. Cheap scoping before a full simulate.
- **`what_if`** — TIME MACHINE: fetch a real historical tx, apply your overrides, re-simulate at its
  original ledger. (Verified to reproduce a real reward claim's `GenesisMint` to the drop.)

## Keyless + honest fidelity (carry these caveats)
- **No key custody.** Builder tools never take a seed; simulation needs no signature. Anything that
  would be submitted comes back UNSIGNED — sign offline (xaman / xrpl-accountlib). Defaults to testnet.
- **Real bytecode, simulated environment.** The VM implements a large slice of the Hook API (XFL,
  slots, STObject subfields, state, util_*, keylets, foreign state…). What it CAN'T do faithfully is
  recorded, not faked: unsupported calls return the real `NOT_IMPLEMENTED`, are listed in
  `unsupportedCalls`, and mark the run **`degraded`**. `etxn_details` is a disclosed synthetic
  placeholder (in `syntheticCalls`) that can't change the verdict. Report `degraded`/`unsupportedCalls`
  honestly — don't present a degraded run as authoritative.
- **Not a consensus-faithful `xahaud`.** No fee/fuel metering beyond the guard budget; XFL math
  truncates (not round-half-up); value-level math verified only where tested. **Always confirm
  financial/resource hooks on testnet** before trusting a simulated verdict.

## Where it fits
- Before signing: `simulate_transaction` → show the user accept/rollback + emits + scam score.
- Before deploying a hook: `execute_hook` (or the `xahau-hook` skill's `xahc sim`) for a quick check;
  then `xahau-prove` to prove it for ALL inputs (simulate = one tx, prove = every input).
- Resources/prompts also exist on the server: `xahau://rules|hook-api|tx-types`, and the
  `audit_hook`/`simulate_hook`/`explain_hook` prompts.

## Notes
- simulate = ONE transaction's outcome; it is NOT a proof. For "can this EVER happen?" use
  `xahau-prove`/`xahau-audit`. State that distinction; never call a clean simulation "proven safe".
