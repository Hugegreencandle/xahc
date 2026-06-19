---
name: xahau-prove
description: Prove an Xahau Hook obeys a safety property for ALL inputs (or get a concrete counterexample), using the user's xahc-prover. Given a Hook (.wasm or .c) + a plain-English safety intent, map it to the right invariant(s), run the prover, and interpret the verdict HONESTLY. Use when the user says "/xahau-prove", "prove this hook", "is this hook safe", "can this hook be drained / replayed / over-spend", "check this hook for <property>", or asks to verify/audit a Xahau Hook's behavior.
---

# xahau-prove — prove a Xahau Hook safe (or find the counterexample)

xahc-prover is a Python+Z3 symbolic-execution engine that proves a Hook obeys an invariant for ALL
inputs, or returns a concrete counterexample. Third leg of the trifecta: **xahc (write) → xahau-mcp
(simulate one) → xahc-prover (prove all).**

## THE ONE RULE — soundness is the product
A false "PROVEN" (calling an unsafe hook safe) is catastrophic. So:
- **Never call a hook "safe" unqualified.** Always state *which invariant* under *which scope*.
- **INCONCLUSIVE ≠ safe.** Exit 3 means the prover could not decide (it fails closed) — report it as
  "could not prove", never as a pass.
- Quote the prover's own scope caveats (it prints them) — don't strip them.

## Exit codes
`0 PROVEN` · `1 N/A` (property not exercised — not a pass) · `2 COUNTEREXAMPLE` (a concrete failing
input — show it) · `3 INCONCLUSIVE` (fail-closed; not a pass).

## Sequence

1. **Get the Hook as `.wasm`.** If given C, build it first (see the `xahau-hook` skill, or:
   `export PATH="/opt/homebrew/opt/llvm/bin:$PATH"; CC=/opt/homebrew/opt/llvm/bin/clang \
   ~/Desktop/xahc/target/release/xahc build <f>.c -o <f>.wasm` — Apple clang lacks wasm32).

2. **Map the intent → invariant(s).** Pick from the 23 (run several if the intent spans more):
   - "can't overspend / per-tx cap" → `limit` (native) / `limit-iou` (IOU) / `guardrail` (cap+dst)
   - "can't create value / conserve funds" → `conservation` · "bounded emits / no double-spend" → `nospend`
   - "reserve-safe (won't dip below reserve)" → `reserve` · "emit count ≤ reserve" → `emission`
   - "no replay / state only moves forward" → `monotonic` (use `-- --field SLOTHEX:OFF:LEN` for a
     packed slot) · "stateful spend budget over a period" → `period-budget`
   - "cbak re-entry safe" → `reentrancy` · "no value inflation of an in-world resource" →
     `resource-conservation` (`--field`-targetable)
   - "only the owner can trigger" → `authz` · "foreign-state writes are authorized" → `foreign-authz`
   - "required param present" → `validate` · "param within bounds" → `validate-range`
   - "no uint64-overflow bypass of the limit" → `overflow`
   - "outcome can't hinge on grindable nonce" → `time-nonce`
   - "every failable state_set/emit return is checked" → `unchecked-return`
   - "boot blob == pinned hash" → `bootloader` · "commit root == hash(state)" → `commitment`
   - "a wallet's pre-sign PREVIEW matches execution" → `preview-faithfulness`
   (Full meanings: `~/Desktop/xahc-prover/CLAUDE.md`. Don't invent invariant names — list them with
   `xahc prove --help` or read the dispatch table.)

3. **Run it.** `export XAHC_PROVER_DIR=~/Desktop/xahc-prover` then
   `~/Desktop/xahc/target/release/xahc prove <hook>.wasm --invariant <name> [-- <extra args>]`
   (the `-- --field ...` tail forwards to the driver). Or directly:
   `cd ~/Desktop/xahc-prover && . .venv/bin/activate && python src/prove_<name>.py <hook>.wasm`.

4. **Interpret HONESTLY.** For PROVEN: state the invariant + the prover's scope line. For
   COUNTEREXAMPLE: show the concrete failing values the prover printed. For N/A: explain the property
   wasn't exercised (e.g. the hook doesn't read that param) — NOT a pass. For INCONCLUSIVE: say what
   the prover couldn't model (unsupported opcode / solver unknown / hit bound) — NOT a pass.

5. **Report.** "Under invariant `X` (scope: …): <verdict>." If multiple invariants run, give the set.
   Never summarize a mix as a blanket "safe".

## Notes
- New properties: prefer adding a driver in xahc-prover (driver + buggy-twin fixture + adversarial
  verify that no false-PROVEN) over hand-waving — see CLAUDE.md.
- A GUARD_VIOLATION on-chain shows as `tecHOOK_REJECTED`. The prover's `termination` invariant proves
  it can't happen for any input.
