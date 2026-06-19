---
name: xahau-audit
description: Full safety audit of a Xahau Hook (or hook chain) end-to-end with the user's toolchain — lint, simulate, PROVE the relevant invariants, FUZZ the inconclusive ones, COMPOSE across a chain, and (optionally) register the proofs. Produces one honest verdict with stated residual. Use when the user says "/xahau-audit", "audit this hook", "is this hook safe to deploy", "review this hook for vulnerabilities", "check this hook chain", or wants a deploy-readiness safety report for a Xahau Hook.
---

# xahau-audit — full safety audit of a Xahau Hook

Orchestrates the whole toolchain into one honest verdict:
**lint → simulate → prove → fuzz → compose → register.** Pairs with `xahau-hook` (author),
`xahau-prove` (the proof leg), and `xahau-ref` (protocol facts — don't guess).

## THE ONE RULE — soundness is the product
A false "safe" is catastrophic. Never call a hook safe unqualified. Every claim is *which
invariant under which scope*. INCONCLUSIVE / N/A are **not** passes. Always state the residual
(what was NOT proven). Fuzz finding no counterexample is **not** a proof.

## Toolchain (read first)
- Binary: `~/Desktop/xahc/target/release/xahc` (build: `~/.cargo/bin/cargo build --release`).
- `export XAHC_PROVER_DIR=~/Desktop/xahc-prover` (prove/fuzz/registry need it).
- C→wasm needs brew LLVM (Apple clang lacks wasm32):
  `export PATH="/opt/homebrew/opt/llvm/bin:$PATH"; CC=/opt/homebrew/opt/llvm/bin/clang`.
- Protocol facts: cite `~/Desktop/xahc-prover/docs/XAHAU-DEV-REFERENCE.md` (use `xahau-ref`).

## Sequence

1. **Scope it.** Get the hook(s) as `.wasm` (build C first). One line: what each hook enforces,
   its HookParameters, the transactions it polices. List the SAFETY properties to check.

2. **Lint** (static, zero false-positive structural checks):
   `xahc lint <hook>.wasm` — illegal exports, host-import allowlist, guard presence, stack
   budget, semantic safety. Errors here are deploy-blockers; fix before proceeding.

3. **Simulate** (concrete sanity, no testnet): `xahc sim <hook>.wasm --tt 0 --drops <n>` or a
   declarative suite `xahc test <hook>.test.toml`. Confirms accept/rollback on representative txns.

4. **Prove** the mapped invariants (the core): map each safety property → invariant(s) and run
   `xahc prove <hook>.wasm --invariant <name> [-- --field ...]`. (Invariant map: see `xahau-prove`
   / `~/Desktop/xahc-prover/CLAUDE.md`.) Record each verdict: PROVEN (0) / N/A (1) /
   COUNTEREXAMPLE (2, show the input) / INCONCLUSIVE (3). Run all invariants the intent spans.

5. **Fuzz the gaps.** For every invariant that came back INCONCLUSIVE (and that fuzz supports —
   limit/overflow/authz/guardrail): `xahc fuzz <hook>.wasm --invariant <name> --runs 20000`. A
   counterexample turns INCONCLUSIVE → DISPROVEN (act on it). No counterexample raises confidence
   but is NOT a proof — say so, and heed the "accept path never hit" weak-fuzz warning.

6. **Compose** (only for a multi-hook chain on one account): write a chain TOML (ordered
   `[[hook]]` with wasm/namespace/invariants) and `xahc compose chain.toml`. Confirms per-hook
   proofs lift to the chain and flags state-namespace interference + emit-bound caveats. Heed any
   surfaced caveat (e.g. state_foreign_set).

7. **Register** (optional, only the PROVEN results): `xahc registry add <manifest> [--key K]`
   (mint via `xahc registry make-manifest <hook>.wasm --invariant <name> --out m.json`). Gives a
   signed, tamper-evident, HookHash-keyed record (see `docs/PROOF-REGISTRY.md`).

## Report (the deliverable)
A per-property table: `invariant → verdict (scope) → evidence`. Then a one-line bottom verdict
that NEVER blanket-summarizes a mix as "safe":
- e.g. "PROVEN: limit, authz, overflow (native, bounded). DISPROVEN: none. INCONCLUSIVE:
  emission (cbak dynamic re-entry unmodeled) — fuzzed 20k, no CEX, still unproven. Residual:
  <list>. Deploy-blocking lint: none."
Include any COUNTEREXAMPLE inputs verbatim. State the residual explicitly. If anything is
DISPROVEN or lint-error, the audit verdict is FAIL.

## Notes
- Don't invent invariant names — list them via the prover dispatch / `xahau-prove`.
- Stateful invariants (monotonic/period-budget/reentrancy) are prove-only (fuzz needs seeded
  state) — don't claim fuzz coverage for them.
- For deploy: pair with `xahc install-tx` (unsigned SetHook) and `xahc verify` (local-vs-MCP
  differential) — but the safety verdict is steps 4–6, not the deploy mechanics.
