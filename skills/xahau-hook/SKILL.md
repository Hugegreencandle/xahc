---
name: xahau-hook
description: Author a Xahau Hook (C → WASM) end-to-end with the user's toolchain — scaffold, build, lint, simulate, and PROVE it. Use when the user says "/xahau-hook", "write a hook that …", "build/compile this hook", "scaffold a Xahau hook", or wants a safe, deploy-ready C Hook for Xahau. Pairs with xahau-prove (the proof step) and xahau-mcp (single-tx simulate).
---

# xahau-hook — write a safe, proven Xahau Hook

`xahc` ("Xahau Hooks, Checked") is the first leg of the trifecta: **xahc (write) → xahau-mcp
(simulate one) → xahc-prover (prove all).** It compiles C Hooks to clean, lint-passed, deploy-ready
`.wasm`. This skill takes a Hook from idea to proven.

## Toolchain + the wasm32 gotcha (read first)
- Binary: `~/Desktop/xahc/target/release/xahc` (build with `~/.cargo/bin/cargo build --release` if
  missing; ~8-10 min). `xahc doctor` checks the toolchain.
- **Apple clang CANNOT target wasm32.** Use brew LLVM:
  `export PATH="/opt/homebrew/opt/llvm/bin:$PATH"` and pass `CC=/opt/homebrew/opt/llvm/bin/clang`.
- Safe headers live in `~/Desktop/xahc/include/xahc/` (guard.h, check.h, otxn.h, param.h, state.h,
  emit/payment.h, sfcodes.h). Use the `XAHC_*` macros — they wrap the raw hookapi correctly:
  `XAHC_HOOK_ENTRY`, `XAHC_ACCEPT`, `XAHC_REQUIRE`, `XAHC_GUARD`, `XAHC_SBUF`, `XAHC_OTXN_ACCOUNT`,
  `XAHC_HOOK_PARAM_REQUIRE`, `XAHC_STATE_SET`/`XAHC_STATE_GET`, `XAHC_EMIT_PAYMENT`, `xahc_otxn_drops`.

## Sequence

1. **Clarify the spec in one line** — what the Hook enforces (the on-chain invariant), its
   HookParameters, and which transactions it polices. State the SAFETY property you'll prove (step 5).

2. **Scaffold / write the C.** `xahc new <name>` to scaffold, or write `<name>.c` including
   `"xahc/xahc.h"`. Patterns: read otxn fields (`otxn_type`, `XAHC_OTXN_ACCOUNT`, `xahc_otxn_drops`),
   read params (`XAHC_HOOK_PARAM_REQUIRE`), gate with `XAHC_REQUIRE`, persist with `XAHC_STATE_SET`,
   accept/rollback with `XAHC_ACCEPT`/`rollback`. Every loop needs a guard (`XAHC_GUARD(n)`). Model
   new hooks on `~/Desktop/xahc-prover/hooks/agent_guardrail.c`.

3. **Build → clean → lint.** `CC=/opt/homebrew/opt/llvm/bin/clang ~/Desktop/xahc/target/release/xahc
   build <name>.c -o <name>.wasm` (build runs clean + lint: export/import allowlist, guard presence,
   stack budget, semantic safety). Fix any `rule_id` findings — they're stable, real safety lints.

4. **Simulate one tx.** Local: `xahc sim <name>.wasm` (wasmtime). Against a sample settlement tx:
   xahau-mcp `execute_hook`/`simulate_transaction` (the `xahau-mcp-simulate` surface). Confirms the
   hook does what you intend on a concrete input.

5. **PROVE it for ALL inputs** — invoke the `xahau-prove` skill on `<name>.wasm` with the safety
   intent from step 1. A hook isn't done until the relevant invariant is PROVEN (or you understand
   why it's COUNTEREXAMPLE/INCONCLUSIVE). SOUNDNESS IS THE PRODUCT — never ship/claim-safe on a
   simulate alone.

6. **(Optional) install tx.** `xahc install-tx <name>.wasm` emits an unsigned SetHook; sign +
   submit per `~/Desktop/xahc-prover/CLAUDE.md` "Testnet validation" (NetworkID 21338, faucet
   xahau-test.net). Hooked-account Payments need a higher fee (else `telINSUF_FEE_P`); Xahau rippled
   speaks WS api_version 1.

## Notes
- Conventions: commit by name (never `git add -A` — hook-blocked); Conventional-commit style; end
  commit messages with the Co-Authored-By Claude line.
- When proposing a hook is "safe", always say which invariant under which scope (per xahau-prove).
- Reference for protocol Qs (host fns, sfcodes, return codes): `~/Desktop/xahc-prover/docs/
  XAHAU-DEV-REFERENCE.md` — cite it, don't guess.
