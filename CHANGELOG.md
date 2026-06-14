# Changelog

All notable changes to xahc are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

## [1.8.1] - 2026-06-14

Post-release audit fix.

### Changed
- **`NO_EXIT_PATH` downgraded from `error` to `warn`.** A hook importing neither
  `accept` nor `rollback` falls through to a plain return — unusual and almost
  always a bug, but xahaud does **not** reject it as `temMALFORMED` (the VM models
  it as a distinct `RETURNED` outcome). Blocking `build`/`install-tx` on it could
  refuse an odd-but-deployable hook, so it now warns instead of gating. Message no
  longer overclaims "will be rejected." (Aligns with the analyzer's finding-not-block
  semantics and the "don't hard-block valid hooks" rule.)

## [1.8.0] - 2026-06-14

Semantic safety lints — `xahc lint` now catches runtime/correctness footguns, not
just structural (`temMALFORMED`-class) rejections. These mirror the wasm-tractable
rules in xahau-mcp's analyzer, so the author side and the verify side agree before
you ever reach simulation.

### Added
- **`NO_EXIT_PATH`** (error) — hook imports neither `accept` nor `rollback`; it
  cannot terminate a transaction decision (traps / rejected). Blocks `build` /
  `install-tx`. (~ xahau-mcp `HOOK-001-NO-EXIT`.)
- **`EMIT_WITHOUT_RESERVE`** (warn) — calls `emit` without importing `etxn_reserve`;
  every emit fails at runtime. The `XAHC_EMIT_*` macros reserve for you. (~ `HOOK-009`.)
- **`REENTRANCY_EMIT`** (warn) — `emit` + `hook_again` + a `cbak` export can form an
  unbounded emission / re-execution loop. (~ `HOOK-010`.)
- **`STATE_FOREIGN_WRITE`** (warn) — `state_foreign_set` modifies another account's
  state; confirm the HookGrant + bounds. (~ `HOOK-008` foreign.)
- Advisories (new **`info`** level): `EMIT_NO_CBAK`, `STATE_WRITE`, `FLOAT_USAGE`,
  `OVERSIZE_WASM`, `MEMORY_EXCESS`. (~ `HOOK-003/008/012/011/013`.)
- New `info` severity in the `--json` envelope and the human report (does not gate
  build/install — only errors do).
- 9 new lint unit tests (WAT-based); 22 tests total.

## [1.7.0] - 2026-06-14

Positional guard lint — `xahc lint` now matches xahaud's guard verifier exactly.

### Changed
- **The guard check is POSITIONAL, not presence-based.** xahaud requires `_g` to
  be the FIRST branch instruction in a loop (only const/local/arith may precede).
  lint now enforces exactly that:
  - `GUARD_NOT_FIRST` — a guard exists but a non-guard branch precedes it.
  - `UNGUARDED_LOOP` — a loop with no `_g`.
  Both are now **errors** (were warnings) — they cause `temMALFORMED` on-chain, so
  `xahc build` / `install-tx` block them. Built hooks are unaffected: the
  guard-reposition pass (v1.6.0) makes every built hook compliant.
- **Validated against Xahau testnet:** lint's verdict equals the ledger's
  `engine_result` across mispositioned / compliant / unguarded hooks (3/3).
- Moved `unguarded_loop.c` to `tests/fixtures/` + a CI negative test asserting
  `xahc build` fails on it.

## [1.6.1] - 2026-06-14

Post-audit hardening (5-reviewer audit of the money-touching + new-surface code).

### Fixed
- **Emit builders check host-fn returns.** `etxn_details` / `etxn_fee_base` /
  `float_sto` return a negative error code on failure; the builders now
  `rollback` on a negative instead of advancing the buffer pointer by a negative
  length (which would corrupt the emit / shift a negative). Native + IOU paths.
- **`clean` strips ALL custom sections** (not just name/producers/target_features)
  — also any `linking`/`reloc.*`/`.debug_*` — so no stray section reaches xahaud.
- **`install-tx` rejects an unknown numeric tx type** in `--on` (was silently
  ignored by the HookOn encoder, so the user thought it fired on that type).
- **`build` surfaces guard-reposition skips** — a loop guard with non-literal
  args is left in place and now warned, not silent.

### Known (documented, deferred)
- `xahc lint`'s guard check is **presence**, not **positional** — it can't catch a
  *mispositioned* guard the way xahaud does (built hooks are safe; the build pass
  fixes position). Positional lint is planned for v1.7.
- `check_stack` ignores `call_indirect` targets (underestimates depth).

## [1.6.0] - 2026-06-14

Guard-reposition pass — hooks build at `-O2` again, no `-Oz` dependency.

### Added / Changed
- **Guard-reposition pass** (`guardpass`): after compile, hoists each loop's
  guard — the developer's `const id; const maxiter; call _g; (drop)` block — to
  the loop head, satisfying xahaud's rule that `_g` be the **first branch
  instruction in a loop**. The optimizer's loop rotation moves the guard to the
  loop bottom; the pass moves it back. It repositions the *existing* guard and
  its literal bound — it never invents a `maxiter`. Loops with no `_g` at all are
  reported, not faked.
- **`build`: back to `-O2`** (from the v1.5.1 `-Oz` interim). `-O2` hooks now
  install; re-verified on Xahau testnet (guardrail installs, over-limit
  `tecHOOK_REJECTED`, under-limit `tesSUCCESS`).
- `build` prints the repositioned-guard count and warns on any unguarded loop.

## [1.5.1] - 2026-06-14

**Critical:** every prior xahc-built hook was rejected on-chain (`temMALFORMED`).
Found via the first real Xahau testnet deploy; the `agent_guardrail` hook now
installs and enforces a spending cap on-ledger (see [docs/TESTNET-PROOF.md](docs/TESTNET-PROOF.md)).

### Fixed — SetHook validator acceptance
- **`build`: `--gc-sections` + export only `hook`/`cbak`** (was `--export-all`).
  lld left dead functions (e.g. `__wasm_call_ctors`); xahaud validates every
  function and rejects an unguarded dead one.
- **`build`: `-Oz` instead of `-O2`.** `-O2` loop rotation moves the `_g` guard
  out of the position xahaud's guard verifier requires (our lint's presence check
  passed it; the chain's is position-sensitive). `-Oz` keeps guards in place and
  yields smaller hooks (lower SetHook fee). A wasm guard-injection pass is the
  robust long-term fix; `-Oz` is the validated interim.
- **`clean`: strip the `memory` export and compiler custom sections**
  (`name`/`producers`/`target_features`). xahaud rejects a hook that exports
  `memory`.
- **`sim`: re-add a `memory` export in-memory** before instantiating, since the
  deployable wasm no longer exports it (the on-disk artifact is untouched).
- CI: assert built hooks have the on-chain shape (no `memory` export / custom sections).

## [1.5.0] - 2026-06-13

Agentic payments — the layer-1 safety rail for autonomous agents on Xahau.

### Added
- **`agent_guardrail` archetype + `examples/agent_guardrail.c`** — a Hook that
  policies OUTGOING payments: per-tx spend cap (HookParameter `LIM`) and optional
  destination lock (`DST`). The protocol-enforced agent spending limit that
  x402/app-layer flows lack. Tested both sides of the cap (over-limit → rollback).
- **`xahc-guardrail` skill** (`skills/xahc-guardrail/SKILL.md`) — Claude-driven
  scaffold → build → test → `install-tx`, producing an UNSIGNED SetHook (no key
  custody) so an agent installs its own on-chain budget.
- **`hook_param` in the local sim**; test suites gain a `hook_params` table
  (ASCII name → hex value), so guardrail policy is unit-testable offline.
- **Docs:** `docs/AGENTIC.md` (why Hooks beat escrow/multisign for agent controls;
  how xahc / xahau-mcp / xrpl-mcp split the agent safety layer) and
  `docs/X402-XAHAU.md` (proposed `exact-xahau` x402 scheme with the guardrail Hook
  as the L1 spending authority at `/verify` and `/settle`).
- CI runs the guardrail test suite.

## [1.4.0] - 2026-06-13

`xahc sim`/`test` now enforce the guard budget — over-budget loops are caught locally.

### Added / Changed
- **`_g` guard-budget enforcement in the local sim.** A guard crossed more than its
  `maxiter` (`XAHC_GUARD(n)`) now produces a `GUARD_VIOLATION` outcome (exit 2 / test
  failure) instead of being silently accepted — the same loop bound the on-chain
  validator enforces. New `Outcome::GuardViolation`; `expect = "guardviolation"` is
  assertable in test suites. Adds `examples/over_budget.c` + a CI case.
- A local-sim trap (a host fn the sim doesn't model) now routes you to `xahc verify`
  for the full-fidelity xahau-mcp VM, instead of a bare trap message.

### Security
- Bumped **wasmtime 27 → 45**, clearing 15 RUSTSEC advisories (`cargo audit` now
  clean, exit 0). `sim.rs` migrated to wasmtime 45's forked `Error` type (kept the
  VM work in `run_inner`, converted to anyhow once at the boundary). VM behavior is
  unchanged — every example sim and test suite produces identical outcomes.

### Fixed
- `xahc verify` now forwards the SAME otxn fields the local sim synthesizes
  (`sfAmount` always, `sfAccount`/`sfDestination` as zero bytes) and treats a VM
  runtime-error `halted` (guard violation / trap) as a rollback — eliminating
  false `DISAGREE`s on hooks that read account/destination, zero-amount payments,
  and guard-violating hooks (incl. the bundled `over_budget.c`).

## [1.3.0] - 2026-06-13

The loop, wired — `xahc verify` runs the local sim AND the xahau-mcp VM and flags disagreement.

### Added
- **`xahc verify <wasm> [--tt --drops --remote]`** — differential gate: runs the
  built wasm through the fast local sim AND a hosted xahau-mcp `/execute` (the
  fidelity-locked VM), seeding **byte-identical inputs** to both, and flags any
  accept/rollback disagreement (nonzero exit). The local sim is the fast inner
  loop; the MCP VM is the authoritative gate; disagreement is itself a finding.
  Talks over HTTP (`XAHC_SIM_URL` / `--remote`) to an xahau-mcp `/execute` endpoint
  you supply — never a filesystem import of the private MCP, so any hosted shim works
  (vs the old bridge that needed a private-repo checkout).

## [1.2.0] - 2026-06-13

Machine-readable output — xahc can now be driven by CI, the web funnel, and xahau-mcp.

### Added
- **Global `--json` flag** on `build` / `lint` / `sim` / `test` / `clean`. Emits a
  stable result envelope on **stdout**; all human/diagnostic output goes to **stderr**,
  so `xahc build --json | jq` is clean. Exit codes are unchanged (lint error = 1,
  rollback = 2), so structured and exit-code consumers both work.
  - `BuildResult{wasm_path, wasm_hex, bytes, lint}` — `wasm_hex` removes the manual
    file→hex bridge when handing a build to xahau-mcp.
  - `LintResult{ok, error_count, findings:[{level, rule_id, msg}]}`.
  - `SimResult{outcome, return_code, emitted:[{bytes, hex}], state_keys}`.
  - `TestResult{wasm, passed, failed, cases:[{name, ok, detail}]}`.
- **Stable `rule_id`s on lint findings** (ILLEGAL_EXPORT, NO_HOOK_EXPORT, NO_G_IMPORT,
  UNGUARDED_LOOP, STACK_OVERFLOW, …) — a compatibility contract for machine consumers,
  independent of the human message wording.

## [1.1.0] - 2026-06-13

Safety hardening of `install-tx` (pre-launch audit).

### Changed
- **`install-tx --on` is now required** — no implicit fire-on-all-types default,
  which was a footgun (a hook firing on every transaction type, incl. SetHook).

### Added / Fixed
- `install-tx` **refuses a wasm that fails lint** (errors) and **surfaces lint
  warnings** (unguarded loop, stack budget) instead of packaging them silently —
  it's no longer an escape hatch around the safety checks.
- `install-tx` **validates the `--account` r-address** (base58 classic-address
  shape) before emitting.
- `install-tx` **caps HookParameter name/value lengths** (32 B / 256 B).

## [1.0.0] - 2026-06-13

First stable release. xahc is the authoring/compile companion to
[xahau-mcp](https://github.com/Hugegreencandle/xahau-mcp): write a C Hook safely,
compile it, and emit a ready-to-sign install transaction.

### Added
- **Self-contained binary** — the safe-header library is embedded and materialized
  at build time, so an installed `xahc` needs no repo checkout.
- **`xahc doctor`** — verifies clang + wasm-ld and compiles a hook end-to-end.
- **`xahc new <name>`** — scaffolds a buildable project (firewall / accept_all /
  emitter archetypes) with a test suite, justfile, and README.
- **`xahc install-tx`** — emits an UNSIGNED SetHook: CreateCode, HookOn
  (computed from Xahau's active-low mask, regression-tested against golden values),
  HookNamespace
  (`--namespace` or `--namespace-label` = sha256), HookParameters (`--param`),
  NetworkID, Flags.
- **`xahc test`** — declarative TOML test suites over the simulator (outcome +
  emit/state-count assertions), nonzero exit on failure.
- **`xahc sim`** — local wasmtime preflight (accept/rollback, emitted txns, state).
- **`xahc lint`** — export allowlist, Hook API import allowlist, per-loop `_g`
  guard presence, and a stack-budget overflow check.
- **`xahc build` / `clean`** — clang→wasm pipeline with a Rust hook-cleaner.
- **Safe headers** — `guard.h` (auto-numbered guards), `check.h` (checked
  returns), `otxn.h` (+ native-drops decode), `param.h`, `state.h`, `sfcodes.h`,
  and verified emit builders: native `XAHC_EMIT_PAYMENT` (codec-verified) and
  issued `XAHC_EMIT_PAYMENT_IOU` (VM-verified, 1.5 USD).

### Notes
- Pre-1.0 work shipped under 0.0.1 / 0.1.0 tags.
- Not audited. Always confirm financial hooks on testnet before mainnet.
