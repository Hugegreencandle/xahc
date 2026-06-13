# Changelog

All notable changes to xahc are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

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
