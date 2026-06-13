# Changelog

All notable changes to xahc are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

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
  (verified byte-for-byte against xahau-mcp's encoder), HookNamespace
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
