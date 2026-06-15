# xahc — agent guide

Rust CLI that compiles C Hooks to clean, lint-passed, deploy-ready Xahau `.wasm`, and the
first leg of the trifecta: **xahc (write) → xahau-mcp (simulate one) → xahc-prover (prove all)**.
"Xahau Hooks, Checked."

## Reference docs (read before Xahau protocol questions — don't guess from training)
- `~/Desktop/xahc-prover/docs/XAHAU-DEV-REFERENCE.md` — host fns, return codes, sfcodes,
  guard/XFL/emit semantics, SetHook, TSH, amendments (live-scraped).
- `~/Desktop/xahc-prover/docs/XAHAU-RESOURCES.md` — repos/tools/libs/standards.
- Ground truth: `Xahau/xahaud` + `XRPLF/hook-macros` (hookapi.h). xahc's own `include/xahc/*.h`
  wrap these — keep them in sync with hookapi.h.

## Layout
- `crates/xahc-cli/src/` — the CLI. Subcommand → module: `build.rs`, `clean.rs`, `lint.rs`,
  `sim.rs`, `test.rs`, `installtx.rs`, `verify.rs`, `prove.rs`, `doctor.rs`, `scaffold.rs`,
  `guardpass.rs`. Dispatch + `--json` envelopes in `main.rs`.
- `include/xahc/` — the safe hook headers (guard.h, check.h, otxn.h, param.h, state.h,
  emit/payment.h, sfcodes.h) embedded into builds.
- `examples/`, `skills/`, `docs/`, `x402-xahau/` (a Node facilitator), `tests/`.

## Subcommands
`build` (clang→wasm → clean → lint) · `clean` (strip illegal exports) · `lint` (export/import
allowlist, guard presence, stack budget, semantic safety) · `sim` (local wasmtime run) · `test`
(TOML suite) · `install-tx` (unsigned SetHook) · `verify` (local sim vs a hosted xahau-mcp
`/execute`) · `prove` (→ xahc-prover; `--invariant limit|guardrail|termination|monotonic|nospend|conservation|limit-iou|authz|validate|overflow|foreign-authz|reserve|time-nonce|emission`) · `doctor` · `new`.

## Build / test
```sh
cargo build --release          # binary at target/release/xahc
cargo test                     # unit + integration
./target/release/xahc doctor   # checks clang/wasm-ld toolchain
```
- Building hooks needs a **wasm32-capable clang** — Apple clang lacks it. Use brew LLVM:
  `export PATH="/opt/homebrew/opt/llvm/bin:$PATH"` (`xahc doctor` reports the gap).
- `xahc prove` shells to xahc-prover; set `XAHC_PROVER_DIR` if it's not a sibling of this repo.

## Conventions
- `--json` output envelopes are a stable contract consumed by CI / xahau-mcp / the web funnel —
  don't change their shape without bumping intent.
- Lint findings carry stable `rule_id`s — keep them stable.
- Commits: stage BY NAME (never `git add -A` — hook-blocked); Conventional-commit style; end with
  the Co-Authored-By Claude line. This repo often has parallel WIP — commit only your files.
- A release rebuild is ~8–10 min; expect it.
- Caveman mode on in this session: terse chat, code/commits/docs normal.
