# xahc — Xahau Hooks, Checked

The **authoring + compile** companion for **C Hooks** on the
[Xahau Network](https://xahau.network/docs/hooks/): write safely, build, clean,
and hand off a correct `.wasm` for deep analysis.

Hooks are layer-1 WASM smart contracts that fire before/after every transaction on
an account. The stock toolchain (`XRPLF/hook-macros`) is raw C preprocessor macros —
powerful, but every guarantee lives in the developer's head. `xahc` moves those
guarantees into the type system, the compiler, and the build step.

## Where xahc fits — it pairs with [xahau-mcp](https://github.com/Hugegreencandle/xahau-mcp)

The two tools are halves of one loop. xahau-mcp is **read-only**: it analyzes,
simulates (real WASM in a local VM, 78-fn Hook API, fidelity-locked to chain) and
audits hooks that *already exist as WASM*. It does **not** compile C, strip WASM,
or give you a safe write-time library. xahc does exactly that:

```
  AUTHOR + BUILD                 ANALYZE + SIMULATE + VERIFY
  ── xahc ──                     ── xahau-mcp ──
  safe headers ─► xahc build ─►  .wasm ─► execute_hook / analyze_hook / inspect_emitted_tx
       ▲                                              │
       └───────────────  findings feed back  ─────────┘
```

Write & compile with xahc → analyze & simulate with xahau-mcp. For deep static
analysis and VM execution, **use xahau-mcp** — xahc's own `lint`/`sim` are
intentionally thin local preflights, not a competing analysis engine.

> **Emit builders are codec-verified.** `emit/payment.h` output is round-tripped
> through xahau-mcp's chain-validated binary codec — a 1 XAH payment decodes to
> exactly `Amount: "1000000"`, valid `Account`/`Destination` r-addresses, offline.
> See [`scripts/verify-emit.mjs`](scripts/verify-emit.mjs).

## Agentic payments

AI agents are starting to settle value autonomously. xahc builds the **layer-1
safety rail**: a Hook that caps an agent's per-tx spend and locks its
destinations, enforced by the ledger — the control x402/app-layer flows lack.
`xahc new x --archetype agent_guardrail`, or use the
[`xahc-guardrail` skill](skills/xahc-guardrail/SKILL.md). See
[docs/AGENTIC.md](docs/AGENTIC.md) and [docs/X402-XAHAU.md](docs/X402-XAHAU.md).

## What it removes (real footguns, from the stock macros)

| Footgun | Stock | xahc |
|---|---|---|
| Manual guard numbering (`GUARDM(max, n)`) | hand-assign unique `n` per site → wrong = rejected | `XAHC_GUARD(max)` auto-numbers via `__COUNTER__` |
| Hand-computed emit buffer sizes | `PREPARE_PAYMENT_SIMPLE_SIZE 248` | named size + `_Static_assert` |
| Canonical field ordering | misorder `ENCODE_*` → malformed txn | fixed inside typed builder |
| Unchecked return codes | negative return silently ignored | `XAHC_TRY()` auto-rollback |
| Forgot `hook-cleaner` | stray exports → on-chain reject | `xahc build` cleans + verifies |
| Unknown host import | discovered only on deploy | `xahc lint` import allowlist |

## Layout

```
include/xahc/      Layer 0 — header-only safe C lib (guard, check, otxn, param, state, emit, sfcodes)
crates/xahc-cli/   Layer 1 — Rust CLI (headers embedded): build · clean · lint · sim · test · install-tx · doctor · new
scripts/           verify-emit.mjs · verify-emit-vm.mjs — codec/VM round-trips
examples/          *.c hooks + *.test.toml suites
```

The CLI's job is **build + clean** (the part nothing else does). `lint` and `sim`
are convenience preflights for fast local feedback; for authoritative analysis and
VM execution, pipe the `.wasm` to [xahau-mcp](https://github.com/Hugegreencandle/xahau-mcp).

## Install

Download a binary from [Releases](https://github.com/Hugegreencandle/xahc/releases)
(macOS arm64 / Linux x86_64) and drop it on your PATH:

```sh
tar -xzf xahc-<platform>.tar.gz && sudo mv xahc /usr/local/bin/
```

or build from source: `cargo build --release` (binary at `target/release/xahc`).

The headers are **embedded in the binary** — no repo checkout needed. Compiling
hooks also needs a wasm-capable LLVM:

```sh
brew install llvm lld      # macOS  (add their bin dirs to PATH)
apt install clang lld      # Debian/Ubuntu
xahc doctor                # verify the toolchain
```

## Quick start

```sh
xahc doctor                          # check clang/wasm-ld
xahc new myhook                      # scaffold a project (firewall archetype)
cd myhook
xahc build myhook.c -o myhook.wasm   # compile -> clean -> lint
xahc test myhook.test.toml           # run the assertions
xahc install-tx myhook.wasm --account <rYourAccount> --on Payment   # unsigned SetHook
```

## Commands

| Command | Does |
|---|---|
| `doctor` | Verify clang + wasm-ld; compile a hook end-to-end |
| `new <name> [--archetype]` | Scaffold a buildable project (firewall / accept_all / emitter / agent_guardrail) |
| `build <in.c> -o <out.wasm>` | clang→wasm → clean → lint |
| `clean <wasm>` | Strip stray exports (Rust hook-cleaner) |
| `lint <wasm>` | Exports + Hook-API imports + per-loop guards + stack budget + semantic safety (exit path, emit/reserve, foreign state, …) |
| `sim <wasm> --tt --drops` | Local wasmtime run → accept/rollback, emits, state |
| `test <suite.toml>` | Declarative asserted test suite over sim |
| `install-tx <wasm> --account r…` | Emit an UNSIGNED SetHook (HookOn/namespace/params) |
| `verify <wasm> [--tt --drops]` | Differential check: local sim vs an xahau-mcp `/execute` VM **you point it at** (`--remote`/`XAHC_SIM_URL`) — flags disagreement |

Add `--json` to `build`/`lint`/`sim`/`test`/`clean` for a stable result envelope on
stdout (diagnostics stay on stderr) — pipeable into CI, the web funnel, or xahau-mcp:
`xahc build hook.c --json | jq .wasm_hex`. Lint findings carry stable `rule_id`s.

Beyond the structural checks (which catch `temMALFORMED`-class on-chain rejections),
lint also runs **semantic safety** rules — runtime/correctness footguns that deploy
fine but misbehave: `NO_EXIT_PATH` (no `accept`/`rollback`), `EMIT_WITHOUT_RESERVE`,
`REENTRANCY_EMIT`, `STATE_FOREIGN_WRITE` (all `warn`), plus advisories (`info`) for `emit`-without-`cbak`,
XFL use, oversize wasm, and excess memory. This rule set **overlaps / is informed by**
xahau-mcp's analyzer — but it is **not** a 1:1 mirror: some rules differ in id and/or
severity between the two repos (e.g. xahc's `NO_EXIT_PATH` is a `warn`; the MCP's
`HOOK-001` is CRITICAL). Treat the crosswalk as informative, not a parity guarantee.

Write a hook:

```c
#include "xahc/xahc.h"

int64_t hook(uint32_t reserved) {
    XAHC_HOOK_ENTRY();                 // required: declares the guard import

    if (otxn_type() != XAHC_ttPAYMENT)
        XAHC_ACCEPT("not a payment");

    uint8_t amt[8];
    XAHC_REQUIRE(otxn_field(XAHC_SBUF(amt), sfAmount) == 8, "amount read");
    // ...
    XAHC_ACCEPT("ok");
    return 0;
}
```

## Roadmap

Scope is deliberately the **authoring/compile half**. Deep analysis lives in
xahau-mcp; xahc does not chase it.

- **M0** ✅ scaffold: build/clean/lint pipeline, safe headers
- **M1** ✅ guard auto-numbering (`__COUNTER__`) + checked returns (`XAHC_TRY`/`REQUIRE`)
- **M2** ✅ lint preflight: export + import allowlists (synced to `extern.h`), `_g` presence
- **M3** typed emit builders — **native Payment ✅ codec-verified**, **IOU/issued ✅
  VM-verified** (1.5 USD round-trips through xahau-mcp's VM as `{value:"1.5",currency:"USD",...}`)
- **sim** ✅ thin wasmtime preflight (accept/rollback + emit/state); not a substitute
  for xahau-mcp's `execute_hook`
- **test** ✅ `xahc test x.toml` — declarative, asserted suites over sim (outcome +
  emit/state-count assertions), nonzero exit on failure, CI-wired
- **install-tx** ✅ `xahc install-tx x.wasm --account r... --on Payment,Invoke` — emits
  an UNSIGNED SetHook. HookOn (the inverted active-low mask) is computed from the
  documented Xahau encoding and **regression-tested against golden values** (unit tests +
  CI). Refuses a wasm that fails lint; validates the r-address; `--on` is required
- **lint: stack budget** ✅ reads each function's frame size, walks the call graph, warns
  if the deepest chain exceeds the available stack (hooks have no heap) — catches the
  "big array on the stack" overflow before deploy
- **emit-verify** ✅ two paths: offline codec round-trip (`scripts/verify-emit.mjs`, native)
  and VM round-trip (`scripts/verify-emit-vm.mjs`, needs a xahau-mcp checkout — for XFL/IOU)
- **next** — more typed `otxn`/`state` accessors; richer scaffolds; publish to a
  registry. Loop-guard *dominance* and full VM fidelity are **xahau-mcp's** lane —
  not duplicated here.

### Testing

Define cases in TOML and assert outcomes — TDD for hooks, CI-friendly:

```toml
# firewall.test.toml
build = "firewall.c"          # compile first (or wasm = "x.wasm")

[[case]]
name = "below 10 XAH rejects"
tt = 0
drops = 5000000
expect = "rollback"

[[case]]
name = "above floor accepts"
tt = 0
drops = 20000000
expect = "accept"
emits = 0                      # optional: assert emitted-txn count
# fields = { "2.14" = "0000000A" }   # optional: arbitrary otxn fields (type.field or sfName)
```

```sh
$ xahc test firewall.test.toml
  ✓ below 10 XAH rejects      ROLLBACK code=24
  ✓ above floor accepts       ACCEPT code=25 emits=0
4 passed, 0 failed
```

### Deploying a hook

`install-tx` turns a built `.wasm` into a ready-to-sign **SetHook** transaction —
including the correct `HookOn` bitmap, which is notoriously easy to get wrong:

```sh
xahc install-tx firewall.wasm \
  --account rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh \
  --on Payment,Invoke         # required — the tx types the hook fires on
# -> unsigned SetHook JSON (CreateCode, HookOn, HookNamespace, NetworkID)
```

Output is **unsigned** — sign offline (xaman / `xrpl-accountlib`); set `Fee`/`Sequence`
at signing. `HookOn` is regression-tested against golden values (unit tests + CI). For a
pre-flight security audit of the hook before you install it, run the wasm through
xahau-mcp's `analyze_hook`.

### Emit verification

Two complementary checks that xahc's hand-built transaction bytes are correct:

```sh
# native XAH — pure codec round-trip, no checkout needed
xahc sim emit_payment.wasm --tt 0 --drops 50000000   # prints emit[0] hex
node scripts/verify-emit.mjs <hex>                     # -> Amount "1000000" (1 XAH)

# issued / IOU — needs the float host fns, so run through xahau-mcp's VM
XAHAU_MCP=/path/to/xahau-mcp node scripts/verify-emit-vm.mjs emit_iou.wasm Payment
#   -> Amount {"value":"1.5","currency":"USD","issuer":"r..."}
```

### Simulator

```sh
xahc sim firewall.wasm --tt 0 --drops 5000000    # -> ROLLBACK (below 10 XAH floor)
xahc sim firewall.wasm --tt 0 --drops 20000000   # -> ACCEPT
xahc sim firewall.wasm --tt 99                     # -> ACCEPT (not a payment)
```

Rollback/accept codes are the source line numbers (from `__LINE__`), so a
failing assertion points straight at the line that fired.

## Status

**v1.4.0.** Self-contained binary (embedded headers), clean clippy + unit tests,
green CI. Both emit builders are verified: **native XAH** round-trips through
xahau-mcp's chain-validated codec to exactly `Amount: "1000000"` (1 XAH);
**issued/IOU** executes in xahau-mcp's VM (real XFL) and emits
`{value:"1.5",currency:"USD",...}` — non-degraded. `install-tx`'s HookOn is
regression-tested against golden values. Not audited; always confirm financial
hooks on testnet before mainnet. See [CHANGELOG](CHANGELOG.md).

## License

MIT
