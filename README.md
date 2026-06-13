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
include/xahc/      Layer 0 — header-only safe C lib (guard, check, otxn, state, emit, sfcodes)
crates/xahc-cli/   Layer 1 — Rust CLI: build · clean · lint · sim (thin preflights)
scripts/           verify-emit.mjs — codec round-trip vs xahau-mcp's binary codec
examples/          firewall · guarded_loop · unguarded_loop · emit_payment
```

The CLI's job is **build + clean** (the part nothing else does). `lint` and `sim`
are convenience preflights for fast local feedback; for authoritative analysis and
VM execution, pipe the `.wasm` to [xahau-mcp](https://github.com/Hugegreencandle/xahau-mcp).

## Prerequisites

- **Rust** (for the CLI): `curl https://sh.rustup.rs -sSf | sh`
- **wasm-capable LLVM** (for compiling hooks): LLVM with `wasm-ld`.
  Apple's `/usr/bin/clang` won't work. Install: `brew install llvm` then ensure
  `/opt/homebrew/opt/llvm/bin` is on PATH, or use the Xahau Hooks Builder docker image.

## Usage

```sh
cargo build --release                       # builds the `xahc` binary
export PATH="$PWD/target/release:$PATH"

xahc build examples/firewall.c -o firewall.wasm   # clang -> clean -> lint
xahc lint  firewall.wasm                            # static checks only
xahc clean some.wasm -o some.clean.wasm             # strip stray exports
```

Write a hook:

```c
#include "xahc/xahc.h"

int64_t hook(uint32_t reserved) {
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
- **emit-verify** ✅ two paths: offline codec round-trip (`scripts/verify-emit.mjs`, native)
  and VM round-trip (`scripts/verify-emit-vm.mjs`, needs a xahau-mcp checkout — for XFL/IOU)
- **next** — more typed `otxn`/`state` accessors; richer scaffolds; publish to a
  registry. Loop-guard *dominance* and full VM fidelity are **xahau-mcp's** lane —
  not duplicated here.

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

Pre-alpha. Verified end-to-end on macOS (Homebrew LLVM+lld, Rust) and in CI:
examples compile, clean, lint, and simulate correctly. Both emit builders are
verified: **native XAH** round-trips through xahau-mcp's chain-validated codec to
exactly `Amount: "1000000"` (1 XAH); **issued/IOU** executes in xahau-mcp's VM
(real XFL) and emits `{value:"1.5",currency:"USD",...}` — non-degraded. Not audited;
always confirm financial hooks on testnet before mainnet.

## License

MIT
