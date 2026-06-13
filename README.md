# xahc — Xahau Hooks, Checked

A safety layer for writing **C Hooks** on the [Xahau Network](https://xahau.network/docs/hooks/).

Hooks are layer-1 WASM smart contracts that fire before/after every transaction on
an account. The stock toolchain (`XRPLF/hook-macros`) is raw C preprocessor macros —
powerful, but every guarantee lives in the developer's head. `xahc` moves those
guarantees into the type system, the compiler, and a static linter.

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
include/xahc/      Layer 0 — header-only safe C lib (guard, check, otxn, state, emit)
crates/xahc-cli/   Layer 1 — Rust CLI: build · clean · lint
examples/          firewall.c (ported)
```

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
    XAHC_REQUIRE(otxn_field(XAHC_SBUF(amt), XAHC_sfAmount) == 8, "amount read");
    // ...
    XAHC_ACCEPT("ok");
    return 0;
}
```

## Roadmap

- **M0** ✅ scaffold: build/clean/lint pipeline, safe headers
- **M1** guard auto-numbering + checked returns (done in headers; needs on-chain test)
- **M2** lint: export + import allowlists, guard-presence
- **M3** typed emit builders (Payment done; IOU/trustline next) + typed otxn/state
- **Phase 2** ✅ local simulator (MVP): `xahc sim` runs a hook in wasmtime with
  mocked host fns and reports accept/rollback + emitted txns + state writes — no testnet
- **M1.5** *(moat, next)* CFG dominance proof — statically prove every `loop` is guarded
- **Phase 2+** sim: JSON tx fixtures, IOU amounts, assertion DSL, `#[test]` harness

### Simulator

```sh
xahc sim firewall.wasm --tt 0 --drops 5000000    # -> ROLLBACK (below 10 XAH floor)
xahc sim firewall.wasm --tt 0 --drops 20000000   # -> ACCEPT
xahc sim firewall.wasm --tt 99                     # -> ACCEPT (not a payment)
```

Rollback/accept codes are the source line numbers (from `__LINE__`), so a
failing assertion points straight at the line that fired.

## Status

Pre-alpha. Verified end-to-end on macOS (Homebrew LLVM+lld, Rust): firewall
example compiles, cleans, lints, and simulates correctly both sides of its
threshold. The emit serialization offsets (`emit/payment.h`) still need a diff
against a live `xahaud` emit before mainnet use. Not audited.

## License

MIT
