# Contributing to xahc

Thanks for helping. xahc is the authoring/compile half of the Xahau Hooks
toolchain; deep analysis/simulation lives in
[xahau-mcp](https://github.com/Hugegreencandle/xahau-mcp). Keep that split in mind
when proposing features — we don't duplicate the analysis engine.

## Dev setup

- **Rust** (stable) for the CLI.
- **wasm-capable LLVM** to compile hooks: `brew install llvm lld`
  (add `/opt/homebrew/opt/llvm/bin` + `/opt/homebrew/opt/lld/bin` to PATH), or
  `apt install clang lld`. Verify with `cargo run -- doctor`.

## Build, test, lint

```sh
cargo build --release
cargo test --release          # unit tests
cargo clippy --release -- -D warnings   # must be clean (CI enforces)
```

## Working on the headers

The headers in `include/xahc/` are embedded into the binary. When iterating on
them, point the build at your working tree so you don't rebuild the binary each
time:

```sh
XAHC_INCLUDE=$PWD/include cargo run -- build examples/firewall.c -o /tmp/x.wasm
```

## Fund-safety rule

Anything that serializes a transaction or money value (emit builders, HookOn,
amounts) **must** be cross-verified against xahau-mcp's chain-validated codec/VM
(`scripts/verify-emit.mjs`, `scripts/verify-emit-vm.mjs`) and locked with a test
or CI assertion before merge. No hand-rolled serialization ships unverified.

## CI

Every push runs: clippy (blocking), unit tests, build of all examples, the test
suites, the install-tx HookOn regression, and the emit codec round-trip.
