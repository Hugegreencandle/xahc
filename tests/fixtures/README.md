# Guard-placement fixtures

`loop{A,B,C,D}.c` are the four hooks that root-caused the guard byte-adjacency rule. All four
differ ONLY in where the guard sits. Each was submitted to Xahau testnet after its verdict was
predicted from the emitted bytes; the prediction was correct 4/4.

| fixture | guard position | `SetHook` |
|---------|----------------|-----------|
| `loopA` | in the `for` condition — clang hoists it out of the body | **temMALFORMED** |
| `loopB` | first statement inside the body | **tesSUCCESS** |
| `loopC` | last statement inside the body | **temMALFORMED** |
| `loopD` | `loopA`'s condition guard **plus** a body-head guard | **tesSUCCESS** |

`loopD` is the decisive case: identical to `loopA` in imports, exports, types and section layout,
still carrying the hoisted condition guard, and it installs. Adjacency is the discriminator.

`xahc build` must FAIL on `loopA` and `loopC` and SUCCEED on `loopB` and `loopD`. Building them
needs a wasm32-capable clang, so the automated regression lives in
`crates/xahc-cli/src/guardpass.rs::tests` and encodes the same four shapes directly in WAT — that
tests this pass rather than testing clang's optimiser. These C sources are kept as the on-chain
provenance for the rule.

Full write-up: `docs/GUARD_PLACEMENT.md`. Copies also live in `xahc-prover/hooks/`.

`unguarded_loop.c` is unrelated: a loop with no guard at all, for the lint rule that requires one.
