# xahc compose — composition prover for Hook chains

A Xahau account installs an ordered chain of up to 10 hooks. `xahc compose` proves a
safety property over the **whole chain**, not a single hook.

```sh
xahc compose chain.toml
```

## The theorem (why a chain inherits per-hook proofs)

A strong-TSH hook that calls `rollback()` aborts the entire transaction; `accept()` lets
execution continue to the next hook. So the transactions a chain lets through are the
**intersection** of what every hook accepts. Therefore every per-hook safety invariant
(`accept ⟹ P`) also holds for the chain — **composition is conjunction**, and the chain
inherits the union of the hooks' proven safety invariants.

## Why that lift can be unsound — what compose actually checks

The conjunction lift is only valid if the hooks don't interfere. `xahc compose` proves each
hook's claimed invariant with the real engine (`xahc prove`) **and** checks the interference
preconditions:

- **State namespace (the dominant vector).** The prover models a hook's state by bare key,
  not by namespace. Xahau partitions state by `(account, HookNamespace, key)`. So two
  *stateful* hooks (importing `state_set`/`state_foreign_set`) that share a `HookNamespace`
  — including the all-zeros default — can clobber each other's state, voiding the per-hook
  proofs. compose **requires distinct namespaces among stateful hooks**.
- **Emission.** `etxn_reserve` bounds emits per hook, so a chain's total is the sum — but a
  hook that exports `cbak` and emits has an unmodeled dynamic re-entry chain, so the chain's
  total-emit bound is reported **inconclusive** (never silently "bounded").

## Fail-closed

The chain is **NOT COMPOSABLE** (exit 2) if any claimed invariant does not prove, or any two
stateful hooks share a namespace. A composable chain reports the inherited guarantees and the
emit-bound status (exit 0). compose does not re-implement proofs — it composes real ones and
proves the composition is sound.

## Chain spec (TOML)

```toml
# ordered hooks installed on one account
[[hook]]
wasm = "guardrail.wasm"
namespace_label = "guardrail"     # or namespace = "<64-hex>"; default = all-zeros
invariants = ["guardrail"]

[[hook]]
wasm = "spend.wasm"
namespace_label = "spend"
invariants = ["reentrancy", "limit"]
```

`wasm` paths are relative to the chain file. `namespace` (64-hex) and `namespace_label`
(sha256'd) are mutually exclusive; omitting both uses the all-zeros default (which makes two
stateful hooks collide — by design, so the footgun is caught).

## Output

Human: per-hook capability tags (`state`/`emit`/`cbak`), each invariant's verdict, the chain
verdict, the inherited guarantees, and the emit-bound status. `--json` emits the full
`ComposeReport` (hooks[], chain_invariants[], composable, emit_bound, reason) for CI.
Exit: **0** composable · **2** not composable.

## Limitations (stated residual)

The interference check is same-account and namespace-local. A hook that calls
`state_foreign_set` can write *another* account's (or namespace's) state — including a
sibling chain hook's slot — which the namespace-distinctness check does not model. compose
**surfaces a caveat** for any chain containing a foreign writer rather than implying the
chain is interference-free; co-analyze those by hand. Other unmodeled couplings (one hook's
accept-condition depending on state another hook writes within a shared namespace) are
exactly what the distinct-namespace requirement forbids — keep stateful hooks namespaced.

## Related

- `xahc prove` — the per-hook engine compose builds on.
- `xahc author` — generate a single proven hook (front of the pipeline).
- `xahc registry` — record proofs (xahc-prover `docs/PROOF-REGISTRY.md`).
