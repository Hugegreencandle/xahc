# xahc fuzz — concrete counterexample hunter

`xahc fuzz` runs the real hook (via the `sim` wasmtime host) on many boundary-biased
concrete inputs and checks an invariant on each outcome. It is the **complement to
`xahc prove`**: where the prover returns INCONCLUSIVE (it can't settle the invariant
symbolically — hard arithmetic, an over-approximation, an unroll bound), fuzz attacks the
same property concretely.

```sh
xahc fuzz hook.wasm --invariant overflow --runs 20000
xahc fuzz hook.wasm --invariant limit --lim 5000000
xahc fuzz hook.wasm --invariant guardrail --lim 1000000 --dst <40-hex-accountID>
```

## What it can and cannot say (read this)

Fuzzing tests **existentially**, not universally:

- A found **counterexample is a definitive DISPROOF** — the hook really violates the
  invariant, with a concrete, reproducible input (printed, and reproducible from `--seed`).
- Finding **none does NOT prove the hook** — it only raises empirical confidence over the
  inputs tried.

So `xahc fuzz` turns an INCONCLUSIVE into either **DISPROVEN** or "no counterexample in N
runs" — but **never into PROVEN**. Only `xahc prove` proves (∀-inputs). Exit: **0** no
counterexample · **2** DISPROVEN.

## How it works

- A no-dependency, seed-deterministic PRNG (splitmix64) drives a **boundary-biased**
  generator: 0, 1, LIM±1, 2·LIM, u64::MAX, u64::MAX−tip, random powers of two, uniform —
  the edges where off-by-one and overflow bugs live.
- Each input is fed through `sim` and the **outcome** (accept/rollback/guard-violation) is
  checked by a per-invariant **oracle** that uses the *same* values the hook sees:
  - `drops` is masked to the native `sfAmount` 62-bit range so the hook and the oracle
    agree on the value (no false counterexamples for un-representable amounts).
  - `TIP` is a raw u64 hook-param and is the real driver of `drops+tip` overflow, so it is
    fuzzed across the full u64 range for the `overflow` invariant.
- The report includes the outcome distribution and an **"accept path never hit" warning**
  — if no input reached an accept, the fuzz is weak (e.g. a hook that mis-decodes the
  amount and rejects everything), and absence of a counterexample means little.

## Supported invariants (stateless)

`limit` · `overflow` · `authz` · `guardrail`. These have an oracle that is a function of
`(input, outcome)`. Stateful invariants (`monotonic`, `period-budget`, `reentrancy`, …)
need seeded prior state and are out of scope for now — use `xahc prove` for those.

## The workflow it fits

```
xahc prove --invariant overflow   # PROVEN | COUNTEREXAMPLE | INCONCLUSIVE
# if INCONCLUSIVE:
xahc fuzz  --invariant overflow    # DISPROVEN (concrete CEX) | no counterexample
```

A DISPROVEN from fuzz is a hard result you can act on; a clean fuzz plus a future proof is
the goal. fuzz never overrides the prover's soundness — it only ever adds a disproof or
confidence, never a proof.
