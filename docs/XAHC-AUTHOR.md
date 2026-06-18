# xahc author — self-certifying Hook generator

The front of the pipeline: **AUTHOR → build → prove → (watch) → register.**

Describe what you want; `xahc author` maps it to a proven-safe archetype, builds it, and
**proves** the invariant(s) that archetype must satisfy. It emits a *certified* hook only
if every required invariant comes back PROVEN — otherwise it refuses (fail-closed). The
certification is the live proof, never a claim baked into a template.

```sh
xahc author "limit payments to 5 XAH"
xahc author "limit payments to 5 XAH" --account rEXAMPLE... --register --key attester.key
xahc author "owner-only" --name my_gate
```

## What it does

1. **Resolve** the intent to exactly one archetype (fail-closed: ambiguous / unknown → error).
2. **Materialize** the proven C source from the prover's `hooks/` as `<name>.c` — zero
   template drift: the bytecode certified is the exact source the engine reasons about.
3. **Build** → `<name>.wasm` (clean + lint via the normal build path).
4. **Prove** every required invariant with `xahc prove`. Any non-PROVEN ⇒ **NOT CERTIFIED**.
5. Only when fully PROVEN: optionally emit an UNSIGNED **SetHook install-tx** with your
   parameters baked in (`--account`), and/or **register** the proof(s) (`--register`).

## Why it's sound

The prover proves invariants **parametrically** — e.g. `accept ⟹ drops ≤ LIM` for *all*
values of the `LIM` hook-parameter. So one proof covers every parameter value; the concrete
value from your intent (e.g. "5 XAH" → `LIM = 5000000`) is baked into the install-tx at the
end and never affects the proof. xahc-author requires the prover checkout — it cannot
certify without it (set `XAHC_PROVER_DIR` if it isn't a sibling).

Fail-closed at every step: an intent it can't resolve is an error (no guessing); a hook it
can't prove is **NOT CERTIFIED** (exit 2) and gets no install-tx and no registry entry; a
missing required parameter is an error.

## Archetype catalog

| Archetype | Example intent | Proves | Params (set at install) |
| --- | --- | --- | --- |
| `spend-limit` | "limit payments to 5 XAH" | `limit` | `LIM` (drops) |
| `agent-guardrail` | "agent budget, lock to one destination" | `guardrail` | `LIM` (drops), `DST` (40-hex accountID, optional) |
| `owner-only` | "owner-only" | `authz` | — |
| `replay-guard` | "replay protection via nonce" | `monotonic` | `NON` |
| `overflow-safe-limit` | "limit with tip, no overflow" | `overflow` | `LIM`, `TIP` (optional) |

Parameter extraction (MVP): `<n> XAH` / `<n> drops` → an 8-byte BE drops value; a 40-char
hex accountID → `DST`. (r-address base58check auto-decode is a planned nicety; until then
pass a 20-byte hex accountID for `DST`.)

## Output

Human: a CERTIFIED/NOT-CERTIFIED verdict, the guarantee in English, per-invariant results,
the install-tx (if `--account`), and whether proofs were registered. `--json` emits the
full `AuthorReport` (intent, archetype, guarantee, invariants[], certified, install_tx,
registered) for CI. Exit: **0** certified · **2** not certified.

## Related

- `xahc prove` — the engine behind the certification (xahc-prover).
- `xahc registry` — where `--register` records the proof (see xahc-prover `docs/PROOF-REGISTRY.md`).
  `xahc author` mints each manifest via `registry make-manifest` (fail-closed) then `registry add`.
