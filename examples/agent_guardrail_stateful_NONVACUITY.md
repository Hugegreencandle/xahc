# Proven Agent Budget — non-vacuity controls (2 of 3 primitives)

**2026-07-07.** "Proven Agent Budget" proves an agent spending-authority Hook cannot overspend — the
"hard ceiling at the network level" that x402 / AP2 / policy-wallets lack. A proof is only worth anything
if it can FAIL, so each primitive pairs the REAL hook (must PROVE) with a planted-bug twin (must be
REFUTED). Two primitives now have this control end-to-end:

| primitive | real → verdict | twin → verdict | planted bug |
|-----------|----------------|----------------|-------------|
| per-tx cap (LIM) | `agent_guardrail` → ✅ PROVEN | `agent_guardrail_BUG` → ❌ COUNTEREXAMPLE (drops=8590000129 > LIM=2147548920) | 32-bit truncated compare `(uint32_t)drops <= (uint32_t)limit` |
| period budget (PLM, inductive) | `agent_guardrail_stateful` → ✅ PROVEN | `agent_guardrail_stateful_BUG` → ❌ COUNTEREXAMPLE (spent'=1.8447e19 > PLM) | caps `amount <= plm` ignoring prior `spent` |
| destination allowlist (DST) | `agent_guardrail` → ✅ PROVEN (dst-lock) | `agent_guardrail_dstBUG` → ❌ COUNTEREXAMPLE (dest=…00FF… accepted vs allowed …00) | address compare loop checks 4 of 20 bytes |

Core spend-policy set COMPLETE: per-tx cap + period budget + destination allowlist, each proven-on-real +
refuted-on-twin. Next (optional): `rate_limit` + `quorum` (M-of-N co-sign) to round out the suite, then
packaging (attestation card + /policy readout) and binding to x402-xahau's shipped guardrail bytecode.

## Detail: the period-budget primitive (the hardest one)

The differentiated primitive: prove a stateful agent Hook cannot exceed its cumulative per-period budget
across an unbounded payment sequence — the "hard ceiling at the network level" that x402 / AP2 /
policy-wallets lack. A proof is only worth anything if it can FAIL, so this pairs the real hook with a
planted-bug twin the prover must refute.

## The pair

| hook | driver | verdict |
|------|--------|---------|
| `agent_guardrail_stateful.wasm` (real) | `prove_period_budget.py` | ✅ **PROVEN** — inductive step: IF prior `spent ≤ PLM` THEN every accepting path persists `spent' ≤ PLM`; also per-tx `A ≤ LIM` and DST-lock. |
| `agent_guardrail_stateful_BUG.wasm` (twin) | `prove_period_budget.py` | ❌ **COUNTEREXAMPLE** — an in-budget prior state is driven over PLM on an accepting path. |

## The planted bug (one line, realistic)

The real hook checks the payment against REMAINING headroom:
```c
uint64_t remaining = (spent <= plm) ? (plm - spent) : 0;
XAHC_REQUIRE(amount <= remaining, "over period budget");
```
The twin caps against the FULL period budget, ignoring prior spend:
```c
XAHC_REQUIRE(amount <= plm, "over period budget");   /* BUG */
```
Every single payment `≤ PLM` passes, and a fresh-state local sim (`spent==0`) looks correct — lint clean,
sim green. But the hook still persists `spent' = spent + amount`, so a prior `spent` up to PLM plus a new
`amount` up to PLM drives the persisted `spent'` to ~`2·PLM > PLM`.

## The prover's counterexample (concrete, no overflow trick — sum < 2^64)
```
prior spent = 13835058055282163713   PLM = 18446744073441115136   (spent ≤ PLM holds)
amount A    = 4611686018427387900    LIM = 9223380832947798014
persisted spent' = 18446744073709551613  >  PLM = 18446744073441115136
```
(The solver picks large drops because inputs are unconstrained; a human-scale instance is
`PLM=1000, spent=600, amount=600 → spent'=1200 > 1000`.)

## Why this is the sell
- The proof binds to the DEPLOYED bytecode and holds for ALL inputs — strictly higher assurance than any
  app-layer guardrail or single-tx sim.
- The twin proves the proof is NOT vacuous: it catches a plausible developer mistake that both lint and a
  fresh-state sim miss. "Passes your tests, fails the proof" is the pitch.
- Honest scope (from the driver): the present-state path (state read == 16B), covering same-period AND
  period-reset sub-branches; combined with the `spent=0` base case this inductively bounds cumulative spend.
  The absent/fresh-period branch (srd<0) is a separate obligation, disclosed, not claimed here.

## Artifacts
- `agent_guardrail_stateful.c` / `.wasm` — the real hook.
- `agent_guardrail_stateful_BUG.c` / `.wasm` — the refutation twin (this pair's control).
- `~/Desktop/xahc-prover/src/prove_period_budget.py` — the inductive-step driver (fail-closed).

Status: LOCAL, uncommitted — release decision is Dane's (product IP; keep-private lens).
