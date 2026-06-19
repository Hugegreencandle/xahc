# Xahau Hooks — Agent Skills

Invokable [agent skills](https://skills.sh) that let an AI coding agent author, prove, audit,
and reason about **Xahau Hooks** with the `xahc` toolchain + `xahc-prover`. Honest by
construction: they never call a hook "safe" unqualified, treat INCONCLUSIVE/N-A as *not* a pass,
and always state the residual.

## Install

All skills:

```sh
npx skills add Hugegreencandle/xahc
```

A specific skill:

```sh
npx skills add Hugegreencandle/xahc --skill xahau-audit
```

List without installing: `npx skills add Hugegreencandle/xahc --list`.

## The skills

| Skill | What it does |
| --- | --- |
| **xahau-hook** | Author a C → WASM Hook end-to-end: scaffold → build → lint → simulate → prove. |
| **xahau-prove** | Prove a Hook obeys a safety property for ALL inputs (or get a concrete counterexample). |
| **xahau-audit** | Full safety audit: lint → sim → prove → fuzz the inconclusive ones → compose (chains) → register. One honest verdict + stated residual. |
| **xahau-ref** | Cite Xahau protocol facts (host fns, sfcodes, return codes, TSH, amendments) from the dev reference instead of guessing. |
| **xahau-amendment** | Check whether an amendment changed semantics a deployed Hook relies on, and re-prove if so. |
| **evernode-dapp** | HotPocket / Evernode dApp model and where a Xahau Hook is the on-ledger settlement seam. |
| **xahc-guardrail** | Build + install an on-chain spending guardrail for an autonomous agent (per-tx cap, destination lock). |
| **x402-xahau** | Stand up + drive the x402-xahau facilitator — the provable spending-authority layer for agentic payments (the agent's budget is a proven Hook, readable via `GET /policy/:account`; it provably can't overspend). |

## Requirements & safety

- The prove/audit/hook skills drive the `xahc` CLI (this repo, MIT) and the companion
  [`xahc-prover`](https://github.com/Hugegreencandle/xahc-prover) (set `XAHC_PROVER_DIR`).
  Building C → WASM needs a wasm32-capable clang (brew LLVM; Apple clang lacks it).
- The skills run local toolchain commands (`xahc build/lint/sim/prove/fuzz/compose/registry`) and
  read the reference docs. They do not perform destructive operations. Read each `SKILL.md` before
  installing — as you should with any skill.

## License

MIT (see the repository `LICENSE`).
