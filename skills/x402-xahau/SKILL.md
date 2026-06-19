---
name: x402-xahau
description: Stand up and drive the x402-xahau facilitator — the provable spending-authority / agent-governance layer for x402 payments on Xahau. An AI agent's budget becomes an on-chain rule (a proven xahc guardrail Hook), readable live via GET /policy/:account, so the agent provably cannot overspend. Use when the user says "/x402-xahau", "agentic payments on Xahau", "provable agent budget / spending cap", "run the x402 facilitator", "x402 verify/settle on Xahau", or wants an AI agent that can pay but can't overspend. Pairs with xahau-hook (write the guardrail), xahau-prove (prove it), xahau-audit.
---

# x402-xahau — provable spending authority for agentic payments

x402-xahau is a reference **x402 facilitator** for Xahau whose job is NOT throughput — it's
**governance**: it makes an AI agent's budget an *on-chain rule*. The agent's account runs an
**xahc guardrail Hook** (its spending cap), the Hook is **formally proven** by xahc-prover, and
its policy is readable live from the chain via `GET /policy/:account`. The agent **provably cannot
overspend** — a safety guarantee, not a speed claim.

## Positioning (state it honestly)
- **Not a high-throughput facilitator.** It settles **on-chain, per payment** (`verify` +
  `submitAndWait`). For raw pay-per-call volume, a **payment-channel** facilitator (e.g. Dhali, the
  incumbent on Xahau) is the right tool — channels settle micropayments off-chain, far faster.
- **The two COMPOSE.** The agent runs the guardrail Hook (its provable cap) and funds channel
  facilitators *within* that cap: a provable on-chain budget on top, channel-speed micropayments
  underneath. Lead with "provable budget," never with "throughput."

## Run
```sh
cd x402-xahau            # standalone repo, or the x402-xahau/ subdir of xahc
npm test                 # offline verify + settle re-validation cases
npm start                # facilitator on :4021
XAHAU_WSS=wss://… npm start   # enable /settle + /policy against a Xahau node
```
Key env (all optional unless noted): `XAHAU_WSS` (node, required for /settle + /policy),
`X402_SHARED_SECRET` (gate /settle + verbose /metrics /status), `X402_RATE_MAX` (per-IP bucket),
`X402_TRUST_PROXY` (LB hops), `X402_REDIS_URL` (shared durable replay store + limiter),
`X402_RECEIPT_SECRET` (32-byte ed25519 seed for signed receipts), `X402_MCP_URL` (enables advisory
`POST /simulate`). Deploy: `Dockerfile` + `docker-compose.yml` + `deploy/`.

## Endpoints
| Endpoint | Purpose |
|---|---|
| `GET /supported` | advertise the `exact`/`xahau` x402 scheme |
| `POST /verify` | offline checks on a signed Xahau Payment vs the x402 requirements |
| `POST /settle` | submit the signed tx (`submitAndWait`); fail-closed on node errors |
| `GET /policy/:account` | **the differentiator** — read the agent's installed guardrail Hook and report its budget straight from the chain (per-tx `LIM`+`DST`, or stateful `PLM`/`PER` + the REAL remaining budget from on-chain HookState). Keyless, read-only |
| `GET /pubkey` | the facilitator's ed25519 receipt key (verify receipts offline) |
| `GET /health` /metrics /status/:id | ops (verbose/data behind the shared secret) |
| `POST /simulate` | advisory accept/rollback prediction (only when `X402_MCP_URL` set) |

## The guardrail Hook stack (this is where the toolchain plugs in)
The agent's provable budget is a Hook — build + prove it with the other skills:
1. **write** it with `xahau-hook` (or `xahc author "limit payments to N XAH"` /
   `agent-guardrail`). Two variants: per-tx (`LIM` + optional `DST` allowlist) or stateful
   period-budget (`LIM` + `PLM` + `PER`).
2. **prove** it with `xahau-prove` (invariants: `guardrail`, `limit`, `period-budget`, `dst-lock`)
   — so "the agent can't overspend" is proven for ALL inputs, not asserted.
3. **install** it (`xahc install-tx`) on the agent's account; `GET /policy/:account` then surfaces
   the proven policy live.

## Honesty
- Provable BUDGET, not throughput. Say "the agent provably cannot exceed its cap," never "fast."
- `/policy` and `/settle` **fail transparent / fail closed** — a node read that fails never
  fabricates a budget or a settlement; surface the error.
- "Proven" means a specific invariant under xahc-prover — name it (e.g. "guardrail PROVEN: accept
  ⟹ spend ≤ LIM ∧ dst ∈ allowlist"), never an unqualified "safe".

## Notes
- Repos: standalone `github.com/Hugegreencandle/x402-xahau` (MIT) + `xahc/x402-xahau`. Scheme spec:
  `xahc/docs/X402-XAHAU.md`. Demo: `x402-xahau/demo/` (live-testnet agent buys within budget; an
  over-budget buy → `tecHOOK_REJECTED`).
- Gotchas (from testnet): a hooked account's Payment needs a higher fee (else `telINSUF_FEE_P`);
  Xahau rippled speaks WS `api_version 1` (pin it; xrpl@4 defaults to 2).
