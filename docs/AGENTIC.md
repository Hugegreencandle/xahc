# Agentic payments on Xahau — the safety layer

AI agents are starting to move real value: paying for APIs, compute, and
services without a human in the loop. Ripple's **XRPL AI Starter Kit** (X402
support, RLUSD, an XRPL docs MCP, Claude wallet/payment skills) makes that case
for the XRP Ledger. It is, today, **XRPL-mainnet only** — and its "agent
controls" story is the stock account features: escrow, multisign, deposit-auth.

Xahau goes further. With **Hooks**, an account can carry *programmable, bounded*
policy — the agent's spending rules enforced by the ledger itself. This repo
(`xahc`) is the toolchain that builds those policies; [`xahau-mcp`](https://github.com/Hugegreencandle/xahau-mcp)
is the toolchain that audits and simulates them. Together they're the missing
**agent safety layer** for the agentic-payments wave.

## Why Hooks beat "escrow + multisign" for agents

| Need | XRPL stock controls | Xahau Hook (xahc) |
|---|---|---|
| Cap per-tx spend | not native | `LIM` parameter, enforced on every outgoing payment |
| Lock to allowed destinations | deposit-auth (inbound only) | `DST` parameter on outbound |
| Change policy without new keys | re-key / new signer set | re-install with new params (Flags=1) |
| Bounded, auditable logic | n/a | guard-bounded WASM (`_g`) — execution is bounded, narrowing open-ended execution risk |

The "no smart-contract execution risk" argument *for* XRPL also largely applies
to Hooks: they are deliberately constrained — every loop is `_g`-guarded, so
execution is bounded rather than open-ended — which gives you agent-policy
programmability with a much smaller attack surface than a general smart-contract
VM. (This bounds the Hook's own execution; it is not a guarantee about the safety
of any particular policy you write — audit and testnet-confirm your Hook.)

## The kit

1. **Guardrail skill** — [`skills/xahc-guardrail`](../skills/xahc-guardrail/SKILL.md):
   an agent (via Claude) scaffolds, builds, tests, and emits an **unsigned**
   SetHook that installs its *own* spending limit. Self-imposed, on-chain budget.
2. **`agent_guardrail` archetype** — `xahc new x --archetype agent_guardrail`:
   per-tx spend cap + optional destination lock, configured by HookParameters.
3. **Settlement** — `xahc install-tx` emits the SetHook; payments are built by
   the verified emit builders. See [X402-XAHAU.md](X402-XAHAU.md) for how this
   slots under the X402 protocol.
4. **Audit/sim** — hand the `.wasm` to `xahau-mcp` (`analyze_hook`, `execute_hook`)
   for full-fidelity verification; `xahc verify` does a differential check.

## How this relates to the other tools

- **`xahc`** (here) — author/compile the policy Hook.
- **`xahau-mcp`** — analyze + simulate the Hook (real VM, fidelity-locked).
- **`xrpl-mcp`** — read-only XRPL/Xahau ledger access for agents, with
  token-safety / validator / HNDL risk scores. Differentiator vs the official
  XRPL **docs** MCP: execution + risk scoring, not just documentation lookup.

## Demo: an agent that limits itself

```sh
# the agent decides its own ceiling: 10 XAH per payment
xahc new agentguard --archetype agent_guardrail && cd agentguard
xahc build agentguard.c -o agentguard.wasm
xahc test  agentguard.test.toml            # over-limit -> rollback, within -> accept
xahc install-tx agentguard.wasm --account rAGENT --on Payment \
    --param 4C494D=0000000000989680        # LIM = 10,000,000 drops
# -> unsigned SetHook; sign offline. The ledger now caps the agent at 10 XAH/tx.
```

Not audited; confirm on testnet before mainnet.
