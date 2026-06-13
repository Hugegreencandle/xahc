# Testnet proof — agent guardrail enforced on-ledger

On 2026-06-14 the `agent_guardrail` hook was deployed to Xahau **testnet** and the
spending cap was enforced by the ledger itself. This run also surfaced (and drove
the fix for) the v1.5.1 build bug — before it, every xahc-built hook was rejected
on-chain (`temMALFORMED`).

## Result (agent `rKqFBB1nSwXSERqsNyGQduZr4ATTuPxawE`, LIM = 5 XAH)

| Step | Engine result | Tx |
|---|---|---|
| Install `agent_guardrail` (SetHook) | `tesSUCCESS` | [6B41E28B…](https://explorer.xahau-test.net/tx/6B41E28BF583C660DFA37DF2B98E036A39A1BA90B899338FE32A5A8C308C52F6) |
| Pay **10 XAH** (over the 5 XAH cap) | **`tecHOOK_REJECTED`** | [3A81E2E1…](https://explorer.xahau-test.net/tx/3A81E2E183D403DCE989515E4B72AB5CBF5615A68D8AED1B6DA410EB673EEF94) |
| Pay **2 XAH** (under the cap) | `tesSUCCESS` | [441BB402…](https://explorer.xahau-test.net/tx/441BB40280FCC3A05636751439F9D83DE9418E1A4E9DC6A4A6AAA425A6833B0A) |

The over-limit payment was rejected **by the on-account Hook**, not by app code —
exactly the layer-1 agent spending control xahc set out to build.

## Reproduce

```sh
xahc new agentguard --archetype agent_guardrail && cd agentguard
xahc build agentguard.c -o agentguard.wasm
# fund a testnet account (POST https://xahau-test.net/accounts), then:
xahc install-tx agentguard.wasm --account <rAGENT> --on Payment \
    --param 4C494D=00000000004C4B40   # LIM = 5,000,000 drops
# sign offline + submit (xrpl-accountlib / xaman), then send an over-limit Payment
# and watch it tecHOOK_REJECTED.
```

## What the run found (fixed in v1.5.1)

xahaud's SetHook validator rejected xahc output for three independent reasons:
1. dead `__wasm_call_ctors` left by `--export-all` (now `--gc-sections` + export only `hook`/`cbak`);
2. an exported `memory` + compiler custom sections (now stripped by `clean`);
3. `-O2` loop rotation moving the `_g` guard out of the verifier's required position (now `-Oz`).

See [CHANGELOG](../CHANGELOG.md) §1.5.1.
