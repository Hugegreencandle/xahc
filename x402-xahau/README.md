# exact-xahau — reference x402 facilitator for Xahau

A runnable reference for the proposed `exact-xahau` x402 scheme
(spec: [../docs/X402-XAHAU.md](../docs/X402-XAHAU.md)). It turns that proposal
into working code so the design can be exercised and ratified.

## What it does

| Endpoint | Purpose |
|---|---|
| `GET /supported` | Advertise `{scheme:"exact", network:"xahau"}` |
| `POST /verify` | Offline checks on a signed Xahau Payment vs the x402 requirements |
| `POST /settle` | Submit the signed tx to Xahau (`submitAndWait`) |

`/verify` decodes the payload with Xahau's binary codec and checks
`TransactionType`, `Destination == payTo`, `Amount <= maxAmountRequired`, an
expiry window (`LastLedgerSequence`), and signature presence.

**The agent's spending policy is NOT enforced here** — the payer's on-chain
[xahc guardrail Hook](../docs/AGENTIC.md) is. An over-policy payment
`tecHOOK_REJECTED`s at settlement and moves no value, so the facilitator can't be
tricked into settling it. `/verify` is a fast pre-flight; the Hook is the L1
authority. (Optionally, `/verify` can also run the payer's Hook through
xahau-mcp's VM for a pre-settlement check — see the spec doc.)

## Run

```sh
npm install
npm test                      # offline verifyExact cases (no node needed)
npm start                     # facilitator on :4021
XAHAU_WSS=wss://… npm start   # enable /settle against a Xahau node
```

```sh
curl localhost:4021/supported
curl -X POST localhost:4021/verify -d '{
  "paymentPayload": {"txBlob":"<signed Xahau Payment hex>"},
  "paymentRequirements": {"payTo":"r...","maxAmountRequired":"1000000","network":"xahau"}
}'
```

## Status

Reference / proposal-stage. Native XAH only (issued/RLUSD-style amounts and the
exact payload schema are open items in the spec doc). Not audited.
