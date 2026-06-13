# X402 + Xahau — settlement with a layer-1 agent guardrail

A proposal/sketch for using Xahau as an [x402](https://docs.x402.org) settlement
network, where the paying agent's account carries an **xahc guardrail Hook** that
bounds what any x402 payment can do — protocol-enforced, not app-enforced.

> Status: design + reference sketch. The wire details below follow x402's public
> spec (HTTP 402 → signed payload → facilitator `/verify` + `/settle`); the
> Xahau scheme specifics need ratification with the x402 maintainers and the
> XRPL/Xahau facilitator authors (t54).

## x402 recap (vendor-neutral)

1. Client (agent) `GET`s a resource. Server replies `402` with `accepts[]`
   payment requirements: `scheme`, `network`, `maxAmountRequired`, `payTo`,
   `asset`, `maxTimeoutSeconds`.
2. Client builds a signed **Payment Payload** for the chosen scheme and resends
   with the payment header.
3. Server (or a **facilitator**) `/verify`s the payload, then `/settle`s it
   on-chain, and returns the resource with a settlement header.

On EVM the `exact` scheme is a gasless EIP-3009 `transferWithAuthorization`.
Xahau needs its own scheme binding.

## Proposed `exact-xahau` scheme

- **network**: `xahau` / `xahau-testnet` (NetworkID 21337 / 21338).
- **asset**: `XAH` (native) or an issued currency (e.g. RLUSD-equivalent) as
  `{currency, issuer}`.
- **Payment Payload**: a **signed Xahau `Payment` transaction** (the payer agent
  signs; the facilitator submits — payer needs no node). Fields constrained to
  the server's requirements: `Destination = payTo`, `Amount ≤ maxAmountRequired`,
  a short `LastLedgerSequence` window (≈ `maxTimeoutSeconds`), and an
  `InvoiceID`/source-tag binding the payment to the request (replay protection).
- **/verify** (facilitator, read-only): signature valid; `Amount`/`Destination`
  match; `LastLedgerSequence` not expired; the payer account exists and is funded;
  **and the payer's guardrail Hook would accept it** (run the wasm through
  xahau-mcp `execute_hook` against the proposed tx — a pre-flight that the
  on-chain Hook will repeat at settlement).
- **/settle**: submit the signed tx; wait for validation (3–5s deterministic
  finality); return tx hash. Xahau's Hook fires at settlement and is the final
  authority — if the agent's policy rejects, the payment `tecHOOK_REJECTED`s and
  no value moves.

## Why the guardrail Hook matters here

x402 verification is **per-request**. It cannot, by itself, enforce a *standing*
budget across many requests, or "this agent may only ever pay these vendors."
The guardrail Hook does, at L1:

- `LIM` caps the amount of **every** outgoing payment, so a compromised agent or
  a malicious server can't drain the account one request at a time beyond the cap.
- `DST` (optional) locks the agent to an allowlisted payee set.
- The Hook is the same authority at `/verify` (simulated) and at `/settle`
  (enforced) — the facilitator can't be tricked into settling an over-policy tx,
  because the ledger itself rejects it.

So: **x402 handles the request/settlement handshake; the xahc Hook handles the
agent's spending policy.** Clean separation, no overlap.

## Reference facilitator sketch (settle path)

```ts
// POST /settle  — submit a signed Xahau Payment for an x402 exact-xahau payload
import { Client, Wallet } from "xrpl"; // xahau-compatible client

export async function settle(payload: X402Payload): Promise<SettleResult> {
  const { txBlob } = payload;            // signed Payment tx blob from the agent
  const client = new Client(XAHAU_WSS);  // 21337 mainnet / 21338 testnet
  await client.connect();
  const res = await client.submitAndWait(txBlob);
  await client.disconnect();
  const ok = res.result.meta?.TransactionResult === "tesSUCCESS";
  return {
    success: ok,
    transaction: res.result.hash,
    network: "xahau",
    // tecHOOK_REJECTED here == the agent's guardrail Hook blocked an over-policy pay
    errorReason: ok ? null : res.result.meta?.TransactionResult,
  };
}
```

`/verify` mirrors this but instead of submitting, it (a) checks the tx fields vs
the `accepts` entry and (b) runs the payer's installed Hook through
`xahau-mcp execute_hook` so a doomed payment is rejected *before* settlement.

## What xahc already provides toward this

- **The guardrail Hook** (`agent_guardrail` archetype) + `install-tx` to deploy it.
- **Verified emit/serialization** — the same machinery that builds correct Xahau
  Payments (codec-verified for XAH, VM-verified for issued amounts) is the basis
  for constructing the `exact-xahau` payload.
- **`xahc verify`** — differential sim vs the xahau-mcp VM, reusable as the
  facilitator's `/verify` pre-flight.

## Open items (need maintainer input)

- Exact `exact-xahau` payload schema (sign full tx vs an authorization object).
- Issued-asset (RLUSD-style) handling and the DEX-delivered cross-currency case.
- Replay binding: `InvoiceID` vs source-tag vs nonce convention.
- Whether a hosted Xahau facilitator joins the x402 facilitator registry.
