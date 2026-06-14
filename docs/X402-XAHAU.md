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
- **/verify** (facilitator, read-only): the requirements are complete (a valid
  `payTo` and a strict `maxAmountRequired` — a missing bound is a failure, never
  a skip); `NetworkID` matches; `tfPartialPayment` is absent; the **signature is
  cryptographically verified AND bound to the payer** (xrpl `verifySignature`
  against `SigningPubKey`, **then** `deriveAddress(SigningPubKey) == Account` —
  `verifySignature` alone only proves the sig matches the embedded key, not that
  the key belongs to `Account`, so a forged-`Account` tx with an attacker's key
  would otherwise pass; a mismatch fails with `"signature does not match
  Account"`, reported as `signatureVerified`); `Amount`/`Destination` match;
  `LastLedgerSequence` not expired. The reference facilitator also reports
  `guardrailHookPresent` (queried from `account_objects`) so the Hook guarantee
  is conditional on a Hook actually being installed.
  *Open/unimplemented (offline-unverifiable, deferred to on-chain settle):* a
  **RegularKey**-signed tx (the signing key is authorized via an on-ledger
  `SetRegularKey`, so it will NOT derive to `Account`) and **multisig
  (`Signers`)** authorization (an on-ledger `SignerList`) cannot be validated by
  the offline single-sig path — both are reported `signatureVerified:false`
  rather than silently passed. Also open: running the payer's Hook wasm through
  xahau-mcp `execute_hook` as a pre-settlement simulation (the on-chain Hook
  still repeats the check at settlement).
- **/settle**: re-run the full `/verify` checks (do not trust verify was called);
  enforce single-use replay binding (`InvoiceID`/source-tag/`account:sequence`);
  submit the signed tx; wait for validation (3–5s deterministic finality);
  confirm `meta.delivered_amount >= required` (not just `tesSUCCESS`); return tx
  hash. **If — and only if — the payer carries the guardrail Hook**, Xahau's Hook
  fires at settlement and is the final authority: an over-policy payment
  `tecHOOK_REJECTED`s and no value moves. An account with no Hook installed has
  no L1 spending cap, so `guardrailHookPresent` must be checked, not assumed.

## Why the guardrail Hook matters here

x402 verification is **per-request**. It cannot, by itself, enforce a *standing*
budget across many requests, or "this agent may only ever pay these vendors."
The guardrail Hook does, at L1:

- `LIM` caps the amount of **every** outgoing payment, so a compromised agent or
  a malicious server can't drain the account one request at a time beyond the cap.
- `DST` (optional) locks the agent to an allowlisted payee set.
- The Hook is the same authority at `/verify` (simulated) and at `/settle`
  (enforced) — for a Hook-protected account the facilitator can't be tricked into
  settling an over-policy tx, because the ledger itself rejects it. The
  facilitator reports `guardrailHookPresent` so a caller never mistakes an
  unprotected account for a protected one.

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
