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

`/verify` decodes the payload with Xahau's binary codec and enforces (every
check is mandatory — a missing bound is a **failure**, never a skip):

- complete requirements: a valid `payTo` r-address **and** a strict
  `maxAmountRequired` (positive decimal drops) must be present, or it returns
  `isValid:false` with `"incomplete payment requirements"`;
- `TransactionType == Payment`, `NetworkID == 21337` (mainnet) / `21338`
  (testnet);
- `Destination == payTo`, `Amount <= maxAmountRequired` (both strict
  `^[0-9]+$`, in `(0, 100e9 XAH]`);
- `tfPartialPayment` is **rejected**;
- an expiry window (`LastLedgerSequence`);
- a **cryptographically verified** signature (xrpl `verifySignature`, not mere
  presence) that is also **bound to `Account`**: after the signature checks out,
  `deriveAddress(SigningPubKey)` must equal `tx.Account`, otherwise it fails with
  `"signature does not match Account"`. (xrpl `verifySignature` only proves the
  `TxnSignature` matches the *embedded* `SigningPubKey` — not that the key belongs
  to the payer; without the binding a tx with `Account=victim` + an attacker's
  key/signature would pass.) The response reports `signatureVerified: true/false`.
  Residual (documented, not solved): a **RegularKey**-signed tx is legitimate but
  its key→Account link lives in ledger state and **cannot be confirmed offline**,
  and **multisig (`Signers`)** likewise depends on an on-ledger `SignerList`; both
  are reported `signatureVerified:false` (flagged, never silently passed) and rely
  on the on-chain settle as the authority.

**The agent's spending policy is NOT enforced by the facilitator** — the payer's
on-chain [xahc guardrail Hook](../docs/AGENTIC.md) is, **provided it is actually
installed**. `/settle` queries `account_objects` and reports
`guardrailHookPresent: true/false` so the guarantee is never silently implied;
if no Hook is installed, there is no L1 spending cap on that account. An
over-policy payment from a Hook-protected account `tecHOOK_REJECTED`s at
settlement and moves no value. `/verify` is a fast pre-flight; the Hook (when
present) is the L1 authority. (Optionally, `/verify` can also run the payer's
Hook through xahau-mcp's VM for a pre-settlement check — see the spec doc.)

`/settle` does **not** trust that `/verify` was called: it re-runs full
verification, enforces single-use replay binding (`InvoiceID`, else
`account:sequence`), and after `submitAndWait` checks
`meta.delivered_amount >= required` (not just `tesSUCCESS`). It is protected by an
optional shared-secret header (`X402_SHARED_SECRET` → `x-x402-secret`) and a
per-IP rate limit.

## Run

```sh
npm install
npm test                      # offline verifyExact + settle re-validation cases
npm start                     # facilitator on :4021
XAHAU_WSS=wss://… npm start   # enable /settle against a Xahau node

# /settle hardening (optional env):
#   X402_SHARED_SECRET=…   require an x-x402-secret header on /settle
#   X402_RATE_MAX=20       per-IP token-bucket size (default 20 / 60s)
#   XAHAU_NETWORK=xahau-testnet   expect NetworkID 21338 instead of 21337
```

```sh
curl localhost:4021/supported
curl -X POST localhost:4021/verify -d '{
  "paymentPayload": {"txBlob":"<signed Xahau Payment hex>"},
  "paymentRequirements": {"payTo":"r...","maxAmountRequired":"1000000","network":"xahau"}
}'
```

## Status

**Reference-grade hardened, not production.** Native XAH only (issued/RLUSD-style
amounts and the exact payload schema are open items in the spec doc). The hostile-
client checks above (mandatory bounds, real signature verification, NetworkID +
partial-payment guards, settle re-validation, delivered_amount check, auth +
rate-limit, signature-bound-to-Account, oversize-body→clean-413) are enforced and
tested. The in-memory stores are now **bounded**: the replay store evicts entries
after a TTL (`X402_REPLAY_TTL_MS`, default 1h) with a hard cap
(`X402_REPLAY_MAX`, default 100k, oldest-evicted), and the rate-limit buckets are
swept of fully-refilled idle IPs — so neither grows without bound under load or
IP-spray. The replay TTL is safe because a tx is only valid inside its
`LastLedgerSequence` window (minutes), so a binding older than the TTL can no
longer be (re)applied on-ledger.

**Limitations to close before production (architectural, not solved here):** the
replay/nonce store is still **in-memory** — bounded, but it does not survive a
restart and is not shared across instances (a restart or a second instance could
allow one reuse); the rate limiter is single-process; **RegularKey** and
**multisig (`Signers`)** signatures cannot be validated offline (reported
`signatureVerified:false`, deferred to on-chain settle); issued-asset settlement
is unimplemented. Use a durable shared nonce store (Redis/DB) and a distributed
rate limiter for production. Not audited.
