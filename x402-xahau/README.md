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
- `Destination == payTo`, and an **asset-aware amount check** `Amount <=
  maxAmountRequired`:
  - **native XAH** (no `asset` in the requirements): `Amount` is a drops string,
    both strict `^[0-9]+$` in `(0, 100e9 XAH]`;
  - **issued amount / IOU** (`asset: {currency, issuer}` present):
    `Amount` is an object `{currency, issuer, value}`; the `currency`+`issuer` must
    match the asset (currency codes canonicalized so the 3-char ASCII and 40-hex
    forms of the same code are treated as equal; `XRP`/all-zero rejected), and
    `value <= maxAmountRequired` is compared with an **exact BigInt decimal
    comparator** (mantissa+exponent, **no JS float** — a float compare is unsound and
    would wrongly accept an under/over-payment, e.g. it collapses `2^53+1` and `2^53`).
    The token `value` is validated to the XRPL token range (≤16 significant digits,
    normalized exponent in `[-96, 80]`); over-precision is rejected, never truncated.
  - the **asset class must match in both directions**: a native-required request with
    an issued `Amount`, or an issued-required request with a native drops `Amount`,
    is rejected (`asset mismatch`).
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
`meta.delivered_amount >= required` (not just `tesSUCCESS`). For an **IOU** the
`delivered_amount` is read as an issued-amount object and must match the asset
(currency + issuer) AND carry `value >= required` (same exact comparator); a
wrong-type or wrong-asset `delivered_amount` **fails closed**. For native it stays a
drops comparison. It is protected by an
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
#   X402_REDIS_URL=redis://…      use a SHARED, durable replay store + limiter
#                                 (needs `npm i ioredis`; fails fast if missing)
```

```sh
curl localhost:4021/supported
curl -X POST localhost:4021/verify -d '{
  "paymentPayload": {"txBlob":"<signed Xahau Payment hex>"},
  "paymentRequirements": {"payTo":"r...","maxAmountRequired":"1000000","network":"xahau"}
}'

# price in a token (issued amount): add `asset`; maxAmountRequired is the decimal
# value in the token's units (the tx Amount is {currency,issuer,value}).
curl -X POST localhost:4021/verify -d '{
  "paymentPayload": {"txBlob":"<signed Xahau Payment hex>"},
  "paymentRequirements": {
    "payTo":"r...","maxAmountRequired":"1.50","network":"xahau",
    "asset": {"currency":"USD","issuer":"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq"}
  }
}'
```

## Status

**Reference-grade hardened, not production.** Supports **native XAH and issued
amounts (IOU / tokens)** — price in either by omitting or supplying the `asset`
field. (The exact x402 payload schema for the asset field is still being ratified in
the spec doc; the shape used here — `asset: {currency, issuer}` + decimal
`maxAmountRequired` — is the reference proposal.) The hostile-client checks above
(mandatory bounds, real signature verification, NetworkID + partial-payment guards,
settle re-validation, delivered_amount check incl. the IOU asset+value check, exact
no-float token comparison, currency canonicalization, asset-class match both
directions, auth + rate-limit, signature-bound-to-Account, oversize-body→clean-413)
are enforced and tested.

**Injectable store + limiter (Upgrade).** The replay store and the rate limiter sit
behind a small **async interface** with two backends:

- **Default — in-memory (zero extra deps).** Bounded: the replay store evicts
  entries after a TTL (`X402_REPLAY_TTL_MS`, default 1h) with a fail-closed hard cap
  (`X402_REPLAY_MAX`, default 100k — refuses, never evicts a live binding), and the
  rate-limit buckets are swept of fully-refilled idle IPs. The replay TTL is safe
  because a tx is only valid inside its `LastLedgerSequence` window (minutes); a
  binding older than the TTL can no longer be (re)applied on-ledger. **Caveat: this
  default does NOT survive a restart and is NOT shared across instances** — a
  restart or a second instance could allow one reuse. Single-process only.
- **Optional — Redis (shared + durable).** Set `X402_REDIS_URL` to switch to a
  shared store (atomic `SET key val NX PX <window>` reservation; Redis-native PX TTL
  for the on-ledger window expiry) and a shared **fixed-window** rate limiter
  (`INCR` + `PEXPIRE`; worst case ~2×max across a window boundary — the standard
  cheap-distributed-limiter trade-off). This closes the multi-instance / durability
  gap. `ioredis` is an **optional** dependency, lazy-loaded only when
  `X402_REDIS_URL` is set; if it is set but `ioredis` is missing the server
  **fails fast at boot** rather than silently falling back to a non-shared store
  (which would reopen replay across instances).

`reserve()` is an **atomic test-and-set** in both backends, so two concurrent /
multi-instance settles of the same payment can't both win. `/settle` is also
**idempotent**: a terminal outcome (`tesSUCCESS`, or an on-ledger failure that spent
the sequence — e.g. `tecHOOK_REJECTED`) memoizes a receipt keyed by the replay id;
a retry returns that receipt with `replayed:true` (the real tx hash + delivered
amount) and never re-submits, while an in-flight / ambiguous payment returns
`already consumed` (`inFlight:true`) with no fabricated receipt.

**Limitations to close before production (architectural):** with the **default
in-memory backend**, the replay/nonce store does not survive a restart and is not
shared across instances, and the rate limiter is single-process — use the optional
Redis backend (`X402_REDIS_URL`) for a durable, shared deployment; **RegularKey**
and **multisig (`Signers`)** signatures cannot be validated offline (reported
`signatureVerified:false`, deferred to on-chain settle). Not audited.

**Issued-amount caveats (honest):** the exact token comparator is sound over the full
XRPL token range, but a few issued-amount edge cases are intentionally **out of
scope** and rejected rather than guessed: values needing **>16 significant digits**
are rejected (not truncated to fit XRPL precision); the facilitator does **not** check
trust lines, issuer freeze/`NoRipple`, or path-dependent delivery — it verifies the
signed `Amount`/`delivered_amount` shape + value, and (as for native) relies on the
on-chain settle (and the payer's guardrail Hook) as the spending/settlement authority.
A `tfPartialPayment` IOU is rejected for the same reason as native (delivered could be
far less than `Amount`).
