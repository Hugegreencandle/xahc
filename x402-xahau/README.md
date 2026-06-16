# exact-xahau — reference x402 facilitator for Xahau

> **Standalone mirror.** This is the canonical standalone home of the x402-xahau
> facilitator. It is also developed inside the **xahc** toolchain repo at
> [`Hugegreencandle/xahc/x402-xahau`](https://github.com/Hugegreencandle/xahc/tree/main/x402-xahau),
> where its companion tools live: the guardrail Hook is **written** with
> [xahc](https://github.com/Hugegreencandle/xahc), **simulated** with
> [xahau-mcp](https://github.com/Hugegreencandle/xahau-mcp), and **proven** safe with
> [xahc-prover](https://github.com/Hugegreencandle/xahc-prover). MIT-licensed.

A runnable reference for the proposed `exact-xahau` x402 scheme (spec:
[`X402-XAHAU.md` in the xahc repo](https://github.com/Hugegreencandle/xahc/blob/main/docs/X402-XAHAU.md)).
It turns that proposal into working code so the design can be exercised and ratified.

## What it does

| Endpoint | Purpose |
|---|---|
| `GET /supported` | Advertise `{kinds:[{x402Version:2, scheme:"exact", network:"xahau"}]}` |
| `POST /verify` | Offline checks on a signed Xahau Payment vs the x402 requirements |
| `POST /settle` | Submit the signed tx to Xahau (`submitAndWait`) |
| `GET /health` | Liveness JSON. **Minimal** `{ status, network, uptimeSec }` unauthenticated (LB probe); verbose internals require the shared secret |
| `GET /metrics` | Counters as JSON (or Prometheus text on `Accept: text/plain`). **Auth-gated** behind the shared secret (open in reference mode) |
| `GET /policy/:account` | **On-ledger budget introspection** — read the account's installed xahc guardrail Hook and surface its spending policy (per-tx `LIM` cap + `DST` allowlist) straight from the chain. Read-only, public. Needs `XAHAU_WSS` (503 if unset). Fail-transparent |
| `GET /pubkey` | The facilitator's **ed25519 receipt verification key** (`{ alg, pubkey }`, raw 32-byte hex). Public. Lets a resource server verify signed receipts **offline** |
| `GET /status/:id` | Look up a stored settlement by its `replayId` (or `hash:<txhash>`). **Auth-gated** (exposes payment data; open in reference mode). Honest `unknown` when not found/expired |
| `POST /simulate` | **(Optional, config-gated)** Predict the guardrail Hook's accept/rollback for a payment **without submitting** (advisory). Only enabled when `X402_MCP_URL` is set (else 404) |

### New features (summary)

- **On-ledger policy (`GET /policy/:account`)** — the agent's spending policy *lives in a
  Hook*, so this is the one thing no other x402 facilitator can report. We read
  `account_objects type:hook`, identify the `agent_guardrail` Hook by its `LIM`
  HookParameter, and decode `LIM` (8-byte big-endian drops per-tx cap) + `DST` (20-byte
  account-id → r-address allowlist). The `agent_guardrail` Hook is **stateless** (a per-tx
  cap, not a running budget): we report `stateful:false` and never invent a `remaining`.
  **Fail-transparent:** any node/decode error returns `policy:null` + an honest `note` —
  **never** a fabricated limit. A wrong policy readout would be a credibility bug.
- **Signed receipts + `GET /pubkey`** — every **successful** settlement attaches a
  facilitator-signed `proof` (ed25519) over a **canonical, deterministic** serialization of
  the receipt's load-bearing fields, so a resource server can verify it **offline** with just
  the pubkey. Failed/rejected settlements carry `proof:null` (a receipt proves a settlement
  *occurred*, not future behavior). See the verification recipe below.
- **`scheme: "exact" | "upto"`** — `paymentRequirements.scheme` selects the amount check:
  `exact` ⇒ paid **must equal** `maxAmountRequired` (strict, native + IOU exact compare);
  `upto` ⇒ paid `<=` max. **Default when `scheme` is absent = today's behavior** (the
  `<=` ceiling, identical to `upto`) — fully back-compatible.
- **Advisory simulation (`POST /simulate`, `dryRun`)** — when `X402_MCP_URL` is set, predict
  the Hook outcome via xahau-mcp **without submitting**. **Advisory only:** it never changes
  settle's security semantics (a predicted-accept still runs the full real settle). A
  `dryRun:true` on `/settle` returns the prediction and does not submit; the opt-in
  `preSimReject:true` may skip the submit on a *predicted-reject* (clearly labeled, reserves
  no replay slot). Fails soft — a sim error never blocks the real settle.

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
  key/signature would pass.) The `/verify` response reports
  `signatureVerified: true/false`.
  **What `/verify` confirms OFFLINE:** only a **master-key single-sig** is bound
  offline (`deriveAddress(SigningPubKey) === Account` after the crypto check →
  `signatureVerified:true`). A **RegularKey**-signed tx and a **multisig
  (`Signers`)** tx cannot be confirmed offline (the key→Account link / `SignerList`
  live in ledger state, and xrpl `verifySignature` cannot even validate a multisig
  blob), so `/verify` returns `signatureVerified:false` for them (flagged, never a
  guarantee).
  **What `/settle` confirms ON-LEDGER (Upgrade #3):** at settle the facilitator
  holds a node connection, so for a tx that was *not* bound offline it does a
  POSITIVE on-ledger authorization check and reports the *source*:
  - **RegularKey** (single-sig): `account_info` is read; authorized iff the
    account's `RegularKey` equals `deriveAddress(SigningPubKey)`. (Note: a
    single-sig whose key doesn't derive to `Account` is already rejected offline by
    the conservative master-key binding; the RegularKey on-ledger path is the
    documented hook for that case.)
  - **multisig** (`Signers`): the on-ledger `SignerList` is read; each signer's
    `TxnSignature` is cryptographically verified over `encodeForMultisigning(tx,
    signer.Account)`, `deriveAddress(signer.SigningPubKey)` must equal
    `signer.Account`, the signer must be on the `SignerList`, and the sum of the
    **on-ledger** `SignerWeight` of the valid, listed signers (deduped) must reach
    the on-ledger `SignerQuorum`.
  These checks may only **REJECT** (an obviously-unauthorized tx is refused
  *pre-submit* — no slot reserved, no submit wasted, `signatureVerified:false`) or
  **UPGRADE** confidence (a genuinely-authorized tx settles with
  `signatureVerified:true` and `signatureSource: "regularkey" | "multisig"` —
  master-key txs report `source:"master"`). They never weaken a check. **The check
  fails CLOSED:** if the node read fails, the facilitator does NOT fabricate
  authorization — it falls back to its prior behavior (proceed to submit; the
  **ledger is the ultimate authority** and rejects a bad tx at `submitAndWait` via
  `tefBAD_AUTH` / `tefBAD_QUORUM` etc.). `signatureVerified:true` is never reported
  without a positive on-ledger confirmation.

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

**Hook-execution transparency (read-only).** When a payment from a hooked account
is submitted, the validated tx's `meta` carries `HookExecutions` — each with the
executing `HookAccount`/`HookHash`, the `HookReturnCode`, a `HookReturnString`, and
emitted-txn info. `/settle` surfaces this on the receipt as a `hookExecutions: [...]`
array, decoding each entry to
`{ hookAccount, hookHash (short), returnCode, returnString (hex→utf8, bounded +
printable), emitCount?, flags? }`. This is **purely informational**: it is included
on both successful **and failed** receipts (a `tecHOOK_REJECTED` is exactly when the
guardrail's `returnString` rejection reason is most useful). A tx with no Hook
executions yields `[]`. **It is NOT part of the signed receipt proof** — it rides
alongside, unsigned (the `proof` is computed over the fixed canonical fields only, so
the proof bytes are byte-for-byte unchanged by this field), and it **never** affects
any accept/reject/replay/idempotency decision. Decoding is defensive and bounded
(unknown meta shape → `[]`, never throws), and reports only what is actually in the
meta (no fabrication). Note: exact `HookExecutions` shape can vary across node
implementations/versions; the decoder accepts the canonical `{ HookExecution: {...} }`
wrapper and a bare object, and falls back to `[]` on anything it can't recognize.

## Run

```sh
npm install
npm test                      # offline verifyExact + settle re-validation cases
npm start                     # facilitator on :4021
XAHAU_WSS=wss://… npm start   # enable /settle against a Xahau node

# /settle hardening (optional env):
#   X402_SHARED_SECRET=…   require an x-x402-secret header on /settle AND /metrics,
#                          and to see /health's verbose internals (else /health is
#                          the minimal liveness shape only)
#   X402_RATE_MAX=20       per-IP token-bucket size (default 20 / 60s)
#   X402_TRUST_PROXY=0     # trusted proxy/LB hops in front of this server. 0
#                          # (default) = NEVER trust X-Forwarded-For (use the socket
#                          # peer addr); n>0 = take the client IP as the (n+1)-th
#                          # entry from the RIGHT of XFF (strip n trusted hops). Set
#                          # this to the EXACT number of proxies you control — a too-
#                          # high value lets a client spoof its rate-limit identity.
#   XAHAU_NETWORK=xahau-testnet   expect NetworkID 21338 instead of 21337
#   X402_REDIS_URL=redis://…      use a SHARED, durable replay store + limiter
#                                 (needs `npm i ioredis`; fails fast if missing)
#   X402_RECEIPT_SECRET=<hex|base64>  32-byte ed25519 SEED for signing receipts.
#                                 If UNSET, an EPHEMERAL key is generated at boot (a
#                                 warning is logged; receipts won't persist across
#                                 restarts — resource servers must re-fetch /pubkey).
#                                 The secret is NEVER logged.
#   X402_MCP_URL=https://…/simulate   xahau-mcp HTTP shim for ADVISORY pre-settle
#                                 simulation. When SET, enables POST /simulate +
#                                 dryRun/preSimReject on /settle. When UNSET the
#                                 feature is entirely OFF (no coupling, /simulate=404).
#   X402_MCP_TIMEOUT_MS=5000      per-call simulation fetch timeout (fails soft)
# operational (optional env):
#   X402_CONNECT_TIMEOUT_MS=8000  per-attempt xrpl connect timeout
#   X402_CONNECT_ATTEMPTS=3       bounded reconnect attempts (then fail closed)
#   X402_CONNECT_BACKOFF_MS=500   backoff between connect attempts
#   X402_SHUTDOWN_DRAIN_MS=10000  graceful-shutdown in-flight drain budget
#   X402_REQUEST_TIMEOUT_MS=15000 max time to receive a full request (slowloris)
#   X402_HEADERS_TIMEOUT_MS=10000 max time to receive request headers (slowloris)
#   X402_MAX_CONNECTIONS=1024     cap concurrent sockets (connection-flood bound)
```

```sh
curl localhost:4021/health     # minimal liveness (no auth)
curl -H 'x-x402-secret: …' localhost:4021/health    # verbose internals (auth)
curl -H 'x-x402-secret: …' localhost:4021/metrics   # counters (JSON, auth-gated)
curl -H 'x-x402-secret: …' -H 'Accept: text/plain' localhost:4021/metrics  # Prometheus text
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

```sh
# On-ledger spending policy (reads the payer's guardrail Hook). Needs XAHAU_WSS.
curl localhost:4021/policy/rMWaeQoWNZoKvuaiUh59z7eHWz6qsToPbg
# -> { "account":"r...", "guardrailHookPresent":true,
#      "policy": { "perTxLimitDrops":"5000000", "allowlist":["rPsf6..."],
#                  "stateful":false, "note":"per-tx spend cap (stateless guardrail)..." },
#      "source":"on-ledger", "asOfLedger": 9720000 }
# Fail-transparent: node down / undecodable -> { ..., "policy":null, "note":"... unknown" }.

# Facilitator receipt public key (for OFFLINE receipt verification).
curl localhost:4021/pubkey            # -> { "alg":"ed25519", "pubkey":"<64-hex>" }

# Look up a stored settlement (auth-gated when a secret is set).
curl -H 'x-x402-secret: …' localhost:4021/status/acct:rPAYER:1234
# -> { "found":true, "status":"settled", "receipt": { ... , "proof": {...} } }   (or found:false/unknown)

# Pre-settle simulation (advisory; only when X402_MCP_URL is set).
curl -X POST localhost:4021/simulate -d '{ "paymentPayload":{...}, "paymentRequirements":{...} }'
# -> { "advisory":true, "simulation": { "available":true, "prediction":"accept"|"reject"|"unknown" } }

# Exact-amount scheme (paid must EQUAL maxAmountRequired); upto = the default ceiling.
curl -X POST localhost:4021/verify -d '{
  "paymentPayload": {"txBlob":"<hex>"},
  "paymentRequirements": {"payTo":"r...","maxAmountRequired":"1000000","network":"xahau","scheme":"exact"}
}'

# Dry-run a settle (predict + DO NOT submit / reserve). preSimReject:true opts into the
# fee-saving predicted-reject short-circuit. Both are ADVISORY.
curl -X POST -H 'x-x402-secret: …' localhost:4021/settle -d '{
  "paymentPayload": {...}, "paymentRequirements": {...}, "dryRun": true
}'
```

## Verifying a signed receipt offline

Every **successful** `/settle` returns a receipt with a `proof`:

```json
{
  "success": true, "transaction": "<txhash>", "network": "xahau",
  "delivered": "1000000", "payer": "rPAYER", "payTo": "rPAYEE",
  "txHash": "<txhash>", "required": "1000000", "asset": null, "ts": 1700000000000,
  "hookExecutions": [],
  "proof": { "alg": "ed25519", "pubkey": "<64-hex>", "sig": "<128-hex>" }
}
```

A resource server can verify it **offline** with just the facilitator's `/pubkey`. The
signature is ed25519 over the **canonical bytes** of the receipt's load-bearing fields.
(`hookExecutions` is read-only/informational and is **NOT** among those signed fields,
so it never affects verification — see the Hook-execution transparency note above.)
**Canonical-bytes recipe** (the verifier MUST reproduce these exact bytes):

1. Build the object with **exactly** these keys (an absent value is the JSON literal
   `null`, never dropped): `{ v: 1, network, txHash, payer, payTo, asset, delivered,
   required, ts }`.
2. JSON-serialize with **keys sorted ascending at every level** and **no whitespace**
   (recursive; arrays keep order). Non-finite numbers are not allowed.
3. UTF-8 encode → those are the signed bytes. Verify `proof.sig` (hex) against the bytes
   using `proof.pubkey` (raw 32-byte ed25519 key, hex).

You should also confirm `proof.pubkey` equals the key you fetched from a trusted
`GET /pubkey` — a valid signature under an *unknown* key is not trust.

```js
import crypto from "node:crypto";
// `canon` = sorted-key, no-whitespace JSON (see step 2).
const canon = (v) => v === null ? "null"
  : typeof v === "string" || typeof v === "number" ? JSON.stringify(v)
  : typeof v === "boolean" ? (v ? "true" : "false")
  : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
  : "{" + Object.keys(v).filter(k => v[k] !== undefined).sort()
      .map(k => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";

function verifyReceipt(r, expectedPubkey) {
  const p = r.proof;
  if (!p || p.alg !== "ed25519" || p.pubkey !== expectedPubkey) return false;
  const payload = { v: 1, network: r.network, txHash: r.txHash, payer: r.payer,
    payTo: r.payTo, asset: r.asset ?? null, delivered: r.delivered ?? null,
    required: r.required ?? null, ts: r.ts };
  const bytes = Buffer.from(canon(payload), "utf8");
  const key = crypto.createPublicKey({ format: "jwk",
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(p.pubkey, "hex").toString("base64url") } });
  return crypto.verify(null, bytes, key, Buffer.from(p.sig, "hex"));
}
```

The facilitator also **exports** `verifyReceipt(receipt, { expectedPubkey })` from
`server.mjs` for in-process verification. **Scope:** a receipt proves a settlement
*occurred* (and the delivered amount), **not** future behavior. The on-ledger guardrail
Hook (when installed) is the L1 spending authority — see `/policy/:account`.

## Operational hardening

- **`GET /health`** — cheap, never throws. **Auth-tiered:** an unauthenticated caller
  (LB liveness probe) gets only the minimal `{ status, network, uptimeSec }`; an
  **authenticated** caller (the `x-x402-secret` shared secret, same as `/settle`)
  additionally gets the operational internals `{ networkID, replayStore:
  "memory"|"redis", rateLimiter: "memory"|"redis", redisConnected?, xrplConfigured,
  xrplConnected?, replayBindings }`. In **reference mode** (no `X402_SHARED_SECRET`)
  every caller is treated as authenticated, so the verbose object is returned.
  **Honest by design:** connectivity it cannot cheaply determine is reported
  falsy/absent, never fabricated as healthy (`xrplConnected` is only `true` if a
  pooled client reports `isConnected()`; `redisConnected` only if ioredis status is
  `ready`). It does not open a connection to answer.
- **`GET /metrics`** — **auth-gated** behind the same shared secret as `/settle`
  (`401` without it; open in reference mode when no secret is configured). JSON
  counters by default, Prometheus exposition text on `Accept: text/plain`. Counters
  move on **real events only**, wired at the exact code points: `verify_total`,
  `settle_total`, `settle_success`, `settle_replayed`, `settle_rejected` (+ breakdown
  buckets `verify_failed`, `replay_inflight`, `store_full`, `submit_ambiguous`,
  `tem_rejected`, `on_ledger_failure`, `delivered_short`, `other`),
  `rate_limited_total`, `body_too_large_total`. **No PII** (no addresses/amounts) is
  ever recorded.
- **Structured logging** — dependency-free JSON lines to **stderr**
  (`{ ts, level, event, ... }`), honest level (error/warn/info). Never logs secrets,
  full tx blobs, or signatures.
- **Resilient xrpl client** — reconnects on disconnect; each connect attempt is
  bounded by `X402_CONNECT_TIMEOUT_MS` with a bounded backoff retry
  (`X402_CONNECT_ATTEMPTS`). **Not** an unbounded in-request retry loop: after the
  bounded attempts it **fails closed** and `/settle` returns a clear `errorReason`.
- **Graceful shutdown** — `SIGTERM`/`SIGINT` stop accepting new connections,
  **close idle keep-alive sockets immediately** (`server.closeIdleConnections()`, so a
  slow/idle client can't ride out the drain and stall `server.close()`), drain
  in-flight requests within `X402_SHUTDOWN_DRAIN_MS`, then close the xrpl client and
  Redis connection and exit. **Handlers are attached only inside `serve()`** (never
  at import) so importing the module for tests installs no signal handlers / exit.
- **Slowloris / flood bounds** — set on the live server in `serve()` (never at
  import): `requestTimeout` (`X402_REQUEST_TIMEOUT_MS`, default **15000ms**) caps the
  total time to receive a full request so a slow drip can't hold a socket forever;
  `headersTimeout` (`X402_HEADERS_TIMEOUT_MS`, default **10000ms**) caps header
  receipt; `maxConnections` (`X402_MAX_CONNECTIONS`, default **1024**) caps concurrent
  sockets so a connection flood can't exhaust file descriptors. These add **time +
  count** bounds alongside the existing 64 KiB body-**size** bound.
- **Pre-submit store outage → retryable `503`, fail-closed** — if the replay store
  (Redis) is unreachable on a **pre-submit** read (`isConsumed`/`getReceipt`/
  `reserve`), `/settle` returns `{ success:false, errorReason:"replay store
  unavailable", retryable:true }` → HTTP **`503`** (not an opaque `500`). It **never**
  proceeds to submit on a store error (that would be fail-**open**, risking a
  double-submit) — the submit only happens after the reservation is held. A
  **post-submit** persistence failure is handled separately as best-effort: the
  authoritative receipt is still returned (the tx already applied), never a `500`.
- **Boot-time config validation** — on `serve()`, validates `PORT`, the `XAHAU_WSS`
  ws/wss URL form, `XAHAU_NETWORK`/`XAHAU_NETWORK_ID` consistency, and the
  `X402_REDIS_URL` form. A **fatal** misconfig logs a structured error and exits
  non-zero (fail fast); a **non-fatal** gap (e.g. `XAHAU_WSS` unset → `/settle`
  disabled) logs a warning and runs on. Validation runs only in `serve()`, never at
  import.

## x402 spec compliance (and intentional divergences)

Field names follow the x402 facilitator interface (source:
[docs.payai.network/x402/reference §7](https://docs.payai.network/x402/reference),
corroborated by [docs.x402.org/core-concepts/facilitator](https://docs.x402.org/core-concepts/facilitator)
and the x402 OpenAPI `VerifyResponse`/`SettleResponse` shapes). Changes are
**additive and non-breaking** — every field the tests already assert is retained:

- **`GET /supported`** → `{ kinds: [{ x402Version: 2, scheme: "exact", network }] }`
  (added the spec's `x402Version` alongside the original `{scheme, network}`).
- **`POST /verify`** → spec requires `{ isValid, invalidReason?, payer }` — already
  present and unchanged.
- **`POST /settle`** → spec requires `{ success, transaction, network, payer,
  errorReason? }`. **Added `payer`** (the signature-bound `tx.Account`) and ensured
  `transaction` is always present (empty string on failure, per spec) on every
  settlement result, alongside the exact-xahau extras (`delivered`,
  `guardrailHookPresent`, and the idempotency flags `replayed`/`inFlight`/`retryable`).

**Documented divergences** (exact-xahau is a *proposed* x402 scheme for Xahau, not
EVM/SVM): `network` is the bare string `"xahau"` (not a CAIP-2 id like
`eip155:8453`); the payment payload is a **raw signed Xahau transaction blob** (not
an EIP-3009 `transferWithAuthorization` or a Solana partially-signed tx); and the
`guardrailHookPresent`/`delivered`/idempotency fields are exact-xahau extensions
not present in the canonical schema.

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
  for the on-ledger window expiry) and a shared **token-bucket** rate limiter
  (Upgrade #4). The limiter is an atomic Redis **Lua script** (`EVAL`): per IP it
  stores `{tokens, ts}`, refills `max` tokens per `windowMs` by elapsed time
  (clamped at `max`; a backwards clock adds nothing), consumes 1 per request, and
  returns allow/deny + a reset hint — a true continuous-refill bucket matching the
  in-memory limiter's model, with **no fixed-window 2×max boundary burst**. Tokens
  are integer fixed-point to avoid Lua float drift; the bucket key TTLs out when
  idle. If `EVAL` itself fails (e.g. a Redis build without scripting), the limiter
  **fails CLOSED** (denies) rather than allowing unbounded traffic. This closes the
  multi-instance / durability gap. `ioredis` is an **optional** dependency,
  lazy-loaded only when `X402_REDIS_URL` is set; if it is set but `ioredis` is
  missing the server **fails fast at boot** rather than silently falling back to a
  non-shared store (which would reopen replay across instances).

**Proxy-aware rate-limit key (Upgrade #4).** Both `/verify` and `/settle` key the
limiter off a `clientIp(req)` helper governed by `X402_TRUST_PROXY` (number of
trusted proxy/LB hops). At the default `0`, `X-Forwarded-For` is **never** trusted
(it is client-spoofable) and the direct socket peer address is used. With `n>0`, the
client IP is the `(n+1)`-th entry from the **right** of `X-Forwarded-For` (strip `n`
trusted hops), falling back to the socket address if the header is missing/short/
malformed. This avoids both failure modes: keying off the socket alone throttles
every client behind a proxy as one IP, while blindly trusting `XFF` lets a client
forge its limiter identity. Set `X402_TRUST_PROXY` to the **exact** hop count you
control.

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
Redis backend (`X402_REDIS_URL`) for a durable, shared deployment. **RegularKey**
and **multisig (`Signers`)** signatures cannot be validated **offline** (so `/verify`
reports `signatureVerified:false`); at `/settle` they are checked **on-ledger**
(RegularKey match / SignerList quorum) and either rejected pre-submit or settled with
`signatureVerified:true` + a `signatureSource`, with the **ledger remaining the
ultimate authority** (the on-ledger check fails closed to ledger authority on a node
read error). Not audited.

**Issued-amount caveats (honest):** the exact token comparator is sound over the full
XRPL token range, but a few issued-amount edge cases are intentionally **out of
scope** and rejected rather than guessed: values needing **>16 significant digits**
are rejected (not truncated to fit XRPL precision); the facilitator does **not** check
trust lines, issuer freeze/`NoRipple`, or path-dependent delivery — it verifies the
signed `Amount`/`delivered_amount` shape + value, and (as for native) relies on the
on-chain settle (and the payer's guardrail Hook) as the spending/settlement authority.
A `tfPartialPayment` IOU is rejected for the same reason as native (delivered could be
far less than `Amount`).
