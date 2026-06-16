#!/usr/bin/env node
/**
 * exact-xahau — a reference x402 facilitator for Xahau (hardened).
 *
 * Implements the x402 facilitator surface for the proposed `exact-xahau` scheme
 * (see ../docs/X402-XAHAU.md):
 *   GET  /supported  -> advertise {kinds:[{x402Version:2, scheme:"exact", network:"xahau"}]}
 *   POST /verify     -> offline checks on a signed Xahau Payment vs the requirements
 *   POST /settle     -> submit the signed tx to Xahau (needs XAHAU_WSS)
 *   GET  /health     -> liveness JSON. UNAUTHENTICATED callers get a minimal
 *                       { status, network, uptimeSec } (LB liveness). Sensitive
 *                       internals (backends, redis/xrpl connectivity, networkID,
 *                       replayBindings) are returned ONLY to an authenticated caller
 *                       (shared secret, same as /settle). Cheap, never throws.
 *   GET  /metrics    -> counters as JSON, or Prometheus text on Accept: text/plain.
 *                       AUTH-GATED behind the shared secret (401 otherwise; open in
 *                       reference mode when no SHARED_SECRET is configured).
 *
 * x402 SPEC ALIGNMENT (non-breaking; originals retained): /verify returns the
 * spec's {isValid, invalidReason?, payer}; /settle returns {success, transaction,
 * network, payer, errorReason?} — `payer` and a (possibly empty) `transaction` are
 * now always present, alongside the original exact-xahau extras (delivered,
 * guardrailHookPresent, replayed/inFlight/retryable). /supported uses the spec's
 * {kinds:[{x402Version, scheme, network}]} discovery shape. INTENTIONAL DIVERGENCES
 * from canonical x402 (exact-xahau is a PROPOSED scheme for Xahau): `network` is the
 * bare string "xahau" (not a CAIP-2 id); the payment payload is a raw signed Xahau
 * tx blob (not an EIP-3009 authorization); and the extra fields above are additive.
 *
 * OPERATIONAL HARDENING: dependency-free structured logging (JSON lines -> stderr,
 * no secrets/blobs/signatures), accurate metrics counters (incremented on REAL
 * events only — no PII), a RESILIENT xrpl client (reconnect-on-disconnect + bounded
 * connect timeout + bounded backoff, fail-closed — never an unbounded in-request
 * retry), boot-time config validation (fail-fast on a fatal misconfig; warn on a
 * non-fatal gap), and graceful shutdown (SIGTERM/SIGINT -> stop accepting, drain
 * in-flight within a bounded budget, close xrpl+Redis, exit). Signal handlers and
 * config-exit are attached ONLY inside serve(), never at import.
 *
 * Threat model: hostile clients. Every check is enforced; absence of a bound is
 * treated as a FAILURE, never a skip. Signatures are cryptographically verified.
 * The payer's on-chain xahc **guardrail Hook** is the L1 spending authority, but
 * the facilitator (a) honestly reports whether that Hook is actually installed and
 * (b) re-validates everything at /settle and checks delivered_amount — it never
 * trusts that /verify was called, and it refuses to settle the same payment twice.
 *
 * The replay store and the rate limiter are INJECTABLE behind a small ASYNC
 * interface. The DEFAULT backends are in-memory (zero extra deps): a bounded replay
 * store + a single-process token bucket — reference-grade, NOT shared across
 * instances and NOT durable across restarts (the long-standing production gap). An
 * OPTIONAL Redis backend (gated on env X402_REDIS_URL, lazy-loading `ioredis`)
 * closes that gap with a SHARED, DURABLE store + a shared limiter; if X402_REDIS_URL
 * is set but `ioredis` is missing the server FAILS FAST at boot rather than silently
 * falling back to a non-shared store (which would reopen replay across instances).
 *
 * Whichever backend is active, the replay store is REPLAY-SAFE and the SAME security
 * properties hold: reserve() is an ATOMIC test-and-set (in-memory: check-then-set on
 * the single-threaded event loop; Redis: SET NX PX) so two concurrent / multi-
 * instance settles of the same payment can't BOTH win; each binding's expiry is tied
 * to the tx's actual on-ledger validity window (Hole 1 — a binding never expires
 * while its tx is still submittable); settle rejects any tx whose window exceeds the
 * bound; and the hard cap is fail-CLOSED (only EXPIRED entries reclaimed; refuses new
 * reservations with 503 when full of live ones — never evicts a live binding, Hole 2).
 * A submit that fails AMBIGUOUSLY (LastLedgerSequence passed mid-wait / disconnect /
 * timeout) RETAINS the reservation and stores NO receipt — only a provably-not-applied
 * preliminary `tem*` result releases it, so a maybe-applied tx can never be settled
 * twice. settle is also IDEMPOTENT: terminal outcomes (tesSUCCESS, or an on-ledger
 * failure that spent the sequence) memoize a receipt keyed by the replay id; a retry
 * returns that receipt (replayed:true) — never a re-submit — while an in-flight /
 * ambiguous payment returns "already consumed" (inFlight:true) with no fabricated
 * receipt. Both public POST paths (/verify and /settle) are rate-limited; /settle,
 * /metrics, and the VERBOSE form of /health additionally require the shared secret.
 * A pre-submit replay-store outage (Redis down on isConsumed/getReceipt/reserve) is
 * caught and surfaced as a RETRYABLE 503 (fail-CLOSED — never proceeds to submit),
 * not an opaque 500. The HTTP server is bounded against slowloris/flood: a request/
 * headers timeout caps how long a slow client may drip a request, maxConnections caps
 * concurrent sockets, and graceful shutdown closes idle keep-alive sockets so a slow
 * client can't ride out the drain budget (all applied in serve(), never at import).
 * Signatures: a master-key single-sig is bound OFFLINE (deriveAddress == Account ->
 * signatureVerified:true). RegularKey + multisig (Signers) are offline-unverifiable
 * (verify reports signatureVerified:false), but at SETTLE — where a node connection
 * exists — they get a POSITIVE on-ledger authorization check (#3): RegularKey match
 * (account_info.RegularKey == deriveAddress(SigningPubKey)) / multisig SignerList
 * quorum (per-signer multisigning-data verify + on-ledger weight sum >= quorum).
 * That check may only REJECT pre-submit or UPGRADE confidence (signatureVerified:true
 * + signatureSource); it FAILS CLOSED to ledger authority on any node-read error and
 * never fabricates authorization. The rate-limit key is proxy-aware (#4): X402_TRUST_
 * PROXY hops control whether X-Forwarded-For is trusted (default 0 = socket addr only,
 * never trust a spoofable XFF); the Redis limiter is an atomic Lua token bucket.
 *
 * ASSETS: both native XAH and ISSUED amounts (IOU / tokens) are supported. The x402
 * paymentRequirements carry an optional `asset` field: when ABSENT the payment is
 * native XAH (Amount is a drops string — the original behavior, byte-for-byte
 * unchanged); when PRESENT it is { currency, issuer } and the payment must be exactly
 * that token (Amount is an object { currency, issuer, value }, maxAmountRequired is a
 * decimal value string in the token's units). Token value comparison is EXACT — a
 * self-contained BigInt decimal comparator (mantissa+exponent, no JS float anywhere),
 * sound over the full XRPL token range; a float compare would wrongly accept an
 * under/over-payment (e.g. it collapses 2^53+1 and 2^53). Currency codes are
 * canonicalized so the 3-char ASCII and 40-hex forms of the same code match. /settle
 * checks delivered_amount as an issued-amount object for an IOU (currency+issuer match
 * + value >= required, exact compare), failing closed on a wrong-type/wrong-asset
 * delivered_amount.
 */
import http from "node:http";
import crypto from "node:crypto";
import { decode } from "xahau-binary-codec";

const PORT = process.env.PORT || 4021;
export const NETWORK = "xahau";

// NetworkID per the exact-xahau scheme (X402-XAHAU.md).
const NETWORK_IDS = { xahau: 21337, "xahau-testnet": 21338 };
export const EXPECTED_NETWORK_ID =
  Number(process.env.XAHAU_NETWORK_ID) || NETWORK_IDS[process.env.XAHAU_NETWORK || "xahau"] || 21337;

// tfPartialPayment — a partial payment can deliver far less than Amount.
const TF_PARTIAL_PAYMENT = 0x00020000;
// XAH total supply ceiling in drops, used as a sanity upper bound on amounts.
const MAX_DROPS = 100_000_000_000n * 1_000_000n; // 100e9 XAH * 1e6 drops
const STRICT_DROPS = /^[0-9]+$/;

const MAX_BODY_BYTES = 64 * 1024;
const SHARED_SECRET = process.env.X402_SHARED_SECRET || "";

// Process start time (epoch ms) for /health uptime. Set at module load.
const BOOT_TS = Date.now();

// ---------------------------------------------------------------------------
// structured logging (dependency-free JSON lines -> stderr)
// ---------------------------------------------------------------------------
// One JSON object per line: { ts, level, event, ...fields }. stderr is the sink
// (stdout stays clean for any future machine output). NEVER log secrets, full tx
// blobs, signatures, or PII (addresses/amounts): callers pass only safe fields
// (event name, error code/class, counts). `level` is honest: error/warn/info.
function log(level, event, fields = {}) {
  try {
    const rec = { ts: new Date().toISOString(), level, event, ...fields };
    process.stderr.write(JSON.stringify(rec) + "\n");
  } catch {
    // Logging must never throw into a request path. Last-resort: a bare line.
    try { process.stderr.write(`{"level":"${level}","event":"${event}"}\n`); } catch { /* give up */ }
  }
}
const logInfo = (event, fields) => log("info", event, fields);
const logWarn = (event, fields) => log("warn", event, fields);
const logError = (event, fields) => log("error", event, fields);

// ---------------------------------------------------------------------------
// metrics (dependency-free counters; incremented on REAL events only)
// ---------------------------------------------------------------------------
// A flat counter map. Each counter moves ONLY when its underlying event happens
// (wired at the exact code points). No PII is ever stored here — only counts.
// `settle_rejected_*` break the rejected total down by cause bucket. Exposed as
// JSON (default) or Prometheus text (Accept: text/plain) by GET /metrics.
const metrics = {
  verify_total: 0,
  settle_total: 0,
  settle_success: 0,
  settle_replayed: 0,
  settle_rejected: 0,
  // rejected breakdown (sum of these == settle_rejected):
  settle_rejected_verify_failed: 0,
  settle_rejected_replay_inflight: 0,
  settle_rejected_store_full: 0,
  settle_rejected_submit_ambiguous: 0,
  settle_rejected_tem_rejected: 0,
  settle_rejected_on_ledger_failure: 0,
  settle_rejected_delivered_short: 0,
  settle_rejected_other: 0,
  rate_limited_total: 0,
  body_too_large_total: 0,
};
function metricInc(name, by = 1) {
  if (Object.prototype.hasOwnProperty.call(metrics, name)) metrics[name] += by;
}
// Map a settle reject reason to its bucket counter + bump the rejected total.
// Buckets are derived from the structured settle outcome, never from PII. An
// unrecognized reason lands in `_other` so the breakdown always sums to the total.
function recordSettleReject(bucket) {
  metricInc("settle_rejected");
  const key = `settle_rejected_${bucket}`;
  if (Object.prototype.hasOwnProperty.call(metrics, key)) metricInc(key);
  else metricInc("settle_rejected_other");
}
// Render the counters as Prometheus exposition text (counters only).
function metricsPrometheus() {
  const lines = [];
  for (const [k, v] of Object.entries(metrics)) {
    const name = `x402_${k}`;
    lines.push(`# TYPE ${name} counter`);
    lines.push(`${name} ${v}`);
  }
  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
function send(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(b) });
  res.end(b);
}

// Sentinel marking a request the body-reader has already responded to (e.g. it
// sent a clean 413). The request handler must NOT send a second response.
const ALREADY_RESPONDED = Symbol("x402.alreadyResponded");

/**
 * Read+parse a JSON body, capped at MAX_BODY_BYTES.
 *
 * On oversize, send a clean 413 response and stop consuming the body — do NOT
 * req.destroy() the socket (that gives the client an ECONNRESET, not a 413).
 * We pause the stream, send 413, and on the next event reject with a sentinel so
 * the caller knows a response was already written (no double-response/crash).
 */
function readBody(req, res) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    req.on("data", (c) => {
      if (settled) return;
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        settled = true;
        // Respond cleanly with 413 instead of resetting the socket. We must keep
        // DRAINING the rest of the inbound body to /dev/null — if the server
        // stops reading while the client is still writing, the OS sends a TCP RST
        // and the client sees ECONNRESET instead of our 413. `Connection: close`
        // tells the client this socket won't be reused, so it closes gracefully
        // after reading the response.
        metricInc("body_too_large_total");
        log("warn", "body_too_large", { limitBytes: MAX_BODY_BYTES });
        if (res && !res.headersSent) {
          const b = JSON.stringify({ error: "request body too large" });
          res.writeHead(413, {
            "content-type": "application/json",
            "content-length": Buffer.byteLength(b),
            "connection": "close",
          });
          res.end(b);
        }
        // Discard remaining inbound data so 'end'/'close' fires without an RST.
        req.on("data", () => {});
        req.on("end", () => {});
        req.resume();
        reject(ALREADY_RESPONDED);
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (settled) return;
      settled = true;
      const d = Buffer.concat(chunks).toString("utf8");
      try { resolve(d ? JSON.parse(d) : {}); }
      catch { const err = new Error("invalid JSON"); err.statusCode = 400; reject(err); }
    });
    req.on("error", (e) => { if (!settled) { settled = true; reject(e); } });
  });
}

/** Validate an XRPL/Xahau classic r-address. Lazy-loads ripple-address-codec. */
let _isValidAddress = null;
function isValidRAddress(addr) {
  if (typeof addr !== "string" || addr.length === 0) return false;
  if (_isValidAddress === null) {
    try {
      // ripple-address-codec ships transitively with the codec; load once.
      const m = require_("xahau-address-codec");
      _isValidAddress = m.isValidClassicAddress;
    } catch {
      _isValidAddress = false;
    }
  }
  if (typeof _isValidAddress === "function") return _isValidAddress(addr);
  // Fallback: structural check if the codec lib is unavailable.
  return /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(addr);
}

// CJS require shim usable from ESM (these deps are CJS).
import { createRequire } from "node:module";
const require_ = createRequire(import.meta.url);

/**
 * Strict native-XAH drops parser. Returns a bigint in (0, MAX_DROPS], or null if
 * the value is not a plain decimal-digit string in range. Rejects hex, negative,
 * empty, leading-zero-only-padding-is-fine, and out-of-range.
 */
function parseStrictDrops(value) {
  if (typeof value !== "string" || !STRICT_DROPS.test(value)) return null;
  let n;
  try { n = BigInt(value); } catch { return null; }
  if (n <= 0n || n > MAX_DROPS) return null;
  return n;
}

// ---------------------------------------------------------------------------
// issued-amount (IOU / token) support
// ---------------------------------------------------------------------------
// XRPL/Xahau token amounts are base-10 floats with a 54-bit mantissa normalized
// to [1e15, 1e16) and an exponent in [-96, 80] — i.e. up to ~16 significant
// decimal digits over a very wide magnitude range. Comparing two such values with
// JS `Number`/parseFloat is UNSOUND: doubles carry only ~15-17 significant digits
// and cannot represent many decimal fractions exactly, so a compare can wrongly
// accept an under/over-payment. This is security-critical for a payment facilitator.
//
// APPROACH (b) — self-contained EXACT decimal comparator over BigInt. We parse each
// decimal `value` string into a sign + an integer mantissa + a base-10 exponent
// (mant * 10^exp, no fraction lost), then compare two values by aligning exponents
// with BigInt powers of ten. BigInt is arbitrary-precision, so the alignment +
// compare is EXACT for the entire XRPL token range (and beyond) — there is no float
// anywhere on the path. We chose this over porting XFL parse/encode because the
// inputs here are already decimal STRINGS (XFL's enbase-10 packing buys us nothing
// for a string<->string compare, and its normalization TRUNCATES the 16th+ digit,
// which we must NOT do when validating a client's stated value). The validator also
// enforces the XRPL token bounds so a malformed/out-of-range value is rejected, not
// silently compared.
//
// Range bounds mirror XRPL's IOU representation (see xfl.ts): a non-zero value's
// normalized exponent must be within [-96, 80]; combined with up to 16 significant
// mantissa digits, the smallest positive value is ~1e-96 and the largest ~9.999...e95.
const TOKEN_EXP_MIN = -96;
const TOKEN_EXP_MAX = 80;
const TOKEN_MAX_MANT_DIGITS = 16; // XRPL mantissa precision (normalized [1e15,1e16))

/**
 * Parse a decimal token `value` string EXACTLY into { sign, mant, exp } such that
 * the value == sign * mant * 10^exp, with `mant` a non-negative BigInt (no fraction
 * lost). Returns null if the string is not a well-formed, in-range, POSITIVE token
 * value. Hostile-input rule: anything we cannot represent exactly and in range is
 * rejected (null), never coerced.
 *
 * Accepted grammar (a strict subset of XRPL's, sufficient for x402 prices):
 *   [whitespace-free] digits, optional single '.', optional exponent e/E[+/-]digits.
 *   Examples: "1", "1.0", "0.000001", "100", "1.5", "1e3", "2.5E-4".
 * Rejected: empty, sign-prefixed ('+'/'-' -> not positive), hex, NaN/Inf, multiple
 *   dots, value <= 0, or a value whose normalized base-10 exponent falls outside
 *   [TOKEN_EXP_MIN, TOKEN_EXP_MAX], or with more than TOKEN_MAX_MANT_DIGITS
 *   significant digits (more precision than XRPL can hold -> reject, don't truncate).
 */
function parseTokenValue(value) {
  if (typeof value !== "string" || value.length === 0) return null;
  // Strict: optional digits with at most one dot, optional decimal exponent. No sign
  // (must be positive), no spaces, no hex, no leading '+'.
  const m = /^([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(value);
  if (!m) return null;
  const intPart = m[1];
  const fracPart = m[2] || "";
  const expPart = m[3];
  let exp10;
  try { exp10 = expPart != null ? Number(expPart) : 0; } catch { return null; }
  if (!Number.isFinite(exp10) || !Number.isInteger(exp10)) return null;

  // Combine int+frac into a single integer mantissa string; the fractional digit
  // count shifts the exponent down (mant * 10^(exp10 - fracLen)).
  let digits = intPart + fracPart;
  let exp = exp10 - fracPart.length;

  // Strip leading zeros from the mantissa (exact: leading zeros carry no value).
  digits = digits.replace(/^0+/, "");
  if (digits === "") return null; // value is exactly zero -> not a positive payment value

  // Strip trailing zeros, folding them into the exponent (keeps mant minimal +
  // canonical so "1.0", "1", "1e0", "10e-1" all parse to the same {mant,exp}).
  let trailing = 0;
  for (let i = digits.length - 1; i > 0 && digits[i] === "0"; i--) trailing++;
  if (trailing > 0) { digits = digits.slice(0, digits.length - trailing); exp += trailing; }

  // Significant-digit (precision) bound: XRPL can hold at most ~16 significant digits.
  // A value needing more precision than that is NOT exactly representable on-ledger,
  // so reject rather than silently round.
  if (digits.length > TOKEN_MAX_MANT_DIGITS) return null;

  let mant;
  try { mant = BigInt(digits); } catch { return null; }
  if (mant <= 0n) return null;

  // Normalized-exponent range check, mirroring XRPL/XFL: normalize the mantissa to
  // [1e15, 1e16) and require the resulting exponent within [-96, 80]. We compute the
  // normalized exponent without mutating our exact {mant, exp} (used for compare).
  const normExp = exp + (digits.length - TOKEN_MAX_MANT_DIGITS);
  if (normExp < TOKEN_EXP_MIN || normExp > TOKEN_EXP_MAX) return null;

  return { sign: 1, mant, exp };
}

/**
 * Exact signed comparison of two parsed token values a,b (each { sign:1, mant, exp }
 * from parseTokenValue — both positive here). Returns -1 if a<b, 0 if equal, 1 if a>b.
 * Aligns the two mantissas to a common exponent using BigInt powers of ten (exact,
 * no float) and compares the resulting integers.
 */
function cmpTokenValue(a, b) {
  // Align to the lower exponent so both become integers in the same base-10 unit.
  const e = a.exp < b.exp ? a.exp : b.exp;
  const ma = a.mant * 10n ** BigInt(a.exp - e);
  const mb = b.mant * 10n ** BigInt(b.exp - e);
  if (ma === mb) return 0;
  return ma > mb ? 1 : -1;
}

/**
 * Canonicalize an XRPL/Xahau currency code to a comparable 40-hex (20-byte) string.
 * Accepts either the 3-character ASCII form (e.g. "USD") or the 40-char hex form;
 * the codec decodes standard codes back to 3-char ASCII and non-standard codes as
 * 40-hex, while a server may supply asset.currency in EITHER form — so we map both
 * to one canonical 40-hex value before comparing. Returns the uppercase 40-hex
 * string, or null if the input is malformed.
 *
 * Standard 3-char ASCII codes map to the 20-byte layout with the ASCII bytes at
 * offset 12..14 and all other bytes zero (the XRPL standard-currency encoding) — the
 * same canonical form the codec produces internally. "XRP" is rejected as a token
 * currency (it is native, not an issued asset).
 */
function canonicalizeCurrency(cur) {
  if (typeof cur !== "string" || cur.length === 0) return null;
  if (/^[0-9a-fA-F]{40}$/.test(cur)) {
    const hex = cur.toUpperCase();
    // The all-zero code is XRP/native, never a valid issued-asset currency.
    if (/^0{40}$/.test(hex)) return null;
    return hex;
  }
  // 3-char ASCII standard code. XRPL standard codes are exactly 3 chars; "XRP" is
  // reserved for native and is invalid as an issued currency.
  if (cur.length === 3 && /^[\x20-\x7E]{3}$/.test(cur)) {
    if (cur === "XRP") return null;
    const b = Buffer.alloc(20, 0);
    b.write(cur, 12, "ascii");
    return b.toString("hex").toUpperCase();
  }
  return null;
}

/**
 * Validate a decoded tx Amount that is expected to be an ISSUED amount object
 * { currency, issuer, value } against the required asset + max value. Returns
 * { value } (the parsed {sign,mant,exp}) on success, or { error } on failure.
 * Performs: type/shape check, currency canonicalization + match, issuer match,
 * value well-formedness + range, and value <= maxTokenValue (exact).
 */
function checkIssuedAmount(amount, asset, maxTokenValue) {
  if (amount === null || typeof amount !== "object" || Array.isArray(amount))
    return { error: "Amount must be an issued-amount object for this asset" };
  if (typeof amount.currency !== "string" || typeof amount.issuer !== "string" || typeof amount.value !== "string")
    return { error: "Amount issued-amount object malformed (currency/issuer/value)" };

  const wantCur = canonicalizeCurrency(asset.currency);
  const gotCur = canonicalizeCurrency(amount.currency);
  if (wantCur === null) return { error: "asset.currency malformed" };
  if (gotCur === null || gotCur !== wantCur)
    return { error: "Amount.currency != asset.currency" };
  if (!isValidRAddress(amount.issuer)) return { error: "Amount.issuer malformed" };
  if (amount.issuer !== asset.issuer) return { error: "Amount.issuer != asset.issuer" };

  const v = parseTokenValue(amount.value);
  if (v === null) return { error: "Amount.value malformed or out of token range" };
  if (cmpTokenValue(v, maxTokenValue) > 0)
    return { error: "Amount.value > maxAmountRequired" };
  return { value: v };
}

// ---------------------------------------------------------------------------
// FEATURE 2 — verifiable signed receipts (ed25519, offline-verifiable)
// ---------------------------------------------------------------------------
// Every SUCCESSFUL settlement is signed by the facilitator over a CANONICAL,
// deterministic byte-serialization of the receipt's load-bearing fields, so a
// resource server can verify the receipt OFFLINE with just the facilitator's
// public key (GET /pubkey). Only tesSUCCESS+delivered>=required settlements are
// signed; a failed/rejected/replayed-failure settle carries proof:null.
//
// Signing key: ed25519 via node crypto (zero new deps). Sourced from env
// X402_RECEIPT_SECRET (a 32-byte seed, hex or base64). If unset, an EPHEMERAL
// keypair is generated at boot and a clear WARNING is logged — receipts won't
// persist across restarts (resource servers must re-fetch /pubkey). The secret /
// private key is NEVER logged.
//
// CANONICAL BYTES RECIPE (the verifier MUST reconstruct these exact bytes):
//   1. Build the object { v, network, txHash, payer, payTo, asset, delivered,
//      required, ts } using EXACTLY these keys (omit none; an absent value is the
//      JSON literal null, never undefined-dropped).
//   2. JSON.stringify with keys sorted ascending and NO whitespace
//      (canonicalJSONStringify below: deterministic key order, recursive).
//   3. UTF-8 encode -> those are the signed bytes.
//   The signature is ed25519 over those bytes; pubkey is the raw 32-byte key as
//   lowercase hex. proof = { alg:"ed25519", pubkey, sig } (sig = hex).

// ASN.1 prefix for a PKCS#8-wrapped raw ed25519 seed (RFC 8410). Prepending this
// to a 32-byte seed yields a DER PKCS#8 private key node crypto can import.
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/**
 * Deterministic, canonical JSON serialization: object keys sorted ascending at
 * every level, arrays in order, no whitespace. This is the LOAD-BEARING contract
 * a verifier reconstructs — it must be stable regardless of insertion order. We
 * intentionally support only the JSON value types a receipt uses (object, array,
 * string, number, boolean, null); a non-finite number or undefined is rejected
 * (throws) rather than silently producing bytes a verifier can't reproduce.
 */
function canonicalJSONStringify(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) throw new Error("canonicalJSON: non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJSONStringify).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJSONStringify(value[k])).join(",") + "}";
  }
  throw new Error(`canonicalJSON: unsupported type ${t}`);
}

/**
 * Project a receipt to the canonical, signable payload. EXACTLY these keys, in a
 * fixed shape — both the signer and any verifier build this same projection so the
 * canonical bytes match. `delivered`/`asset` may be null (native vs IOU); we keep
 * the key present with a null value rather than dropping it, so the shape is fixed.
 */
function receiptSignablePayload({ network, txHash, payer, payTo, asset, delivered, required, ts }) {
  return {
    v: 1,
    network: network ?? null,
    txHash: txHash ?? null,
    payer: payer ?? null,
    payTo: payTo ?? null,
    asset: asset ?? null,
    delivered: delivered ?? null,
    required: required ?? null,
    ts: ts ?? null,
  };
}

// Lazily-built ed25519 signing key (private + raw-hex public). Null until init.
let _receiptKey = null;       // { privateKey: KeyObject, pubHex: string }
let _receiptKeyEphemeral = false;

/**
 * Build a node-crypto ed25519 private KeyObject from a 32-byte seed.
 * Returns the KeyObject, or null if the seed is the wrong size / unparseable.
 */
function ed25519KeyFromSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) return null;
  try {
    const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
    return crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  } catch { return null; }
}

/** Raw 32-byte public key (lowercase hex) for an ed25519 private/public KeyObject. */
function ed25519PubHex(keyObject) {
  const pub = keyObject.type === "private" ? crypto.createPublicKey(keyObject) : keyObject;
  const jwk = pub.export({ format: "jwk" });
  return Buffer.from(jwk.x, "base64url").toString("hex");
}

/**
 * Parse X402_RECEIPT_SECRET (hex or base64/base64url) into a 32-byte seed Buffer,
 * or null if absent/malformed. NEVER logs the value.
 */
function parseReceiptSecret(raw) {
  if (typeof raw !== "string" || raw.length === 0) return null;
  const s = raw.trim();
  // hex (64 chars)?
  if (/^[0-9a-fA-F]{64}$/.test(s)) { try { return Buffer.from(s, "hex"); } catch { return null; } }
  // base64 / base64url -> 32 bytes?
  try {
    const b = Buffer.from(s, "base64");
    if (b.length === 32) return b;
  } catch { /* fall through */ }
  return null;
}

/**
 * Initialize the receipt signing key (idempotent). Uses X402_RECEIPT_SECRET when a
 * valid 32-byte seed is present; otherwise generates an EPHEMERAL key and logs a
 * clear WARNING (once). Returns { pubHex, ephemeral }. The private key is held in a
 * KeyObject and never serialized/logged. A malformed-but-present secret FAILS the
 * derivation and falls back to ephemeral with a distinct warning (never silently
 * uses a wrong key).
 */
function initReceiptKey(env = process.env) {
  if (_receiptKey) return { pubHex: _receiptKey.pubHex, ephemeral: _receiptKeyEphemeral };
  const seed = parseReceiptSecret(env.X402_RECEIPT_SECRET);
  if (seed) {
    const priv = ed25519KeyFromSeed(seed);
    if (priv) {
      _receiptKey = { privateKey: priv, pubHex: ed25519PubHex(priv) };
      _receiptKeyEphemeral = false;
      logInfo("receipt_key_loaded", { source: "env", alg: "ed25519" });
      return { pubHex: _receiptKey.pubHex, ephemeral: false };
    }
    // Present but unusable -> do NOT silently proceed with a wrong key; warn + ephemeral.
    logWarn("receipt_key_secret_invalid", { note: "X402_RECEIPT_SECRET set but not a valid 32-byte seed (hex/base64) — using an EPHEMERAL key" });
  } else if (typeof env.X402_RECEIPT_SECRET === "string" && env.X402_RECEIPT_SECRET.length > 0) {
    logWarn("receipt_key_secret_invalid", { note: "X402_RECEIPT_SECRET set but not a valid 32-byte seed (hex/base64) — using an EPHEMERAL key" });
  }
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  _receiptKey = { privateKey, pubHex: ed25519PubHex(privateKey) };
  _receiptKeyEphemeral = true;
  logWarn("receipt_key_ephemeral", { note: "no X402_RECEIPT_SECRET — receipts are signed with an EPHEMERAL key that changes on restart; resource servers must re-fetch /pubkey", alg: "ed25519" });
  return { pubHex: _receiptKey.pubHex, ephemeral: true };
}

/** The facilitator's receipt public key as { alg, pubkey } (raw 32-byte hex). */
function receiptPubkey() {
  const k = initReceiptKey();
  return { alg: "ed25519", pubkey: k.pubHex };
}

/**
 * Sign the canonical bytes of a receipt's signable payload. Returns the proof
 * object { alg:"ed25519", pubkey, sig } (both hex), or null if signing is
 * impossible (should not happen — key is always available after init). The bytes
 * signed are EXACTLY canonicalJSONStringify(receiptSignablePayload(fields)) in UTF-8.
 */
function signReceipt(fields) {
  try {
    initReceiptKey();
    const payload = receiptSignablePayload(fields);
    const bytes = Buffer.from(canonicalJSONStringify(payload), "utf8");
    const sig = crypto.sign(null, bytes, _receiptKey.privateKey);
    return { alg: "ed25519", pubkey: _receiptKey.pubHex, sig: sig.toString("hex") };
  } catch (e) {
    log("warn", "receipt_sign_failed", { error: String(e?.name || "sign_error") });
    return null;
  }
}

/**
 * OFFLINE receipt verification (exported for resource servers). Given a receipt that
 * carries `proof: { alg, pubkey, sig }`, reconstruct the canonical signable bytes
 * from the receipt's own fields and verify the ed25519 signature against the proof's
 * pubkey. Returns true iff the signature is valid for those exact bytes; false
 * otherwise (missing/malformed proof, tampered field, wrong key, bad sig). NEVER
 * throws. NOTE: this proves the BYTES were signed by the holder of `proof.pubkey`;
 * the caller must separately check that `proof.pubkey` is the facilitator's expected
 * key (from a trusted GET /pubkey fetch) — a valid sig under an UNKNOWN key is not
 * trust. We expose that as a soundness contract, not an implicit guarantee.
 */
export function verifyReceipt(receipt, { expectedPubkey } = {}) {
  try {
    if (!receipt || typeof receipt !== "object") return false;
    const proof = receipt.proof;
    if (!proof || typeof proof !== "object") return false;
    if (proof.alg !== "ed25519") return false;
    if (typeof proof.pubkey !== "string" || !/^[0-9a-fA-F]{64}$/.test(proof.pubkey)) return false;
    if (typeof proof.sig !== "string" || !/^[0-9a-fA-F]+$/.test(proof.sig) || proof.sig.length % 2 !== 0) return false;
    if (expectedPubkey !== undefined && proof.pubkey.toLowerCase() !== String(expectedPubkey).toLowerCase()) return false;
    // Reconstruct the signable payload from the RECEIPT's fields (the same projection
    // the signer used). A tampered field changes the bytes -> verification fails.
    const payload = receiptSignablePayload({
      network: receipt.network,
      txHash: receipt.txHash,
      payer: receipt.payer,
      payTo: receipt.payTo,
      asset: receipt.asset,
      delivered: receipt.delivered,
      required: receipt.required,
      ts: receipt.ts,
    });
    const bytes = Buffer.from(canonicalJSONStringify(payload), "utf8");
    const rawPub = Buffer.from(proof.pubkey, "hex");
    const pubKeyObj = crypto.createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: rawPub.toString("base64url") },
      format: "jwk",
    });
    return crypto.verify(null, bytes, pubKeyObj, Buffer.from(proof.sig, "hex"));
  } catch {
    return false; // any parse/crypto error -> NOT verified (never throw, never fabricate)
  }
}

/**
 * Cryptographically verify the tx blob's signature against its SigningPubKey
 * (single-sig) using the xrpl library. Returns true/false; null if xrpl is not
 * installed (caller decides how to treat "cannot verify").
 */
let _xrplVerify = undefined;
function verifyTxSignature(txBlob) {
  if (_xrplVerify === undefined) {
    try { _xrplVerify = require_("xahau").verifySignature; }
    catch { _xrplVerify = null; }
  }
  if (typeof _xrplVerify !== "function") return null;
  try { return _xrplVerify(txBlob) === true; }
  catch { return false; }
}

/**
 * Derive the classic r-address that owns a SigningPubKey. Used to bind a verified
 * signature to the tx's Account (xrpl.verifySignature only checks the sig against
 * the embedded SigningPubKey — NOT that the key belongs to the payer). Returns
 * the address string, or null if ripple-keypairs is unavailable / the key is
 * malformed.
 */
let _deriveAddress = undefined;
function deriveAddressFromPubKey(pubKey) {
  if (typeof pubKey !== "string" || pubKey.length === 0) return null;
  if (_deriveAddress === undefined) {
    try { _deriveAddress = require_("xahau-keypairs").deriveAddress; }
    catch { _deriveAddress = null; }
  }
  if (typeof _deriveAddress !== "function") return null;
  try { return _deriveAddress(pubKey); }
  catch { return null; }
}

/**
 * ripple-keypairs `verify(message, signature, publicKey)` — verifies a hex-encoded
 * signature over hex-encoded message bytes against a public key. Returns true/false;
 * null if ripple-keypairs is unavailable. A malformed signature/key THROWS inside
 * ripple-keypairs, which we catch and treat as a FAILED verification (false) — never
 * as "cannot verify". This is the primitive used to check each multisig Signer's
 * TxnSignature over the per-signer multisigning data.
 */
let _kpVerify = undefined;
function keypairVerify(messageHex, signatureHex, publicKeyHex) {
  if (_kpVerify === undefined) {
    try { _kpVerify = require_("xahau-keypairs").verify; }
    catch { _kpVerify = null; }
  }
  if (typeof _kpVerify !== "function") return null;
  try { return _kpVerify(messageHex, signatureHex, publicKeyHex) === true; }
  catch { return false; } // malformed sig/key -> NOT verified (fail closed)
}

/**
 * Codec `encodeForMultisigning(tx, signerAccount)` — reproduces the exact bytes a
 * multisig Signer signed (the tx serialized with the signer's account appended, per
 * the XRPL multisigning scheme). Returns the hex string, or null if the codec is
 * unavailable / the input is unencodable. Verified end-to-end: encoding the DECODED
 * tx with each Signer.Account reproduces the data ripple-keypairs.verify accepts
 * against that signer's SigningPubKey + TxnSignature.
 */
let _encodeForMultisigning = undefined;
function encodeForMultisigning(tx, signerAccount) {
  if (_encodeForMultisigning === undefined) {
    try { _encodeForMultisigning = require_("xahau-binary-codec").encodeForMultisigning; }
    catch { _encodeForMultisigning = null; }
  }
  if (typeof _encodeForMultisigning !== "function") return null;
  try { return _encodeForMultisigning(tx, signerAccount); }
  catch { return null; }
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------
/**
 * Offline verification of an `exact-xahau` payload.
 * payload: { txBlob }  — a signed Xahau Payment
 * req:     { payTo, maxAmountRequired, network, maxTimeoutSeconds }
 *
 * Hostile-client rule: a check is NEVER skipped because its bound is absent.
 * Missing/empty/malformed requirements => isValid:false.
 */
export function verifyExact(payload, req) {
  if (!payload || typeof payload.txBlob !== "string" || payload.txBlob.length === 0)
    return { isValid: false, invalidReason: "missing txBlob" };

  // (1) Requirements must be complete BEFORE we trust any per-field check.
  if (!req || typeof req !== "object")
    return { isValid: false, invalidReason: "incomplete payment requirements" };
  if (!isValidRAddress(req.payTo))
    return { isValid: false, invalidReason: "incomplete payment requirements (payTo missing/invalid)" };

  // FEATURE 3 — x402 `scheme` ("exact" | "upto"). When ABSENT, the DEFAULT preserves
  // TODAY's exact-xahau behavior byte-for-byte: paid <= maxAmountRequired (a ceiling).
  // "exact" => paid MUST EQUAL maxAmountRequired (strict, both native + IOU exact).
  // "upto"  => paid <= maxAmountRequired (the legacy default behavior, made explicit).
  // Any other scheme value is rejected (hostile-input rule: never coerce an unknown
  // scheme to a weaker check). NOTE the semantics: the legacy default is mathematically
  // identical to "upto" (a max ceiling); we keep ABSENT distinct in NAME only for
  // back-compat documentation, but it enforces the same <= bound as "upto".
  let scheme = "upto"; // default == legacy ceiling behavior
  if (req.scheme !== undefined && req.scheme !== null) {
    if (req.scheme !== "exact" && req.scheme !== "upto")
      return { isValid: false, invalidReason: "incomplete payment requirements (unknown scheme; expected 'exact' or 'upto')" };
    scheme = req.scheme;
  }

  // Asset selection: when req.asset is present this is an ISSUED-AMOUNT (IOU/token)
  // payment; when absent it is native XAH (today's behavior, UNCHANGED). For an IOU
  // the asset must be a well-formed { currency, issuer } and maxAmountRequired is a
  // token VALUE string (same units as the token), validated like Amount.value.
  let asset = null;
  let maxDrops = null;        // native path: bigint drops
  let maxTokenValue = null;   // IOU path: parsed {sign,mant,exp}
  if (req.asset !== undefined && req.asset !== null) {
    const a = req.asset;
    if (typeof a !== "object" || Array.isArray(a) || typeof a.currency !== "string" || typeof a.issuer !== "string")
      return { isValid: false, invalidReason: "incomplete payment requirements (asset malformed)" };
    const canonCur = canonicalizeCurrency(a.currency);
    if (canonCur === null)
      return { isValid: false, invalidReason: "incomplete payment requirements (asset.currency invalid)" };
    if (!isValidRAddress(a.issuer))
      return { isValid: false, invalidReason: "incomplete payment requirements (asset.issuer invalid)" };
    asset = { currency: a.currency, issuer: a.issuer };
    maxTokenValue = parseTokenValue(req.maxAmountRequired);
    if (maxTokenValue === null)
      return { isValid: false, invalidReason: "incomplete payment requirements (maxAmountRequired missing/invalid token value)" };
  } else {
    maxDrops = parseStrictDrops(req.maxAmountRequired);
    if (maxDrops === null)
      return { isValid: false, invalidReason: "incomplete payment requirements (maxAmountRequired missing/invalid)" };
  }

  let tx;
  try { tx = decode(payload.txBlob); } catch { return { isValid: false, invalidReason: "undecodable txBlob" }; }

  if (tx.TransactionType !== "Payment")
    return { isValid: false, invalidReason: "not a Payment" };

  // (5b) NetworkID must match the expected network — block cross-network replay.
  if (tx.NetworkID == null || Number(tx.NetworkID) !== EXPECTED_NETWORK_ID)
    return { isValid: false, invalidReason: `NetworkID != ${EXPECTED_NETWORK_ID}` };

  if (tx.Destination !== req.payTo)
    return { isValid: false, invalidReason: "Destination != payTo" };

  // (5a) Reject partial payments outright — delivered amount could be ~0.
  const flags = Number(tx.Flags || 0);
  if (flags & TF_PARTIAL_PAYMENT)
    return { isValid: false, invalidReason: "tfPartialPayment not allowed" };

  // Amount check. Two mutually-exclusive shapes, keyed off whether req.asset is set:
  //   - native XAH (asset absent): Amount is a drops STRING (UNCHANGED behavior).
  //   - issued amount (asset present): Amount is an OBJECT {currency,issuer,value}.
  // A mismatch between the required asset and the Amount's shape is rejected in BOTH
  // directions (native-required but Amount is an object; IOU-required but Amount is a
  // string) — a hostile client cannot substitute one asset class for the other.
  let paid = null;          // native: bigint drops (kept for downstream code paths)
  let paidTokenValue = null; // IOU: parsed {sign,mant,exp}
  if (asset === null) {
    // Native XAH path — byte-for-byte the original logic.
    if (typeof tx.Amount !== "string")
      return { isValid: false, invalidReason: "asset mismatch: native XAH required but Amount is an issued amount" };
    paid = parseStrictDrops(tx.Amount);
    if (paid === null)
      return { isValid: false, invalidReason: "Amount malformed (must be positive drops string)" };
    // "upto"/default: paid <= max (ceiling). "exact": paid MUST EQUAL max.
    if (paid > maxDrops)
      return { isValid: false, invalidReason: "Amount > maxAmountRequired" };
    if (scheme === "exact" && paid !== maxDrops)
      return { isValid: false, invalidReason: "Amount != maxAmountRequired (scheme: exact)" };
  } else {
    // Issued-amount (IOU/token) path.
    if (typeof tx.Amount === "string")
      return { isValid: false, invalidReason: "asset mismatch: issued amount required but Amount is native XAH" };
    // checkIssuedAmount enforces the <= ceiling ("upto"/default). For "exact" we add a
    // strict equality on top (exact token compare, no float).
    const chk = checkIssuedAmount(tx.Amount, asset, maxTokenValue);
    if (chk.error) return { isValid: false, invalidReason: chk.error };
    if (scheme === "exact" && cmpTokenValue(chk.value, maxTokenValue) !== 0)
      return { isValid: false, invalidReason: "Amount != maxAmountRequired (scheme: exact)" };
    paidTokenValue = chk.value;
  }

  if (tx.LastLedgerSequence == null)
    return { isValid: false, invalidReason: "missing LastLedgerSequence (no expiry window)" };

  // (2) Signature is cryptographically VERIFIED, not merely present.
  const isMultisig = Array.isArray(tx.Signers) && tx.Signers.length > 0;
  if (!tx.TxnSignature && !isMultisig)
    return { isValid: false, invalidReason: "unsigned (no TxnSignature/Signers)" };

  // (2b) HIGH: bind the verified signature to the payer. xrpl.verifySignature
  // only proves the TxnSignature matches the *embedded* SigningPubKey — it does
  // NOT prove that key belongs to tx.Account. Without this binding, a tx with
  // Account=victim but an attacker's SigningPubKey/TxnSignature would pass.
  //
  // A *master-key* single-sig must derive to Account. A RegularKey-signed tx
  // (SigningPubKey != master key, but authorized via a SetRegularKey) is a
  // legitimate signer whose key CANNOT be confirmed offline — the regular-key
  // assignment lives in ledger state. Likewise multisig (Signers) authorization
  // is a SignerList in ledger state. We therefore:
  //   - single-sig: cryptographically verify the TxnSignature AND require
  //     deriveAddress(SigningPubKey) === Account (master key), else FAIL;
  //   - multisig:   xrpl.verifySignature CANNOT validate a Signers blob (it expects a
  //     single TxnSignature and THROWS on a multisig tx). The per-signer signatures +
  //     SignerList quorum can only be confirmed against ON-LEDGER state, which we do
  //     at /settle (#3). So offline we DO NOT run the single-sig crypto check on a
  //     multisig (it would spuriously read as "invalid signature"); we pass it through
  //     with signatureVerified:false (flagged, not a guarantee) and let the on-ledger
  //     settle check be the authority. The ledger still rejects a bad multisig at
  //     submit (tefBAD_AUTH / tefBAD_QUORUM). This is a CONFIDENCE-only relaxation: a
  //     multisig is never reported verified offline, and settle re-checks it.
  let signatureVerified = false;
  if (isMultisig) {
    // Offline single-sig crypto cannot validate a SignerList/Signers blob. Flag,
    // don't run the (throwing) single-sig verify, don't pass as verified.
    signatureVerified = false;
  } else {
    const sigOk = verifyTxSignature(payload.txBlob);
    if (sigOk === false)
      return { isValid: false, invalidReason: "invalid signature" };
    if (sigOk === true) {
      const derived = deriveAddressFromPubKey(tx.SigningPubKey);
      if (derived === null) {
        // Can't derive (ripple-keypairs missing / malformed key) -> can't bind.
        signatureVerified = false;
      } else if (derived !== tx.Account) {
        // The signing key does NOT belong to Account. This is either a forged
        // Account or a RegularKey signature; neither can be trusted offline as a
        // master-key signature. A master-key signature MUST derive to Account, so
        // a mismatch fails closed.
        return { isValid: false, invalidReason: "signature does not match Account" };
      } else {
        signatureVerified = true;
      }
    }
    // sigOk === null => xrpl not installed (cannot verify). Report honestly rather
    // than implying a guarantee; signatureVerified stays false.
  }

  // Replay binding: bind this payment to the request via InvoiceID (preferred)
  // or a SourceTag nonce. We surface the binding so /settle can consume it.
  const replayId = replayKeyFor(tx);

  if (asset !== null) {
    // Issued-amount result. `amount` echoes the (canonicalized) decimal value string;
    // `asset` lets /settle re-derive the required value + check delivered_amount.
    return {
      isValid: true,
      invalidReason: null,
      payer: tx.Account,
      amount: tokenValueToString(paidTokenValue),
      asset,
      scheme,
      signatureVerified,
      replayId,
    };
  }

  return {
    isValid: true,
    invalidReason: null,
    payer: tx.Account,
    amount: paid.toString(),
    asset: null,
    scheme,
    signatureVerified,
    replayId,
  };
}

/**
 * Render a parsed token value { sign:1, mant, exp } back to a plain decimal string
 * (no exponent), exact. Used to echo the verified value in the result + to memoize
 * the required value for /settle. mant>0, sign positive (we only handle positive
 * payment values).
 */
function tokenValueToString(v) {
  const digits = v.mant.toString();
  if (v.exp >= 0) return digits + "0".repeat(v.exp);
  const neg = -v.exp;
  if (neg < digits.length) {
    const i = digits.length - neg;
    return digits.slice(0, i) + "." + digits.slice(i);
  }
  return "0." + "0".repeat(neg - digits.length) + digits;
}

/** Stable replay key for a decoded tx: InvoiceID if present, else acct:seq. */
function replayKeyFor(tx) {
  if (typeof tx.InvoiceID === "string" && tx.InvoiceID.length) return `inv:${tx.InvoiceID}`;
  return `acct:${tx.Account}:${tx.Sequence}`;
}

// ---------------------------------------------------------------------------
// replay store + receipts (INJECTABLE, async — default in-memory, optional Redis)
// ---------------------------------------------------------------------------
// The replay store is abstracted behind an ASYNC interface so a durable, SHARED
// backend (Redis) can be plugged in for multi-instance deployments, while the
// DEFAULT remains a zero-dependency in-memory store that reproduces the previous
// semantics EXACTLY. The async shape is required because Redis is async; the
// in-memory backend simply resolves synchronously.
//
// Store contract (all methods async):
//   reserve(key, expiryMs) -> "reserved" | "exists" | "full"
//       Atomic test-and-set. "reserved" iff the key was newly bound (this caller
//       won the race); "exists" iff a LIVE binding already held the key (caller
//       must NOT proceed — replay); "full" iff the store is at its hard cap with
//       only LIVE entries (fail-CLOSED — never evict a live binding, surface 503).
//       Atomicity is what makes two concurrent / multi-instance settles of the
//       same payment unable to BOTH win (the old check-then-mark race is gone).
//   get(key) -> expiryMs | undefined        (raw expiry of a live binding)
//   isConsumed(key) -> bool                  (true iff a live binding exists)
//   release(key) -> void                     (drop a reservation; also its receipt)
//   set(key, expiryMs) -> void               (unconditional upsert; used for the
//                                             redundant tx-hash binding)
//   size() -> number                         (live-entry count; best-effort)
//   getReceipt(key) -> receipt | undefined   (final settle receipt, if stored)
//   setReceipt(key, receipt, expiryMs) -> void
//
// Hole 1 (expiry bound to the tx's REAL on-ledger window), Hole 2 (fail-closed
// hard cap — refuse, never evict a live binding), and the validity-window bound
// (MAX_VALIDITY_LEDGERS, settle rejects over-window txs) are PRESERVED across both
// backends: consumedExpiryFor computes the same window-bound expiry, settle passes
// it as `expiryMs` into reserve, and each backend enforces the cap fail-closed.
const REPLAY_TTL_MS = Number(process.env.X402_REPLAY_TTL_MS) || 60 * 60 * 1000; // 1h
const REPLAY_MAX_ENTRIES = Number(process.env.X402_REPLAY_MAX) || 100_000;

// --- Hole 1: bind validity window to the replay TTL ------------------------
// A Xahau/XRPL tx is (re)submittable until its LastLedgerSequence is passed by
// the validated ledger. The consumed entry MUST NOT expire while the tx is still
// submittable, or the same payment can be replayed in the gap. We therefore cap
// how far ahead LastLedgerSequence may be and tie the consumed-entry expiry to
// the ACTUAL window, never to a flat TTL that could be shorter than the window.
//
// Ledgers close ~3-4s on Xahau; we use a conservative 4s/ledger to translate the
// ledger gap into wall-clock time, plus a safety margin so the entry always
// outlives the on-ledger window even if a few ledgers close slowly.
const LEDGER_CLOSE_MS = Number(process.env.X402_LEDGER_CLOSE_MS) || 4000; // ~4s/ledger (conservative)
const REPLAY_EXPIRY_MARGIN_MS = Number(process.env.X402_REPLAY_MARGIN_MS) || 5 * 60 * 1000; // 5m slack
// Maximum allowed ledger gap (LastLedgerSequence - currentLedger). Chosen so the
// translated wall-clock window (+margin) stays within REPLAY_TTL_MS — i.e. the
// flat TTL is always an UPPER bound on any window we accept, so an entry kept for
// its real window is always reclaimable inside the TTL budget. Reject anything
// whose window would exceed the TTL.
const MAX_VALIDITY_LEDGERS = Math.max(
  1,
  Math.floor((REPLAY_TTL_MS - REPLAY_EXPIRY_MARGIN_MS) / LEDGER_CLOSE_MS)
);

/**
 * Wall-clock expiry (epoch ms) for a consumed entry given the tx's on-ledger
 * window. Guarantees expiry >= the time at which LastLedgerSequence can no longer
 * apply: now + ledgerGap * LEDGER_CLOSE_MS + margin. Falls back to the flat TTL
 * when no ledger context is available (offline path), which is safe ONLY because
 * settle independently REJECTS any tx whose window would exceed the TTL.
 */
function consumedExpiryFor({ lastLedgerSequence, currentLedger } = {}, now = Date.now()) {
  if (
    Number.isFinite(lastLedgerSequence) &&
    Number.isFinite(currentLedger) &&
    lastLedgerSequence > currentLedger
  ) {
    const gap = lastLedgerSequence - currentLedger;
    return now + gap * LEDGER_CLOSE_MS + REPLAY_EXPIRY_MARGIN_MS;
  }
  return now + REPLAY_TTL_MS;
}

/**
 * Default in-memory backend. Reproduces TODAY's exact semantics: a Map<key,
 * expiryEpochMs> of live bindings, sweep-on-access expiry, a fail-CLOSED hard cap
 * (only EXPIRED entries reclaimed; refuse when full of live ones — Hole 2), and an
 * expiry tied to the tx's real on-ledger window (Hole 1, via the expiryMs passed
 * by settle). Receipts live in a parallel Map sharing the same key + expiry. Does
 * NOT survive restart, NOT shared across instances — that is the production gap the
 * optional Redis backend closes.
 *
 * A clock seam (`_now`) keeps the deterministic test hooks (which pass an explicit
 * `now`) working: callers may pass `now` to any method; it defaults to _now().
 */
export class InMemoryStore {
  constructor({ maxEntries = REPLAY_MAX_ENTRIES, now = Date.now } = {}) {
    this.map = new Map();       // key -> expiry (epoch ms)
    this.receipts = new Map();  // key -> { receipt, expiry }
    this.maxEntries = maxEntries;
    this._now = now;
  }
  /** Drop expired bindings + receipts; return true iff there is room for one more. */
  _sweep(now) {
    for (const [k, exp] of this.map) if (exp <= now) this.map.delete(k);
    for (const [k, v] of this.receipts) if (v.expiry <= now) this.receipts.delete(k);
    return this.map.size < this.maxEntries;
  }
  async reserve(key, expiryMs, now = this._now()) {
    // Live binding already held -> replay; do NOT overwrite, do NOT extend.
    const exp = this.map.get(key);
    if (exp !== undefined && exp > now) return "exists";
    // Either absent or expired. Sweep (reclaims the expired one for cap accounting).
    const hasRoom = this._sweep(now);
    if (!hasRoom && !this.map.has(key)) return "full"; // fail closed, never evict live
    this.map.set(key, expiryMs);
    return "reserved";
  }
  async get(key, now = this._now()) {
    const exp = this.map.get(key);
    if (exp === undefined) return undefined;
    if (exp <= now) { this.map.delete(key); return undefined; }
    return exp;
  }
  async isConsumed(key, now = this._now()) {
    return (await this.get(key, now)) !== undefined;
  }
  /** Unconditional upsert (used for the redundant tx-hash binding). Honors the cap fail-closed. */
  async set(key, expiryMs, now = this._now()) {
    const hasRoom = this._sweep(now);
    if (!hasRoom && !this.map.has(key)) return false;
    this.map.set(key, expiryMs);
    return true;
  }
  async release(key) { this.map.delete(key); this.receipts.delete(key); }
  async size() { return this.map.size; }
  async getReceipt(key, now = this._now()) {
    const v = this.receipts.get(key);
    if (v === undefined) return undefined;
    if (v.expiry <= now) { this.receipts.delete(key); return undefined; }
    return v.receipt;
  }
  async setReceipt(key, receipt, expiryMs) { this.receipts.set(key, { receipt, expiry: expiryMs }); }
}

/**
 * Optional Redis backend (multi-instance SHARED + DURABLE). Lazy-loads `ioredis`
 * only when X402_REDIS_URL is set (mirrors the lazy require_ pattern; ioredis is an
 * OPTIONAL peer dep — the default in-memory path needs zero new deps). If
 * X402_REDIS_URL is set but ioredis is missing we FAIL FAST at boot (createStore)
 * rather than silently falling back to a non-shared store — a silent fallback would
 * reopen replay across instances.
 *
 * Reserve atomicity comes from Redis-native `SET key val NX PX <window>`: the reply
 * is "OK" iff the key was newly set (reserved); a nil reply means a LIVE binding
 * already exists (exists). Redis-native PX TTL implements the Hole-1 window expiry
 * server-side. The hard cap (Hole 2) is enforced fail-CLOSED via DBSIZE before a
 * new reserve: if at/over the cap and the key is absent, refuse ("full") — Redis
 * never evicts a live binding to satisfy us (assuming no maxmemory-allkeys policy;
 * documented honestly). Receipts are a second Redis key (`r:<key>`) with the same
 * PX expiry.
 */
export class RedisStore {
  constructor(redis, { maxEntries = REPLAY_MAX_ENTRIES, now = Date.now } = {}) {
    this.redis = redis;
    this.maxEntries = maxEntries;
    this._now = now;
  }
  _px(expiryMs, now) { return Math.max(1, Math.floor(expiryMs - now)); } // ms TTL from absolute expiry
  async reserve(key, expiryMs, now = this._now()) {
    // Fail-closed hard cap (Hole 2): refuse when at the cap and the key is absent.
    // DBSIZE is a coarse, shared-store approximation of "live entries"; we count
    // hash+receipt keys against it, which only makes the cap MORE conservative. It
    // ALSO counts the SHARED rate-limiter (`rl:<ip>:<window>`) keys when the Redis
    // rate limiter shares this DB, so under rate-limit traffic the cap is more
    // conservative still (it can refuse a reservation before REPLAY_MAX replay
    // bindings exist). This only ever errs toward refusing early (fail-closed), never
    // toward over-admitting — acceptable for a hard cap; size it with that headroom.
    const px = this._px(expiryMs, now);
    // Atomic test-and-set: OK iff newly reserved, nil iff a live binding exists.
    const r = await this.redis.set(key, "1", "NX", "PX", px);
    if (r === "OK") {
      // Newly reserved. Enforce the cap AFTER the fact would be racy; instead check
      // before committing to a brand-new key. We already committed, so if we are now
      // over the cap, roll back this fresh reservation and report "full" (fail
      // closed). This never deletes a DIFFERENT live binding.
      const n = await this.redis.dbsize();
      if (n > this.maxEntries) { await this.redis.del(key); return "full"; }
      return "reserved";
    }
    return "exists";
  }
  async get(key, now = this._now()) {
    const pttl = await this.redis.pttl(key); // ms remaining, -2 if absent, -1 if no TTL
    if (pttl === -2) return undefined;
    if (pttl === -1) return now + REPLAY_TTL_MS; // no TTL set: treat as flat-TTL live
    return now + pttl;
  }
  async isConsumed(key) { return (await this.redis.exists(key)) === 1; }
  async set(key, expiryMs, now = this._now()) {
    await this.redis.set(key, "1", "PX", this._px(expiryMs, now));
    return true;
  }
  async release(key) { await this.redis.del(key); await this.redis.del(`r:${key}`); }
  async size() { return await this.redis.dbsize(); }
  async getReceipt(key) {
    const v = await this.redis.get(`r:${key}`);
    if (v == null) return undefined;
    try { return JSON.parse(v); } catch { return undefined; }
  }
  async setReceipt(key, receipt, expiryMs, now = this._now()) {
    await this.redis.set(`r:${key}`, JSON.stringify(receipt), "PX", this._px(expiryMs, now));
  }
}

// Lazily-constructed singleton store (chosen by env at first use / boot).
let _store = null;
let _redisClient = null;
/**
 * Build the configured store. With X402_REDIS_URL set -> RedisStore (lazy ioredis,
 * FAIL FAST if the module is missing — never silently fall back). Otherwise the
 * default InMemoryStore. Idempotent: returns the same singleton.
 */
export function createStore() {
  if (_store) return _store;
  const url = process.env.X402_REDIS_URL;
  if (url) {
    let Redis;
    try { Redis = require_("ioredis"); }
    catch {
      // FAIL FAST: a silent in-memory fallback would reopen replay across instances.
      throw new Error(
        "X402_REDIS_URL is set but 'ioredis' is not installed. Install it (npm i ioredis) " +
        "or unset X402_REDIS_URL. Refusing to fall back to a non-shared in-memory store."
      );
    }
    _redisClient = new (Redis.default || Redis)(url);
    _store = new RedisStore(_redisClient);
  } else {
    _store = new InMemoryStore();
  }
  return _store;
}

// Module-level default store used by the production code paths. Tests inject their
// own via _deps.store; serve() reassigns it via createStore() at boot.
let store = new InMemoryStore();

// ---------------------------------------------------------------------------
// guardrail-Hook presence check
// ---------------------------------------------------------------------------
/**
 * Ask the node whether `account` has at least one Hook installed (account_objects
 * type "hook"). Returns true/false, or null if it could not be determined.
 */
async function guardrailHookPresent(client, account) {
  try {
    const r = await client.request({ command: "account_objects", account, type: "hook" });
    const objs = r?.result?.account_objects || [];
    return objs.length > 0;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// FEATURE 1 — on-ledger spending-POLICY introspection (read the agent's xahc
// guardrail Hook + decode its parameters straight from the chain)
// ---------------------------------------------------------------------------
// The agent's spending policy lives in a Hook (agent_guardrail.c), so no other
// x402 facilitator can report it — but THIS one can read the Hook's installed
// HookParameters off the validated ledger and surface the per-tx limit (LIM) +
// destination allowlist (DST), plus any cumulative-budget HookState if present.
//
// Hook parameter encoding (from the testnet proof + agent_guardrail.c):
//   - HookParameter NAME is the HEX of the ASCII bytes ("LIM" -> "4C494D",
//     "DST" -> "445354"). Account_objects returns each param as
//     { HookParameter: { HookParameterName: <hex>, HookParameterValue: <hex> } }.
//   - LIM value = 8-byte BIG-ENDIAN drops (per-tx cap).
//   - DST value = 20-byte account-id (the single allowed destination), which we
//     encode back to an r-address for the readout.
//
// HONEST / FAIL-TRANSPARENT contract: a wrong policy readout is a credibility bug,
// so anything we cannot decode SOUNDLY is reported as null / "unknown" with a note —
// NEVER a fabricated limit or remaining budget. If the node can't be read we return
// guardrailHookPresent:null + policy:null. If a Hook is present but it is not the
// recognizable guardrail (no LIM param) we report guardrailHookPresent:true but
// policy:null with a note. The agent_guardrail Hook is STATELESS (a per-tx cap, no
// running total): we report stateful:false and DO NOT invent a "remaining" budget.
// If a future stateful guardrail keeps a cumulative total in HookState we surface the
// raw state entries under `hookState` (best-effort) and still never fabricate a
// decoded remaining unless the layout is known — here it is not, so we mark it
// stateful:false and expose the raw state for transparency only.
const HOOK_PARAM_LIM = Buffer.from("LIM", "ascii").toString("hex").toUpperCase(); // 4C494D
const HOOK_PARAM_DST = Buffer.from("DST", "ascii").toString("hex").toUpperCase(); // 445354

/** Encode a 20-byte account-id hex to a classic r-address, or null on failure. */
let _encodeAccountID = undefined;
function accountIdHexToRAddress(hex) {
  if (typeof hex !== "string" || !/^[0-9a-fA-F]{40}$/.test(hex)) return null;
  if (_encodeAccountID === undefined) {
    try { _encodeAccountID = require_("xahau-address-codec").encodeAccountID; }
    catch { _encodeAccountID = null; }
  }
  if (typeof _encodeAccountID !== "function") return null;
  try { return _encodeAccountID(Buffer.from(hex, "hex")); }
  catch { return null; }
}

/** Decode an 8-byte big-endian hex drops value to a decimal string, or null. */
function decode8ByteDropsHex(hex) {
  if (typeof hex !== "string" || !/^[0-9a-fA-F]{16}$/.test(hex)) return null;
  try {
    const n = BigInt("0x" + hex);
    if (n < 0n || n > MAX_DROPS) return null;
    return n.toString();
  } catch { return null; }
}

/**
 * Pull the HookParameters array out of a single account_objects hook entry.
 * Returns a Map<NAME_HEX_UPPER, VALUE_HEX_UPPER> (empty if none). Tolerant of the
 * two shapes a node may return (each element wrapped in { HookParameter: {...} }, or
 * flat { HookParameterName, HookParameterValue }).
 */
function hookParamsMap(hookObj) {
  const out = new Map();
  const arr = hookObj?.HookParameters;
  if (!Array.isArray(arr)) return out;
  for (const el of arr) {
    const p = el?.HookParameter || el;
    const name = p?.HookParameterName;
    const value = p?.HookParameterValue;
    if (typeof name === "string" && typeof value === "string")
      out.set(name.toUpperCase(), value.toUpperCase());
  }
  return out;
}

/**
 * Read an account's installed Hook(s) and decode the guardrail spending policy.
 * Read-only; uses ONLY validated-ledger reads. Returns the /policy response object:
 *   { account, guardrailHookPresent: bool|null,
 *     policy: { perTxLimitDrops?, allowlist?, stateful, remaining?, note? } | null,
 *     source: "on-ledger", asOfLedger: <validated index>|null, note? }
 * FAIL-TRANSPARENT on every error (node down, undecodable params): null fields + an
 * honest note, never a fabricated limit. `client` is the (injected or pooled) node
 * client; `asOfLedger` is read for provenance (best-effort).
 */
async function getPolicy(client, account) {
  const out = {
    account,
    guardrailHookPresent: null,
    policy: null,
    source: "on-ledger",
    asOfLedger: null,
  };
  // Provenance: which validated ledger this readout reflects (best-effort).
  try { out.asOfLedger = await currentValidatedLedger(client); } catch { out.asOfLedger = null; }

  let hooks;
  try {
    const r = await client.request({ command: "account_objects", account, type: "hook", ledger_index: "validated" });
    hooks = r?.result?.account_objects;
  } catch {
    out.note = "node read failed — could not read account_objects (policy unknown)";
    return out; // guardrailHookPresent:null, policy:null — never fabricate
  }
  if (!Array.isArray(hooks)) {
    out.note = "node returned no account_objects (policy unknown)";
    return out;
  }
  out.guardrailHookPresent = hooks.length > 0;
  if (hooks.length === 0) {
    out.note = "no Hook installed — there is no L1 spending policy on this account";
    return out;
  }

  // Find a Hook that carries the guardrail's LIM parameter. account_objects may list
  // the Hook object directly, or nested under a Hooks[] array per the SetHook layout;
  // we scan both, collecting every HookParameters set we can see.
  let limHex = null, dstHex = null, matched = false;
  for (const h of hooks) {
    // A hook entry may expose HookParameters directly, or under Hooks[].Hook.
    const candidates = [];
    candidates.push(h);
    if (Array.isArray(h?.Hooks)) for (const hh of h.Hooks) candidates.push(hh?.Hook || hh);
    for (const c of candidates) {
      const params = hookParamsMap(c);
      if (params.has(HOOK_PARAM_LIM)) {
        matched = true;
        limHex = params.get(HOOK_PARAM_LIM);
        dstHex = params.get(HOOK_PARAM_DST) || null;
        break;
      }
    }
    if (matched) break;
  }

  if (!matched) {
    // A Hook IS installed but it doesn't carry the recognizable guardrail LIM param.
    // We refuse to guess a policy from an unrecognized Hook (could be any Hook).
    out.note = "a Hook is installed but no recognizable guardrail policy (LIM parameter) was found — policy unknown";
    return out;
  }

  const perTxLimitDrops = decode8ByteDropsHex(limHex);
  if (perTxLimitDrops === null) {
    // The guardrail param is present but its value isn't a sound 8-byte drops cap —
    // do NOT fabricate a number; report present-but-undecodable.
    out.note = "guardrail LIM parameter present but its value could not be decoded as an 8-byte drops cap — policy unknown";
    return out;
  }

  const policy = {
    perTxLimitDrops,
    stateful: false, // agent_guardrail is a per-tx cap, NOT a running budget — no fabricated "remaining"
    note: "per-tx spend cap (stateless guardrail). This is the maximum per transaction, NOT a cumulative remaining budget.",
  };
  if (dstHex) {
    const dstAddr = accountIdHexToRAddress(dstHex);
    // If DST is present but undecodable, say so rather than dropping it silently.
    policy.allowlist = dstAddr ? [dstAddr] : [];
    if (!dstAddr) policy.note += " (DST destination-lock present but its account-id could not be decoded)";
  }
  out.policy = policy;
  return out;
}

/**
 * Current VALIDATED ledger index from the node. Used to bound a tx's validity
 * window (Hole 1) — we compare LastLedgerSequence against this. Returns a finite
 * number, or null if it could not be determined (settle then fails closed: it
 * cannot safely bind the consumed-entry expiry without knowing the window).
 */
async function currentValidatedLedger(client) {
  try {
    const r = await client.request({ command: "ledger", ledger_index: "validated" });
    const idx = r?.result?.ledger_index ?? r?.result?.ledger?.ledger_index;
    const n = Number(idx);
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// on-ledger authorization (RegularKey + multisig) — settle-time only
// ---------------------------------------------------------------------------
// At /settle we hold a node connection, so we can do POSITIVE on-ledger auth checks
// that the OFFLINE verifyExact cannot: confirm a RegularKey-signed or multisig tx is
// genuinely authorized by reading ledger state (the account's RegularKey / SignerList).
//
// CONTRACT (security-critical, fail-closed everywhere):
//   - These checks may only REJECT (prove a tx is unauthorized -> skip the submit) or
//     UPGRADE confidence (report signatureVerified:true + a source). They NEVER weaken
//     a check, and they NEVER fabricate authorization.
//   - If the node read FAILS (account_info / SignerList unreadable), we return a
//     "node read failed" outcome -> settle FALLS BACK to its existing behavior
//     (proceed to submit; the LEDGER enforces auth and rejects a bad tx at submit).
//     We never claim authorized without a POSITIVE on-ledger confirmation.
//   - account flags: a RegularKey is invalid for signing if the master key is the
//     ONLY enabled signer in a way that disables the regular key — but lsfDisableMaster
//     does the OPPOSITE (it disables the MASTER, making the regular key the authority),
//     and there is no flag that disables a SET regular key while leaving the account
//     usable. So a present, matching RegularKey is authorized regardless of
//     lsfDisableMaster. We document this rather than guess at a non-existent flag.

// AccountRoot flag: master key disabled (the regular key / signer list is the authority).
const LSF_DISABLE_MASTER = 0x00100000;

/**
 * Fetch an account's AccountRoot via account_info. Returns the `account_data` object,
 * or null if it could not be read (node error / missing). Caller treats null as
 * "could not determine -> fall back to ledger-authoritative submit".
 */
async function fetchAccountRoot(client, account) {
  try {
    const r = await client.request({ command: "account_info", account, ledger_index: "validated" });
    const data = r?.result?.account_data;
    return (data && typeof data === "object") ? data : null;
  } catch {
    return null;
  }
}

/**
 * Fetch an account's on-ledger SignerList entries. Tries account_info with
 * `signer_lists:true` (the canonical place), falling back to account_objects type
 * "signer_list". Returns an array of { account, weight } for the (single) active
 * SignerList plus its quorum, as { quorum, signers: [{account, weight}] }, or null
 * if it could not be read or the account has NO SignerList.
 *
 * XRPL allows at most one SignerList (SignerListID 0) on an account today; if a node
 * returns multiple we conservatively reject (return { error:"multiple_signer_lists" })
 * rather than guess which applies.
 */
async function fetchSignerList(client, account) {
  let lists = null;
  // Preferred: account_info signer_lists.
  try {
    const r = await client.request({ command: "account_info", account, signer_lists: true, ledger_index: "validated" });
    const sl = r?.result?.account_data?.signer_lists;
    if (Array.isArray(sl)) lists = sl;
  } catch {
    lists = null;
  }
  // Fallback: account_objects type signer_list.
  if (lists === null) {
    try {
      const r = await client.request({ command: "account_objects", account, type: "signer_list", ledger_index: "validated" });
      const objs = r?.result?.account_objects;
      if (Array.isArray(objs)) lists = objs;
    } catch {
      return null; // node read failed on both paths -> fall back to ledger authority
    }
  }
  if (lists === null) return null;          // node read failed
  if (lists.length === 0) return { error: "no_signer_list" };
  if (lists.length > 1) return { error: "multiple_signer_lists" };
  const list = lists[0];
  const quorum = Number(list?.SignerQuorum);
  const entries = list?.SignerEntries;
  if (!Number.isInteger(quorum) || quorum <= 0 || !Array.isArray(entries))
    return { error: "malformed_signer_list" };
  const signers = [];
  for (const e of entries) {
    const se = e?.SignerEntry;
    const acct = se?.Account;
    const weight = Number(se?.SignerWeight);
    if (typeof acct !== "string" || !Number.isInteger(weight) || weight <= 0)
      return { error: "malformed_signer_list" };
    signers.push({ account: acct, weight });
  }
  if (signers.length === 0) return { error: "malformed_signer_list" };
  return { quorum, signers };
}

/**
 * On-ledger authorization for a tx whose offline binding was NOT established
 * (verifyExact returned signatureVerified:false). Called at settle ONLY (needs the
 * node). Returns one of:
 *   { decision: "authorized", source: "regularkey" | "multisig" }
 *   { decision: "rejected", reason: <string> }          -> caller MUST NOT submit
 *   { decision: "fallback" }                            -> node read failed; caller
 *                                                          proceeds to submit (ledger
 *                                                          is the authority)
 *
 * The decoded `tx` is passed (already decoded at settle). `txBlob` is the original
 * blob (single-sig signature already cryptographically verified in verifyExact; here
 * we only need to confirm the KEY's authority on-ledger).
 *
 * REGULARKEY (single-sig): tx has SigningPubKey + TxnSignature, deriveAddress !=
 *   Account (else verifyExact would have bound it as master). The signature itself
 *   was already verified by verifyExact (it never reaches settle if invalid). We fetch
 *   account_info and AUTHORIZE iff account.RegularKey === deriveAddress(SigningPubKey).
 *   No RegularKey set, or a mismatch -> REJECT (forgery / unauthorized).
 *
 * MULTISIG (Signers): we verify EACH listed signer's TxnSignature over
 *   encodeForMultisigning(tx, signer.Account) against signer.SigningPubKey, require
 *   deriveAddress(signer.SigningPubKey) === signer.Account, require signer.Account be
 *   in the on-ledger SignerList, then SUM the on-ledger SignerWeight of the VALID,
 *   LISTED signers and require sum >= on-ledger SignerQuorum. Any invalid signature,
 *   any unlisted/derive-mismatched signer is EXCLUDED from the sum (not fatal on its
 *   own — but it cannot contribute weight). AUTHORIZE iff the surviving weight >=
 *   quorum; else REJECT. A node read failure (cannot fetch SignerList) -> fallback.
 *
 * Determinism / soundness notes: duplicate signer Accounts are collapsed (a signer's
 * weight counts at most ONCE) so a repeated entry can't inflate the sum. We use the
 * ON-LEDGER weight (not any client-claimed weight). encodeForMultisigning is verified
 * to reproduce exactly the bytes each signer signed.
 */
function authorizeOnLedger_decide(tx, signerList, accountRoot, isMultisig) {
  if (isMultisig) {
    // signerList is the resolved { quorum, signers } | { error } | null.
    if (signerList === null) return { decision: "fallback" }; // node read failed
    if (signerList.error) {
      // No SignerList / malformed / multiple lists: we cannot positively authorize a
      // multisig tx offline-of-the-ledger here. "no_signer_list" means the account is
      // NOT multisig-configured -> the tx is unauthorized -> REJECT. A malformed or
      // ambiguous list we cannot evaluate -> fall back to the ledger at submit.
      if (signerList.error === "no_signer_list")
        return { decision: "rejected", reason: "unauthorized: account has no on-ledger SignerList for this multisig" };
      return { decision: "fallback" };
    }
    const weightByAccount = new Map();
    for (const s of signerList.signers) weightByAccount.set(s.account, s.weight);

    const counted = new Set(); // signer accounts already credited (dedupe)
    let sum = 0;
    for (const entry of tx.Signers) {
      const s = entry?.Signer;
      if (!s || typeof s.SigningPubKey !== "string" || typeof s.TxnSignature !== "string" || typeof s.Account !== "string")
        continue; // malformed signer entry -> contributes nothing
      // (2) derived address must match the claimed signer account.
      const derived = deriveAddressFromPubKey(s.SigningPubKey);
      if (derived === null || derived !== s.Account) continue;
      // (3) signer must be on the on-ledger SignerList.
      const weight = weightByAccount.get(s.Account);
      if (weight === undefined) continue;
      // (1) signature must verify over the per-signer multisigning data.
      const signingData = encodeForMultisigning(tx, s.Account);
      if (signingData === null) return { decision: "fallback" }; // codec unavailable -> ledger authority
      const ok = keypairVerify(signingData, s.TxnSignature, s.SigningPubKey);
      if (ok !== true) continue; // invalid (or unverifiable) signature -> excluded
      if (counted.has(s.Account)) continue; // dedupe: count each signer's weight once
      counted.add(s.Account);
      sum += weight;
    }
    if (sum >= signerList.quorum)
      return { decision: "authorized", source: "multisig" };
    return { decision: "rejected", reason: "unauthorized: multisig quorum not met by valid on-ledger signers" };
  }

  // RegularKey single-sig path.
  if (accountRoot === null) return { decision: "fallback" }; // node read failed
  const derived = deriveAddressFromPubKey(tx.SigningPubKey);
  if (derived === null) return { decision: "fallback" }; // cannot derive -> ledger authority
  const regularKey = accountRoot.RegularKey;
  if (typeof regularKey === "string" && regularKey.length > 0 && regularKey === derived)
    return { decision: "authorized", source: "regularkey" };
  // No RegularKey set, or it does not match the signing key -> forgery / unauthorized.
  return { decision: "rejected", reason: "unauthorized: signing key is neither master nor current RegularKey" };
}

/**
 * Orchestrate the on-ledger auth check: fetch the needed ledger state for the tx's
 * signing mode, then decide. Returns the same shape as authorizeOnLedger_decide.
 * isMultisig is derived by the caller from the decoded tx. Network reads are guarded
 * inside fetchAccountRoot/fetchSignerList (they return null on failure -> fallback).
 */
async function authorizeOnLedger(client, tx, isMultisig) {
  if (isMultisig) {
    const signerList = await fetchSignerList(client, tx.Account);
    return authorizeOnLedger_decide(tx, signerList, null, true);
  }
  const accountRoot = await fetchAccountRoot(client, tx.Account);
  return authorizeOnLedger_decide(tx, null, accountRoot, false);
}

// ---------------------------------------------------------------------------
// pooled client
// ---------------------------------------------------------------------------
let _client = null;
// Bounded connect: how long a single connect attempt may take, how many attempts,
// and the backoff between them. Kept SMALL so a node blip degrades gracefully (a
// settle fails closed with a clear errorReason) instead of wedging the request.
const CONNECT_TIMEOUT_MS = Number(process.env.X402_CONNECT_TIMEOUT_MS) || 8000;
const CONNECT_ATTEMPTS = Math.max(1, Number(process.env.X402_CONNECT_ATTEMPTS) || 3);
const CONNECT_BACKOFF_MS = Number(process.env.X402_CONNECT_BACKOFF_MS) || 500;

/** Race a promise against a timeout; reject with a clear message if it wins. */
function withTimeout(promise, ms, label) {
  let t;
  const timeout = new Promise((_, reject) => {
    t = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
}

/**
 * Get a connected xrpl client. RESILIENT: reuses the pooled client only while it
 * isConnected(); on a disconnect it rebuilds + reconnects. Each connect attempt is
 * BOUNDED by CONNECT_TIMEOUT_MS, with a small bounded backoff retry (CONNECT_ATTEMPTS)
 * so a transient node blip doesn't wedge settle. This is NOT an unbounded in-request
 * retry loop: after the bounded attempts it FAILS CLOSED (throws) and settle surfaces
 * a clear errorReason. The _deps.client injection seam in settle bypasses this entirely.
 */
async function getClient() {
  const wss = process.env.XAHAU_WSS;
  if (!wss) throw new Error("XAHAU_WSS not set");
  let Client;
  try { ({ Client } = await import("xahau")); }
  catch { throw new Error("xahau not installed"); }
  // Fast path: reuse a live connection.
  if (_client && _client.isConnected()) return _client;
  // Stale/disconnected client: best-effort tear down before rebuilding.
  if (_client) {
    try { await _client.disconnect(); } catch { /* ignore */ }
    _client = null;
  }
  let lastErr;
  for (let attempt = 1; attempt <= CONNECT_ATTEMPTS; attempt++) {
    const c = new Client(wss);
    try {
      await withTimeout(c.connect(), CONNECT_TIMEOUT_MS, "xrpl connect");
      _client = c;
      return _client;
    } catch (e) {
      lastErr = e;
      try { await c.disconnect(); } catch { /* ignore */ }
      log("warn", "xrpl_connect_failed", { attempt, attempts: CONNECT_ATTEMPTS, error: String(e?.message || e) });
      if (attempt < CONNECT_ATTEMPTS) await new Promise((r) => setTimeout(r, CONNECT_BACKOFF_MS));
    }
  }
  // Fail CLOSED after bounded attempts — never an unbounded retry inside a request.
  throw new Error(`xrpl connect failed after ${CONNECT_ATTEMPTS} attempts: ${lastErr?.message || lastErr}`);
}

/**
 * Return true ONLY when a thrown `submitAndWait` PROVES the transaction was not
 * (and cannot become) applied — i.e. a preliminary `tem*` engine result, which
 * xahaud rejects BEFORE the tx is broadcast. Every other failure (LastLedgerSequence
 * passed mid-wait, disconnect, timeout, tx-lookup error, any unrecognised throw) is
 * treated as MAYBE-APPLIED and must fail CLOSED — releasing the replay reservation
 * there would reopen a replay/double-settle window for a tx that may already be
 * (or about to be) on-ledger. `tem*` is the only class where release is provably safe.
 */
function submitDefinitelyNotApplied(e) {
  // Prefer a structured engine_result if xrpl attached one.
  const er =
    (e && (e.data?.engine_result ?? e.data?.result?.engine_result)) ??
    (typeof e?.engine_result === "string" ? e.engine_result : null);
  if (typeof er === "string") return /^tem[A-Z]/.test(er);
  // Fallback: a TIGHT match for an explicit tem* code token in the message. tem*
  // codes are the only safe-to-release class; an LLS-passed / disconnect message
  // never carries a tem* token (tem* rejects before the wait that throws those).
  const msg = typeof e?.message === "string" ? e.message : "";
  return /\btem[A-Z][A-Z_]{2,}\b/.test(msg);
}

/**
 * (F3) Uniform fail-CLOSED + RETRYABLE reply for a PRE-SUBMIT replay-store/backend
 * outage (e.g. Redis unreachable on isConsumed/getReceipt/reserve). The submit has
 * NOT happened, so refusing is always safe; marking it retryable lets the handler
 * surface a 503 (vs an opaque 500) so the client retries instead of treating it as a
 * hard failure. The store error CLASS only is logged (never the payment / payer PII
 * inside the error). This path NEVER appears AFTER submitAndWait — a post-submit
 * persistence failure is handled best-effort (F2), not as a retryable reject.
 */
function settleStoreUnavailable(payer, e, stage) {
  recordSettleReject("other");
  log("error", "settle_store_unavailable", { stage, error: String(e?.name || "store_error") });
  return { success: false, network: NETWORK, transaction: "", payer: payer ?? "", errorReason: "replay store unavailable", retryable: true };
}

// ---------------------------------------------------------------------------
// FEATURE 4 — pre-settle simulation (OPTIONAL, config-gated, ADVISORY ONLY)
// ---------------------------------------------------------------------------
// When X402_MCP_URL is set, the facilitator can ask xahau-mcp (the Hooks VM HTTP
// shim) to PREDICT the payer guardrail Hook's accept/rollback for a payment WITHOUT
// submitting it. This is ADVISORY: it must NEVER change settle's security semantics.
// A predicted-accept STILL runs the full real settle. A predicted-reject MAY (opt-in)
// short-circuit the submit to save a fee, but only ever returns a clearly-labeled
// advisory rejection and NEVER consumes/keeps a real replay reservation. When unset,
// the feature is entirely OFF (no coupling, no required dep). fetch with a timeout;
// fail SOFT (any sim error -> "simulation unavailable", never blocks the real settle).
const MCP_SIM_TIMEOUT_MS = Number(process.env.X402_MCP_TIMEOUT_MS) || 5000;

/**
 * Call the configured xahau-mcp shim to predict a payment's on-Hook outcome. Returns
 * one of:
 *   { available:false, note }                              — feature off / sim error
 *   { available:true, prediction:"accept"|"reject"|"unknown", raw?, note? }
 * NEVER throws. `_deps.simulateFn` can inject a fake for tests; `_deps.mcpUrl`
 * overrides the env URL. A non-OK HTTP status / timeout / parse error -> available:false
 * (fail soft). We map a clearly-rejecting VM result to "reject", a clearly-accepting one
 * to "accept", and anything ambiguous to "unknown" (never guess accept on ambiguity).
 */
async function simulatePayment(payload, req, _deps = {}) {
  const mcpUrl = _deps.mcpUrl !== undefined ? _deps.mcpUrl : process.env.X402_MCP_URL;
  if (_deps.simulateFn) {
    try { return await _deps.simulateFn(payload, req); }
    catch (e) { return { available: false, note: "simulation unavailable", error: String(e?.name || "sim_error") }; }
  }
  if (!mcpUrl) return { available: false, note: "simulation not configured (X402_MCP_URL unset)" };
  let controller, timer;
  try {
    controller = new AbortController();
    timer = setTimeout(() => controller.abort(), MCP_SIM_TIMEOUT_MS);
    const resp = await fetch(mcpUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ paymentPayload: payload, paymentRequirements: req }),
      signal: controller.signal,
    });
    if (!resp || !resp.ok) return { available: false, note: "simulation unavailable (mcp non-OK)" };
    const data = await resp.json();
    // Interpret the VM result conservatively. xahau-mcp typically returns an
    // engine_result / accepted flag. A clearly-rejecting result -> "reject"; a clearly
    // accepting one -> "accept"; otherwise "unknown" (never assume accept).
    let prediction = "unknown";
    const er = data?.engine_result ?? data?.result?.engine_result;
    const accepted = data?.accepted ?? data?.result?.accepted;
    if (accepted === true || (typeof er === "string" && /^tes/.test(er))) prediction = "accept";
    else if (accepted === false || (typeof er === "string" && /^(tec|tem|tef|tel|ter)/.test(er))) prediction = "reject";
    return { available: true, prediction, raw: { engine_result: er ?? null, accepted: accepted ?? null } };
  } catch (e) {
    return { available: false, note: "simulation unavailable", error: String(e?.name || "sim_error") };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// settle
// ---------------------------------------------------------------------------
/**
 * Submit the signed tx to Xahau. Re-validates EVERYTHING (does not trust /verify
 * was called), enforces single-use replay binding, and checks delivered_amount.
 *
 * FEATURE 4 (advisory sim): `_deps.dryRun:true` (or a `dryRun` flag from the route)
 * returns a prediction WITHOUT submitting and WITHOUT reserving a replay slot.
 * `_deps.preSimReject:true` opts into the fee-saving short-circuit where a predicted-
 * REJECT skips the real submit — still labeled advisory, still reserves NO slot.
 */
async function settle(payload, req, _deps = {}) {
  // settle_total counts every settlement ATTEMPT that reaches this function.
  metricInc("settle_total");
  if (!process.env.XAHAU_WSS) {
    recordSettleReject("other");
    return { success: false, network: NETWORK, transaction: "", payer: "", errorReason: "set XAHAU_WSS to settle" };
  }

  // Dependency seams (injectable for tests): store, client, ledger fetcher, clock.
  const st = _deps.store || store;

  // (4a) Re-run full verification inside settle.
  const v = verifyExact(payload, req);
  if (!v.isValid) {
    recordSettleReject("verify_failed");
    return { success: false, network: NETWORK, transaction: "", payer: v.payer ?? "", errorReason: `verify failed: ${v.invalidReason}` };
  }

  // FEATURE 4 (advisory) — dryRun: predict the Hook outcome and return WITHOUT
  // submitting and WITHOUT reserving a replay slot. This is a HINT, not ground truth:
  // it never touches the store, never submits, and is clearly labeled advisory. A
  // real settle (no dryRun) ignores this branch entirely.
  if (_deps.dryRun === true) {
    const sim = await simulatePayment(payload, req, _deps);
    return {
      success: false,
      dryRun: true,
      advisory: true,
      network: NETWORK,
      transaction: "",
      payer: v.payer,
      simulation: sim,
      errorReason: "dryRun: not submitted (advisory simulation only)",
    };
  }

  // FEATURE 4 (advisory, opt-in fee-saver) — a PREDICTED-REJECT short-circuit. ONLY
  // active when the caller opts in via _deps.preSimReject AND a simulation is available
  // AND it predicts a reject. It returns a clearly-labeled ADVISORY rejection and
  // reserves NO replay slot / submits nothing. Because the sim is a hint (not ground
  // truth), a predicted-ACCEPT or an UNAVAILABLE sim does NOT short-circuit — the full
  // real settle runs. This can never weaken security: it only ever skips a submit the
  // VM thinks would fail, and a false "reject" merely costs the caller a retry (the
  // real settle is always available without the flag).
  if (_deps.preSimReject === true) {
    const sim = await simulatePayment(payload, req, _deps);
    if (sim.available === true && sim.prediction === "reject") {
      log("info", "settle_presim_reject", {});
      return {
        success: false,
        advisory: true,
        network: NETWORK,
        transaction: "",
        payer: v.payer,
        simulation: sim,
        errorReason: "predicted-reject (simulated, not submitted)",
      };
    }
    // available accept / unknown / unavailable -> fall through to the FULL real settle.
  }

  // (4b) Replay protection — refuse a payment whose binding was already consumed.
  // IDEMPOTENCY: if a FINAL receipt was stored for this payment (terminal on-ledger
  // outcome), return THAT receipt with replayed:true — an x402 client retrying gets
  // the real tx hash + delivered amount instead of a bare "already consumed". If the
  // binding exists but no receipt yet (in-flight, or the ambiguous-retained case),
  // the outcome is genuinely unknown: return the existing "already consumed" reply
  // (inFlight:true) and NEVER re-submit.
  //
  // (F3) These are PRE-SUBMIT store reads. If the backend (Redis) is down they THROW.
  // That MUST fail CLOSED — we have not submitted, so refusing is safe — but it must
  // also be RETRYABLE (503), not an opaque 500. A store throw here can NEVER be
  // swallowed into "not consumed -> proceed to submit": that would be fail-OPEN
  // (re-submitting a maybe-already-settled payment). So on any store error we REJECT
  // with retryable:true and return WITHOUT submitting. settleStoreUnavailable() builds
  // that uniform reply; the handler maps retryable -> 503.
  let alreadyConsumed;
  try { alreadyConsumed = await st.isConsumed(v.replayId); }
  catch (e) { return settleStoreUnavailable(v.payer, e, "isConsumed"); }
  if (alreadyConsumed) {
    let receipt;
    try { receipt = await st.getReceipt(v.replayId); }
    catch (e) { return settleStoreUnavailable(v.payer, e, "getReceipt"); }
    if (receipt) { metricInc("settle_replayed"); return { ...receipt, payer: receipt.payer ?? v.payer, replayed: true }; }
    recordSettleReject("replay_inflight");
    return { success: false, network: NETWORK, transaction: "", payer: v.payer, errorReason: "replay: payment already consumed", inFlight: true };
  }

  let tx;
  try { tx = decode(payload.txBlob); } catch { recordSettleReject("other"); return { success: false, network: NETWORK, transaction: "", payer: v.payer ?? "", errorReason: "undecodable txBlob" }; }
  // exact-xahau: the delivered amount must be >= the verified required amount, up to
  // max. For native that's a bigint drops compare; for an IOU it's an exact token
  // compare. v.amount is the verified value the payer committed to (<= maxRequired).
  const isIou = v.asset != null;
  const required = isIou ? null : BigInt(v.amount);
  const requiredTokenValue = isIou ? parseTokenValue(v.amount) : null;

  const now = typeof _deps.now === "function" ? _deps.now() : Date.now();
  const getLedger = _deps.currentValidatedLedger || currentValidatedLedger;

  let client;
  try { client = _deps.client || await getClient(); }
  catch (e) {
    recordSettleReject("other");
    log("error", "settle_client_unavailable", { error: String(e?.message || e) });
    return { success: false, network: NETWORK, transaction: "", payer: v.payer, errorReason: e.message };
  }

  // (Hole 1) Bound the tx's on-ledger validity window. A tx is replayable until
  // its LastLedgerSequence is passed; if that window exceeds what the replay TTL
  // can cover, the consumed entry would expire while the tx is still submittable.
  // So: fetch the current validated ledger and REJECT any tx whose
  // LastLedgerSequence is more than MAX_VALIDITY_LEDGERS ahead. We fail CLOSED if
  // the ledger can't be read — without it we cannot prove the entry will outlive
  // the window.
  const lastLedger = Number(tx.LastLedgerSequence);
  const curLedger = await getLedger(client);
  if (!Number.isFinite(curLedger)) {
    recordSettleReject("other");
    return { success: false, network: NETWORK, transaction: "", payer: v.payer, errorReason: "could not read current ledger (cannot bound validity window)" };
  }
  if (!Number.isFinite(lastLedger) || lastLedger <= curLedger) {
    recordSettleReject("other");
    return { success: false, network: NETWORK, transaction: "", payer: v.payer, errorReason: "LastLedgerSequence not in the future" };
  }
  if (lastLedger - curLedger > MAX_VALIDITY_LEDGERS) {
    recordSettleReject("other");
    return { success: false, network: NETWORK, transaction: "", payer: v.payer, errorReason: `validity window too large (LastLedgerSequence > ${MAX_VALIDITY_LEDGERS} ledgers ahead)` };
  }

  // (#3) ON-LEDGER AUTHORIZATION for txs whose signature could NOT be bound offline.
  // verifyExact cryptographically binds ONLY a master-key single-sig (it returns
  // signatureVerified:true). A RegularKey single-sig and a multisig (Signers) tx come
  // back signatureVerified:false — offline-unverifiable. Here at settle we hold a node
  // connection, so we POSITIVELY check on-ledger authorization BEFORE wasting a submit:
  //   - reject an obviously-unauthorized tx (no/mismatched RegularKey; multisig quorum
  //     not met by valid on-ledger signers) WITHOUT submitting / reserving a slot;
  //   - upgrade signatureVerified -> true (with a source) for a genuinely-authorized
  //     RegularKey / multisig tx, honestly reported in the receipt.
  // This is fail-CLOSED on the CHECK ITSELF: if the ledger reads fail (node error) we
  // do NOT fabricate authorization — we fall back to the existing behavior (proceed to
  // submit; the LEDGER is the ultimate authority and rejects a bad tx at submitAndWait
  // via tefBAD_AUTH etc.). The ledger remains authoritative; this only REJECTS or
  // UPGRADES confidence, never weakens. (master-key single-sig already signatureVerified
  // -> true here, so this entire block is skipped for it.)
  const isMultisig = Array.isArray(tx.Signers) && tx.Signers.length > 0;
  let signatureVerified = v.signatureVerified === true;
  let signatureSource = signatureVerified ? "master" : null;
  if (!signatureVerified) {
    let auth;
    try {
      auth = await authorizeOnLedger(client, tx, isMultisig);
    } catch (e) {
      // Any unexpected throw in the auth check -> fall back to ledger authority (never
      // fabricate authorization, never 500). Log the error class only.
      log("warn", "settle_authz_check_error", { error: String(e?.name || "authz_error") });
      auth = { decision: "fallback" };
    }
    if (auth.decision === "rejected") {
      // Provably unauthorized on-ledger -> REJECT pre-submit. No slot reserved, no
      // submit wasted. The ledger would reject it anyway; we save the round-trip and
      // report honestly.
      recordSettleReject("verify_failed");
      log("info", "settle_unauthorized", { mode: isMultisig ? "multisig" : "regularkey" });
      return { success: false, network: NETWORK, transaction: "", payer: v.payer, errorReason: auth.reason, signatureVerified: false };
    }
    if (auth.decision === "authorized") {
      signatureVerified = true;
      signatureSource = auth.source; // "regularkey" | "multisig"
      log("info", "settle_onledger_authorized", { source: signatureSource });
    }
    // auth.decision === "fallback": node read failed -> proceed to submit; the ledger
    // enforces auth. signatureVerified stays false (no positive confirmation).
  }

  const replayCtx = { lastLedgerSequence: lastLedger, currentLedger: curLedger };
  const expiryMs = consumedExpiryFor(replayCtx, now);

  // (3) Honestly report whether the payer's guardrail Hook is installed.
  const hookPresent = await guardrailHookPresent(client, tx.Account);

  // ATOMIC reserve before submission: two concurrent / multi-instance /settle calls
  // for the same payment can't BOTH win. reserve() is a single atomic test-and-set
  // (in-memory: check-then-set under the single-threaded event loop; Redis: SET NX
  // PX) — this replaces the old check-then-mark race. The expiry is bound to the
  // tx's REAL on-ledger window (Hole 1). "full" = store at cap with only LIVE
  // entries (Hole 2, fail closed) -> surface 503. "exists" = another settle already
  // holds it -> idempotent replay branch (return receipt if any, else in-flight).
  // (F3) reserve() is the last PRE-SUBMIT store call. A backend throw here likewise
  // fails CLOSED + RETRYABLE: we have NOT submitted, so refusing is safe, and we must
  // never treat a thrown reserve as "reserved" and proceed (fail-OPEN). Reject 503.
  let res;
  try { res = await st.reserve(v.replayId, expiryMs, now); }
  catch (e) { return settleStoreUnavailable(v.payer, e, "reserve"); }
  if (res === "full") {
    recordSettleReject("store_full");
    log("warn", "settle_store_full", {});
    return { success: false, network: NETWORK, transaction: "", payer: v.payer, errorReason: "replay store full, retry later", retryable: true };
  }
  if (res === "exists") {
    const receipt = await st.getReceipt(v.replayId);
    if (receipt) { metricInc("settle_replayed"); return { ...receipt, payer: receipt.payer ?? v.payer, replayed: true }; }
    recordSettleReject("replay_inflight");
    return { success: false, network: NETWORK, transaction: "", payer: v.payer, errorReason: "replay: payment already consumed", inFlight: true };
  }

  let r;
  try {
    r = await client.submitAndWait(payload.txBlob);
  } catch (e) {
    // A thrown submitAndWait is AMBIGUOUS by default: a tx that cleared preflight
    // can be broadcast and applied on-ledger yet still throw here when its
    // LastLedgerSequence passes mid-wait or the connection drops. We therefore fail
    // CLOSED — release the reservation ONLY when we can prove nothing was applied
    // (a preliminary tem*). Otherwise KEEP the binding and let the Hole-1 expiry
    // (tied to the tx's real on-ledger validity window) reopen the slot once the tx
    // can no longer apply. Releasing on a maybe-applied throw is a double-settle hole.
    if (submitDefinitelyNotApplied(e)) {
      // tem stores NO receipt; release() also clears any (non-existent) receipt.
      await st.release(v.replayId);
      recordSettleReject("tem_rejected");
      log("warn", "settle_submit_tem", {});
      return { success: false, network: NETWORK, transaction: "", payer: v.payer, errorReason: "submit rejected (tem, not applied)", guardrailHookPresent: hookPresent };
    }
    // AMBIGUOUS retained path: outcome genuinely UNKNOWN -> store NO receipt, so a
    // later retry is treated as in-flight (not handed a fabricated receipt). Log the
    // ERROR CLASS only (never the full error/tx — could carry sensitive context).
    recordSettleReject("submit_ambiguous");
    log("error", "settle_submit_ambiguous", { reservationRetained: true, error: String(e?.message || e).slice(0, 200) });
    return { success: false, network: NETWORK, transaction: "", payer: v.payer, errorReason: "submit result unknown — reservation retained until validity window expires", guardrailHookPresent: hookPresent };
  }

  // (F1) Guard the RESOLVED submitAndWait response shape. submitAndWait can RESOLVE
  // (no throw) yet hand back a shape we cannot classify (r/r.result missing/not an
  // object, or no usable TransactionResult code). A resolved-but-unreadable submit
  // means the tx MAY be on-ledger — so we must fail CLOSED EXACTLY like the
  // ambiguous-retained throw path: KEEP the reservation (already held), store NO
  // receipt, count it in the submit_ambiguous bucket, and return the unknown-outcome
  // reply. NEVER 500, NEVER release — releasing here would reopen the Hole-1 window
  // for a maybe-applied tx (double-settle). A retry then sees the live binding and is
  // treated as in-flight (no re-submit).
  const result = (r && typeof r === "object") ? r.result : undefined;
  const meta = (result && typeof result === "object" && result.meta) ? result.meta : {};
  const code = (result && typeof result === "object") ? result.meta?.TransactionResult : undefined;
  const hash = (result && typeof result === "object") ? result.hash : undefined;
  if (!result || typeof result !== "object" || typeof code !== "string" || code.length === 0) {
    // Genuinely unclassifiable resolved response -> ambiguous-retained (fail closed).
    recordSettleReject("submit_ambiguous");
    log("warn", "settle_submit_unreadable_response", { reservationRetained: true });
    return { success: false, network: NETWORK, transaction: "", payer: v.payer, errorReason: "submit result unknown — reservation retained until validity window expires", guardrailHookPresent: hookPresent };
  }
  // The hash binding shares the tx's window. If the store is momentarily full it
  // is fine to skip the redundant hash entry — replayId already holds the slot.
  // (F2) Best-effort: a store-write failure here must NEVER 500 — the submit already
  // happened and the reservation is already held, so a retry still can't double-submit.
  // Log + continue; the authoritative receipt is still returned below.
  if (hash) {
    try { await st.set(`hash:${hash}`, expiryMs, now); }
    catch (e) { log("warn", "settle_receipt_persist_failed", { stage: "hash", error: String(e?.name || "store_error") }); }
  }

  // READ-ONLY transparency: decode the guardrail Hook's on-ledger execution result
  // from the validated tx meta. This is INFORMATIONAL ONLY — it is attached to the
  // receipt AFTER the proof is signed (below), so it is NEVER part of the signed
  // canonical bytes, and it is read here but NEVER consulted for any accept/reject/
  // replay decision (those are driven solely by `code` + delivered_amount). Defensive
  // + bounded; an absent/unknown HookExecutions shape decodes to [] without throwing.
  const hookExecutions = decodeHookExecutions(meta);

  // Build the terminal receipt + persist it keyed by replayId (same window expiry),
  // so a retry of this terminal payment returns the real outcome (replayed:true)
  // instead of re-submitting. ALL branches below are TERMINAL: the tx is on-ledger
  // and its sequence is spent (tecHOOK_REJECTED / delivered<required / unreadable
  // delivered / tesSUCCESS) — final outcomes, safe to memoize. The ambiguous
  // retained path above is the ONLY non-terminal one and stores no receipt.
  let receipt;
  if (code !== "tesSUCCESS") {
    // tecHOOK_REJECTED here == the payer's guardrail Hook blocked an over-policy
    // payment. The tx is on-ledger (sequence consumed) so keep the replay slot.
    receipt = {
      success: false,
      transaction: hash,
      network: NETWORK,
      errorReason: code || "no result",
      guardrailHookPresent: hookPresent,
    };
  } else {
    // (4c) Validate delivered_amount >= required (not just tesSUCCESS). For an IOU,
    // delivered_amount is an OBJECT {currency,issuer,value} and must match the asset
    // AND carry value >= required (exact token compare). For native it stays drops.
    if (isIou) {
      const delivered = deliveredIssued(meta);
      if (delivered === null) {
        receipt = { success: false, transaction: hash, network: NETWORK, errorReason: "could not read delivered_amount", guardrailHookPresent: hookPresent };
      } else if (
        canonicalizeCurrency(delivered.currency) === null ||
        canonicalizeCurrency(delivered.currency) !== canonicalizeCurrency(v.asset.currency) ||
        delivered.issuer !== v.asset.issuer
      ) {
        // Wrong asset delivered (different currency/issuer than required) -> fail.
        receipt = { success: false, transaction: hash, network: NETWORK, errorReason: "delivered_amount asset mismatch", guardrailHookPresent: hookPresent };
      } else {
        const dv = parseTokenValue(delivered.value);
        if (dv === null) {
          receipt = { success: false, transaction: hash, network: NETWORK, errorReason: "could not read delivered_amount", guardrailHookPresent: hookPresent };
        } else if (requiredTokenValue === null || cmpTokenValue(dv, requiredTokenValue) < 0) {
          receipt = { success: false, transaction: hash, network: NETWORK, errorReason: "delivered_amount < required", guardrailHookPresent: hookPresent };
        } else {
          receipt = {
            success: true,
            transaction: hash,
            network: NETWORK,
            errorReason: null,
            delivered: { currency: delivered.currency, issuer: delivered.issuer, value: tokenValueToString(dv) },
            guardrailHookPresent: hookPresent,
          };
        }
      }
    } else {
      const delivered = deliveredDrops(meta);
      if (delivered === null) {
        receipt = { success: false, transaction: hash, network: NETWORK, errorReason: "could not read delivered_amount", guardrailHookPresent: hookPresent };
      } else if (delivered < required) {
        receipt = { success: false, transaction: hash, network: NETWORK, errorReason: "delivered_amount < required", guardrailHookPresent: hookPresent };
      } else {
        receipt = {
          success: true,
          transaction: hash,
          network: NETWORK,
          errorReason: null,
          delivered: delivered.toString(),
          guardrailHookPresent: hookPresent,
        };
      }
    }
  }
  // x402 SettleResponse requires a `payer` field on every settlement result. The
  // verified payer (== tx.Account, signature-bound) is the authoritative value.
  receipt.payer = v.payer;
  // (#3) Honestly report HOW the payer's authorization was confirmed. master = offline
  // master-key binding (verifyExact); regularkey/multisig = POSITIVE on-ledger check at
  // settle; null source with signatureVerified:false = could not bind/confirm (the
  // ledger was the authority at submit). This UPGRADES the offline report; it never
  // claims true without a positive confirmation.
  receipt.signatureVerified = signatureVerified;
  receipt.signatureSource = signatureSource;
  // Metrics: classify the TERMINAL outcome by its actual cause (no PII). success
  // increments settle_success; on-ledger non-tesSUCCESS (e.g. tecHOOK_REJECTED) ->
  // on_ledger_failure; a tesSUCCESS that under-delivered / mis-asset'd / had an
  // unreadable delivered_amount -> delivered_short.
  if (receipt.success === true) {
    metricInc("settle_success");
  } else if (code !== "tesSUCCESS") {
    recordSettleReject("on_ledger_failure");
    log("info", "settle_on_ledger_failure", { code: code || "no result", guardrailHookPresent: hookPresent });
  } else {
    recordSettleReject("delivered_short");
    log("warn", "settle_delivered_short", { reason: receipt.errorReason });
  }

  // FEATURE 2 — attach a facilitator-SIGNED, offline-verifiable proof. ONLY a truly
  // successful settlement (tesSUCCESS + delivered>=required) is signed; a failed/
  // rejected settle gets proof:null (a receipt proves a settlement OCCURRED, not future
  // behavior). The proof is an ed25519 signature over the CANONICAL bytes of the
  // load-bearing fields (deterministic, sorted-key, no-whitespace) so a resource server
  // can verify offline with just GET /pubkey. We also surface those exact canonical
  // fields on the receipt (txHash, payTo, required, ts) so a verifier can reconstruct
  // the bytes from the receipt alone (see verifyReceipt + README recipe).
  const ts = now; // deterministic in tests (injected now); Date.now() in prod
  // `delivered` on the receipt is a drops STRING (native) or an issued-amount OBJECT
  // (IOU) or absent on failure. `required` mirrors that shape from the verified value.
  const requiredField = isIou
    ? (requiredTokenValue !== null ? { currency: v.asset.currency, issuer: v.asset.issuer, value: tokenValueToString(requiredTokenValue) } : null)
    : (required !== null ? required.toString() : null);
  receipt.txHash = receipt.transaction || null;
  receipt.payTo = req && typeof req.payTo === "string" ? req.payTo : null;
  receipt.required = requiredField;
  // Surface `asset` on the receipt so a verifier reconstructs the SAME canonical
  // bytes that were signed (IOU receipts otherwise reconstruct asset=null and the
  // signature fails). Native = null on both sides.
  receipt.asset = v.asset ?? null;
  receipt.ts = ts;
  if (receipt.success === true) {
    receipt.proof = signReceipt({
      network: NETWORK,
      txHash: receipt.txHash,
      payer: receipt.payer,
      payTo: receipt.payTo,
      asset: receipt.asset,
      delivered: receipt.delivered ?? null,
      required: requiredField,
      ts,
    });
  } else {
    receipt.proof = null; // failed/rejected settlements are not signed
  }

  // Attach the READ-ONLY Hook execution transparency AFTER signing the proof, so it
  // can never enter the signed canonical bytes (the proof is built solely from the
  // explicit fields above). Most useful on a tecHOOK_REJECTED, where returnString
  // carries the guardrail's rejection reason. Empty array when the tx had no Hook
  // executions. This rides ON the persisted receipt too, so a replayed receipt keeps
  // it; it is purely informational and never re-evaluated.
  receipt.hookExecutions = hookExecutions;

  // (F2) Persist the receipt best-effort. The submit already happened, so the
  // computed receipt is the AUTHORITATIVE outcome even if persistence flaps (Redis
  // down post-submit). A throw here must NOT escape settle (that would 500 and lose
  // the receipt for an APPLIED tx, and a retry would see inFlight forever). The
  // reservation is already held, so failing to memoize the receipt only costs a
  // future retry its idempotent "replayed" receipt — strictly safer than a 500.
  try { await st.setReceipt(v.replayId, receipt, expiryMs); }
  catch (e) { log("warn", "settle_receipt_persist_failed", { stage: "receipt", error: String(e?.name || "store_error") }); }
  return receipt;
}

/** delivered_amount (native XAH) as bigint drops, or null. */
function deliveredDrops(meta) {
  const d = meta.delivered_amount ?? meta.DeliveredAmount;
  if (typeof d === "string" && STRICT_DROPS.test(d)) { try { return BigInt(d); } catch { return null; } }
  return null;
}

/**
 * delivered_amount (issued/IOU) as a raw { currency, issuer, value } object, or null
 * if it is absent or the WRONG type for an IOU (e.g. a drops string when an issued
 * amount was required — fail closed, never coerce). Caller validates currency/issuer/
 * value against the required asset.
 */
function deliveredIssued(meta) {
  const d = meta.delivered_amount ?? meta.DeliveredAmount;
  if (d === null || typeof d !== "object" || Array.isArray(d)) return null;
  if (typeof d.currency !== "string" || typeof d.issuer !== "string" || typeof d.value !== "string") return null;
  return d;
}

// ---------------------------------------------------------------------------
// READ-ONLY transparency: surface the guardrail Hook's on-ledger execution result
// ---------------------------------------------------------------------------
// A validated Payment from a hooked account carries Hook execution data in its tx
// meta as `HookExecutions`: an array of `{ HookExecution: { HookAccount, HookHash,
// HookReturnCode, HookReturnString, HookEmitCount, Flags } }`. This decodes that
// array into a small, informational shape for the settle response.
//
// CRITICAL invariants (this is purely additive + read-only):
//   - It is NEVER part of the signed receipt proof (it rides alongside, unsigned).
//   - It NEVER influences any accept/reject/replay/idempotency decision.
//   - No fabrication: only what is actually in the meta is reported; an absent /
//     unrecognizable HookExecutions array -> []. It NEVER throws (defensive at every
//     access), so it can't break the settle hot path on an unexpected meta shape.
//
// Bound: at most MAX_HOOK_EXECUTIONS entries are reported and each decoded
// returnString is clamped to MAX_HOOK_RETURNSTRING_CHARS printable chars.
const MAX_HOOK_EXECUTIONS = 16;
const MAX_HOOK_RETURNSTRING_CHARS = 256;

/**
 * Decode a hex HookReturnString to a bounded, printable UTF-8 string. Strips
 * non-printable control bytes, clamps length. Returns "" for absent/empty/odd-
 * length/non-hex input. NEVER throws.
 */
function decodeHookReturnString(hex) {
  if (typeof hex !== "string" || hex.length === 0) return "";
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) return "";
  let s;
  try { s = Buffer.from(hex, "hex").toString("utf8"); } catch { return ""; }
  // Strip C0/C1 control chars + DEL (keep printable + space); bound the length.
  // eslint-disable-next-line no-control-regex
  s = s.replace(/[\u0000-\u001F\u007F-\u009F]/g, "");
  if (s.length > MAX_HOOK_RETURNSTRING_CHARS) s = s.slice(0, MAX_HOOK_RETURNSTRING_CHARS);
  return s;
}

/**
 * Decode a validated tx meta's `HookExecutions` into a bounded array of
 * informational records, or [] if absent/unrecognizable. Pure, defensive, never
 * throws. Output record shape (only fields actually present are included as
 * non-undefined; missing numeric fields are omitted, missing strings -> ""):
 *   { hookAccount, hookHash, returnCode, returnString, emitCount?, flags? }
 * `hookHash` is shortened (first 16 hex chars) for readability; `returnString` is
 * the decoded, bounded, printable form of HookReturnString.
 */
function decodeHookExecutions(meta) {
  try {
    if (!meta || typeof meta !== "object") return [];
    const raw = meta.HookExecutions;
    if (!Array.isArray(raw)) return [];
    const out = [];
    for (const entry of raw) {
      if (out.length >= MAX_HOOK_EXECUTIONS) break;
      // Canonical XRPL/Xahau shape wraps each execution in { HookExecution: {...} };
      // accept a bare object too (defensive against node shape variance).
      const he = (entry && typeof entry === "object" && entry.HookExecution && typeof entry.HookExecution === "object")
        ? entry.HookExecution
        : (entry && typeof entry === "object" ? entry : null);
      if (!he) continue;
      const rec = {
        hookAccount: typeof he.HookAccount === "string" ? he.HookAccount : "",
        hookHash: typeof he.HookHash === "string" ? he.HookHash.slice(0, 16) : "",
        returnCode: he.HookReturnCode != null && Number.isFinite(Number(he.HookReturnCode)) ? Number(he.HookReturnCode) : null,
        returnString: decodeHookReturnString(he.HookReturnString),
      };
      if (he.HookEmitCount != null && Number.isFinite(Number(he.HookEmitCount))) rec.emitCount = Number(he.HookEmitCount);
      if (he.Flags != null && Number.isFinite(Number(he.Flags))) rec.flags = Number(he.Flags);
      out.push(rec);
    }
    return out;
  } catch {
    return []; // unknown/hostile meta shape -> [] (never throw into the settle path)
  }
}

// ---------------------------------------------------------------------------
// auth + rate limiting for /settle
// ---------------------------------------------------------------------------
function authOk(req) {
  if (!SHARED_SECRET) return true; // no secret configured => open (reference mode)
  const provided = req.headers["x-x402-secret"];
  if (typeof provided !== "string" || provided.length === 0) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(SHARED_SECRET);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// (#4) proxy-aware client IP for the rate-limiter key
// ---------------------------------------------------------------------------
// X402_TRUST_PROXY = the number of TRUSTED proxy/LB hops in front of this server.
//   0 (default) -> NEVER trust X-Forwarded-For (it is client-spoofable); the key is
//     the direct socket peer address. This is the SAFE default — a deployment behind
//     no proxy, or that hasn't opted in, can't be tricked into trusting a forged XFF.
//   n>0 -> the rightmost `n` XFF entries are the trusted hops we control; the client
//     IP is the (n+1)-th from the right (i.e. the entry the OUTERMOST trusted proxy
//     observed). Anything further left is client-controlled and MUST NOT be trusted.
//     Falls back to the socket address if XFF is missing/short/malformed.
// Keying the limiter off the socket address alone is wrong behind a proxy (every
// client shares the proxy's IP -> one IP throttles everyone); keying off a blindly-
// trusted XFF is wrong with no proxy (a client spoofs XFF to dodge / frame others).
// X402_TRUST_PROXY makes the trust boundary EXPLICIT.
const TRUST_PROXY_HOPS = Math.max(0, Math.floor(Number(process.env.X402_TRUST_PROXY) || 0));

/**
 * Resolve the rate-limit client IP for a request, honoring X402_TRUST_PROXY.
 * Returns a non-empty string (falls back to "unknown" if even the socket addr is
 * absent). NEVER trusts X-Forwarded-For when TRUST_PROXY_HOPS === 0.
 */
function clientIp(req, hops = TRUST_PROXY_HOPS) {
  const socketAddr = (req && req.socket && req.socket.remoteAddress) || "unknown";
  if (!hops || hops <= 0) return socketAddr; // do NOT trust XFF
  const xff = req && req.headers && req.headers["x-forwarded-for"];
  if (typeof xff !== "string" || xff.length === 0) return socketAddr; // missing -> fall back
  // XFF is "client, proxy1, proxy2, ..." (left = original client, right = nearest
  // trusted hop). Strip `hops` trusted entries from the right; the client IP is the
  // next one to the left.
  const parts = xff.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  if (parts.length === 0) return socketAddr; // malformed -> fall back
  // index of the client = parts.length - 1 - hops (the (hops+1)-th from the right).
  const idx = parts.length - 1 - hops;
  if (idx < 0) return socketAddr; // fewer entries than trusted hops -> malformed/short, fall back
  const ip = parts[idx];
  return ip && ip.length > 0 ? ip : socketAddr;
}

const RATE_MAX = Number(process.env.X402_RATE_MAX) || 20; // tokens
const RATE_WINDOW_MS = Number(process.env.X402_RATE_WINDOW_MS) || 60_000;

/**
 * Default in-process token-bucket limiter. EXACTLY the previous behavior: per-IP
 * continuous-refill token bucket (RATE_MAX tokens / RATE_WINDOW_MS), with idle
 * fully-refilled buckets swept so an IP-spray can't grow the map without bound.
 * `ok(ip)` is async to match the injectable interface (a Redis limiter is async);
 * it resolves synchronously here.
 */
export class InMemoryRateLimiter {
  constructor({ max = RATE_MAX, windowMs = RATE_WINDOW_MS } = {}) {
    this.max = max;
    this.windowMs = windowMs;
    this.buckets = new Map(); // ip -> { tokens, ts }
    this._lastSweep = 0;
  }
  sweep(now = Date.now()) {
    for (const [ip, b] of this.buckets) {
      if (now - b.ts >= this.windowMs) this.buckets.delete(ip);
    }
  }
  async ok(ip) {
    const now = Date.now();
    if (now - this._lastSweep >= this.windowMs) { this.sweep(now); this._lastSweep = now; }
    let b = this.buckets.get(ip);
    if (!b) { b = { tokens: this.max, ts: now }; this.buckets.set(ip, b); }
    const refill = ((now - b.ts) / this.windowMs) * this.max;
    b.tokens = Math.min(this.max, b.tokens + refill);
    b.ts = now;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }
}

// (#4) Atomic Redis TOKEN-BUCKET Lua script (replaces the old fixed-window counter).
//
// WHY: a fixed-window counter (INCR + PEXPIRE per window) resets at each window
// boundary, allowing a worst-case burst of up to 2*max across the boundary. A token
// bucket refills CONTINUOUSLY (max tokens per windowMs), so the sustained rate is a
// true `max per windowMs` with no boundary doubling.
//
// LUA SEMANTICS (run atomically by Redis — read-modify-write can't interleave across
// instances, which is exactly why this must be a single script, not multiple round
// trips):
//   KEYS[1]                = the per-IP bucket key (`rl:<ip>`)
//   ARGV[1] = now          (caller's epoch ms — passed in so the script is testable
//                           and not tied to Redis server time)
//   ARGV[2] = max          (bucket capacity, in tokens)
//   ARGV[3] = windowMs     (time to refill from 0 to `max`)
//   ARGV[4] = ttlMs        (key TTL to GC idle buckets; >= windowMs)
//   The script:
//     1. HMGET the stored { tokens, ts }; default to a FULL bucket (tokens=max, ts=now)
//        for a brand-new/expired key.
//     2. refill = (now - ts) * max / windowMs, clamped so tokens never exceeds max and
//        never goes below the stored value (a backwards clock can't add tokens: if
//        now < ts, elapsed is treated as 0).
//     3. If tokens >= 1 -> consume 1 (allow); else allow=0 (deny). ts is advanced to
//        now in BOTH cases (so refill accounting stays correct).
//     4. HSET the new { tokens, ts } + PEXPIRE ttlMs.
//     5. return {allow(1/0), resetMs} where resetMs = ms until >=1 token is available
//        (0 when allowed).
// Tokens are stored as a scaled INTEGER (tokens * SCALE) to avoid Lua float drift; the
// arithmetic is integer throughout. The script is loaded via EVAL (ioredis caches the
// SHA after the first call); callers pass `now` so unit tests are deterministic.
const RL_SCALE = 1000000; // fixed-point scale for fractional tokens (integer math in Lua)
const REDIS_TOKEN_BUCKET_LUA = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local max = tonumber(ARGV[2])
local windowMs = tonumber(ARGV[3])
local ttlMs = tonumber(ARGV[4])
local SCALE = ${RL_SCALE}
local maxScaled = max * SCALE

local data = redis.call('HMGET', key, 't', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil or ts == nil then
  tokens = maxScaled
  ts = now
end

-- continuous refill; a backwards/equal clock adds nothing (elapsed clamped to >= 0).
local elapsed = now - ts
if elapsed < 0 then elapsed = 0 end
-- refillScaled = elapsed * maxScaled / windowMs  (integer math; windowMs > 0)
local refill = math.floor(elapsed * maxScaled / windowMs)
tokens = tokens + refill
if tokens > maxScaled then tokens = maxScaled end

local allow = 0
local resetMs = 0
if tokens >= SCALE then
  tokens = tokens - SCALE
  allow = 1
else
  -- ms until one whole token (SCALE units) has refilled.
  local deficit = SCALE - tokens
  resetMs = math.ceil(deficit * windowMs / maxScaled)
end

redis.call('HSET', key, 't', tokens, 'ts', now)
redis.call('PEXPIRE', key, ttlMs)
return {allow, resetMs}
`;

/**
 * Optional Redis TOKEN-BUCKET limiter (multi-instance SHARED). Atomic via a single
 * EVAL of REDIS_TOKEN_BUCKET_LUA (see the script's comment for exact semantics): a
 * per-IP continuous-refill bucket of `max` tokens / `windowMs`, refilled by elapsed
 * time, consuming 1 per request. This MATCHES the in-memory limiter's continuous-
 * refill model (so behavior is consistent whichever backend is active) and removes the
 * fixed-window 2*max boundary burst. ttl GCs idle buckets. `ok(ip)` returns a boolean
 * (true = allowed); the script also returns a reset hint we currently ignore.
 *
 * FALLBACK: if EVAL itself fails (e.g. the Redis build lacks scripting — vanishingly
 * rare, but never assume), we FAIL CLOSED on the rate-limit decision: a limiter that
 * cannot evaluate must DENY (return false), never silently allow unlimited traffic.
 */
export class RedisRateLimiter {
  constructor(redis, { max = RATE_MAX, windowMs = RATE_WINDOW_MS } = {}) {
    this.redis = redis;
    this.max = max;
    this.windowMs = windowMs;
    // TTL must outlive a window so a bucket mid-refill isn't GC'd; 2*window is safe.
    this.ttlMs = windowMs * 2;
  }
  async ok(ip, now = Date.now()) {
    const key = `rl:${ip}`;
    try {
      const r = await this.redis.eval(
        REDIS_TOKEN_BUCKET_LUA, 1, key,
        String(now), String(this.max), String(this.windowMs), String(this.ttlMs)
      );
      // ioredis returns Lua numbers as JS numbers (or strings on some versions); the
      // first element is allow (1/0). Coerce defensively.
      const allow = Array.isArray(r) ? Number(r[0]) : Number(r);
      return allow === 1;
    } catch (e) {
      // A limiter that cannot evaluate must FAIL CLOSED (deny), never allow unbounded.
      log("error", "rate_limiter_eval_failed", { error: String(e?.name || "eval_error") });
      return false;
    }
  }
}

// Module-level default limiter used by the production code paths (overridable via
// _deps.rateLimiter in settle/handler, and rebuilt by createRateLimiter at boot).
let rateLimiter = new InMemoryRateLimiter();
/**
 * Build the configured limiter. With X402_REDIS_URL set -> RedisRateLimiter sharing
 * the store's Redis client (so multi-instance rate limiting is also shared); else
 * the default in-process token bucket. Must be called AFTER createStore so the
 * Redis client exists.
 */
export function createRateLimiter() {
  if (process.env.X402_REDIS_URL && _redisClient) {
    return new RedisRateLimiter(_redisClient);
  }
  return new InMemoryRateLimiter();
}

// Back-compat shim for the existing rate-limit unit test (sync-feeling .ok()).
async function rateLimitOk(ip) { return rateLimiter.ok(ip); }
// test hook: expose the in-memory limiter's bucket sweeper + map for assertions.
function _sweepBuckets(now) {
  if (rateLimiter instanceof InMemoryRateLimiter) { rateLimiter.sweep(now); return rateLimiter.buckets; }
  return new Map();
}

// ---------------------------------------------------------------------------
// boot-time config validation (factored out so it is unit-testable)
// ---------------------------------------------------------------------------
/**
 * Validate the runtime env (pass a plain object, defaults to process.env). Returns
 * { fatal: string[], warnings: string[] }. FATAL entries are misconfigurations the
 * operator almost certainly did NOT intend (a non-numeric PORT, a malformed
 * XAHAU_WSS / X402_REDIS_URL URL, an inconsistent network id) — serve() exits
 * non-zero on any fatal. WARNINGS are non-fatal gaps (e.g. XAHAU_WSS unset ->
 * /settle disabled) that are logged but do not crash. This function NEVER exits or
 * logs itself — the caller decides.
 */
export function validateConfig(env = process.env) {
  const fatal = [];
  const warnings = [];

  // PORT: if explicitly set, must be a sane TCP port number.
  if (env.PORT !== undefined && env.PORT !== "") {
    const p = Number(env.PORT);
    if (!Number.isInteger(p) || p < 1 || p > 65535)
      fatal.push(`PORT="${env.PORT}" is not a valid TCP port (1-65535)`);
  }

  // XAHAU_WSS: optional, but if set must be a ws:// or wss:// URL. Unset -> settle
  // is disabled (non-fatal warning).
  if (env.XAHAU_WSS !== undefined && env.XAHAU_WSS !== "") {
    let ok = false;
    try { const u = new URL(env.XAHAU_WSS); ok = u.protocol === "ws:" || u.protocol === "wss:"; } catch { ok = false; }
    if (!ok) fatal.push(`XAHAU_WSS="${env.XAHAU_WSS}" is not a ws:// or wss:// URL`);
  } else {
    warnings.push("XAHAU_WSS is not set — /settle is DISABLED (offline /verify only)");
  }

  // Network id consistency: if both XAHAU_NETWORK and XAHAU_NETWORK_ID are set, the
  // named network's known id must match the explicit id. An explicit-only id is fine.
  if (env.XAHAU_NETWORK !== undefined && env.XAHAU_NETWORK !== "") {
    const known = NETWORK_IDS[env.XAHAU_NETWORK];
    if (known === undefined)
      fatal.push(`XAHAU_NETWORK="${env.XAHAU_NETWORK}" is not a known network (${Object.keys(NETWORK_IDS).join(", ")})`);
    else if (env.XAHAU_NETWORK_ID !== undefined && env.XAHAU_NETWORK_ID !== "" && Number(env.XAHAU_NETWORK_ID) !== known)
      fatal.push(`XAHAU_NETWORK_ID="${env.XAHAU_NETWORK_ID}" disagrees with XAHAU_NETWORK="${env.XAHAU_NETWORK}" (expected ${known})`);
  }
  if (env.XAHAU_NETWORK_ID !== undefined && env.XAHAU_NETWORK_ID !== "") {
    const n = Number(env.XAHAU_NETWORK_ID);
    if (!Number.isInteger(n) || n <= 0)
      fatal.push(`XAHAU_NETWORK_ID="${env.XAHAU_NETWORK_ID}" is not a positive integer`);
  }

  // X402_REDIS_URL: optional; if set, must be a redis(s):// URL.
  if (env.X402_REDIS_URL !== undefined && env.X402_REDIS_URL !== "") {
    let ok = false;
    try { const u = new URL(env.X402_REDIS_URL); ok = u.protocol === "redis:" || u.protocol === "rediss:"; } catch { ok = false; }
    // Do NOT echo the value — a redis URL can carry an embedded password.
    if (!ok) fatal.push(`X402_REDIS_URL is set but is not a redis:// or rediss:// URL`);
  }

  return { fatal, warnings };
}

// ---------------------------------------------------------------------------
// /health + /metrics builders (cheap, never throw)
// ---------------------------------------------------------------------------
/**
 * Build the /health object. NEVER throws (caught internally) and is HONEST:
 * connectivity it cannot determine is reported as a falsy/unknown value rather than
 * fabricated as healthy.
 *
 * AUTH SPLIT: an UNAUTHENTICATED caller (LB liveness probe) gets only the MINIMAL
 * shape { status, network, uptimeSec } — enough to decide "alive?" without exposing
 * internals. An AUTHENTICATED caller (authed===true; same shared-secret check as
 * /settle) additionally gets the sensitive operational internals (replayStore /
 * rateLimiter backend, redisConnected, xrplConnected, xrplConfigured, networkID,
 * replayBindings). When NO secret is configured (reference mode) the route treats
 * every caller as authed, so the verbose object is returned (matches /settle being
 * open in that mode).
 *
 * `xrplConnected` is only truthy if a pooled client object reports isConnected();
 * we do NOT open a connection here (health must be cheap) — if no client has been
 * built yet it is reported `false` (unknown-but-not-claimed-healthy). Same honesty
 * for Redis: only reported connected if the client exposes a 'ready' status.
 */
function buildHealth(authed = true) {
  // Minimal liveness shape — always safe to expose unauthenticated.
  const h = {
    status: "ok",
    network: NETWORK,
    uptimeSec: Math.floor((Date.now() - BOOT_TS) / 1000),
  };
  if (!authed) return h;
  // Verbose (authenticated) internals.
  h.networkID = EXPECTED_NETWORK_ID;
  h.replayStore = "memory";
  h.rateLimiter = "memory";
  h.xrplConfigured = !!process.env.XAHAU_WSS;
  h.replayBindings = 0;
  try {
    const usingRedis = !!process.env.X402_REDIS_URL;
    h.replayStore = (store instanceof RedisStore) ? "redis" : "memory";
    h.rateLimiter = (rateLimiter instanceof RedisRateLimiter) ? "redis" : "memory";
    if (usingRedis || h.replayStore === "redis" || h.rateLimiter === "redis") {
      // Honest: only claim connected if ioredis reports status === "ready".
      h.redisConnected = !!(_redisClient && _redisClient.status === "ready");
    }
    // xrpl connectivity: report configured + (best-effort, no new connection) connected.
    if (h.xrplConfigured) {
      h.xrplConnected = !!(_client && typeof _client.isConnected === "function" && _client.isConnected());
    }
    // replayBindings: best-effort live-entry count. For the in-memory store this is
    // O(1) via the backing map; size() is async, so use the cheap synchronous map
    // size when available and fall back to 0 (never throw, never block).
    if (store && store.map instanceof Map) h.replayBindings = store.map.size;
  } catch {
    // Health must never throw. Degrade to status:"degraded" with what we have.
    h.status = "degraded";
  }
  return h;
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------
// Shutdown drain budget: how long in-flight requests get to finish on SIGTERM/INT
// before we force-close. Kept short so orchestrators' kill grace isn't exceeded.
const SHUTDOWN_DRAIN_MS = Number(process.env.X402_SHUTDOWN_DRAIN_MS) || 10000;

// Slowloris / resource-exhaustion bounds (applied on the server in serve(), never
// at import). requestTimeout caps the total time to receive a full request (a slow
// drip body can't tie up a socket forever); headersTimeout caps time to receive the
// headers; maxConnections caps concurrent sockets so a connection flood can't
// exhaust fds. These complement the existing MAX_BODY_BYTES (size) bound with TIME +
// COUNT bounds. Values are conservative defaults; maxConnections is env-tunable.
const REQUEST_TIMEOUT_MS = Number(process.env.X402_REQUEST_TIMEOUT_MS) || 15000;
const HEADERS_TIMEOUT_MS = Number(process.env.X402_HEADERS_TIMEOUT_MS) || 10000;
const MAX_CONNECTIONS = Math.max(1, Number(process.env.X402_MAX_CONNECTIONS) || 1024);

function serve() {
  // (6) Boot-time config validation: FAIL FAST on a fatal misconfig (bad PORT,
  // malformed URLs, inconsistent network id); LOG warnings for non-fatal gaps
  // (e.g. XAHAU_WSS unset -> settle disabled) without crashing. Done HERE (not at
  // import) so tests importing the module never trigger an exit.
  const cfg = validateConfig(process.env);
  for (const w of cfg.warnings) logWarn("config_warning", { message: w });
  if (cfg.fatal.length) {
    logError("config_fatal", { errors: cfg.fatal });
    process.exit(1);
  }

  // Boot-time backend selection. createStore FAILS FAST if X402_REDIS_URL is set
  // but ioredis is missing (never a silent non-shared fallback). createRateLimiter
  // must follow so it can share the Redis client when configured.
  store = createStore();
  rateLimiter = createRateLimiter();
  const server = http.createServer(async (req, res) => {
    try {
      // --- liveness/readiness: cheap, never throws ---------------------------
      // The MINIMAL { status, network, uptimeSec } shape is ALWAYS unauthenticated
      // (LB liveness probes must not need a secret). The verbose operational
      // internals are returned ONLY to an authenticated caller (authOk — same
      // shared-secret check as /settle). In reference mode (no SHARED_SECRET) authOk
      // is always true, so the verbose object is returned to everyone.
      if (req.method === "GET" && req.url === "/health")
        return send(res, 200, buildHealth(authOk(req)));

      // --- metrics: JSON by default, Prometheus text on Accept: text/plain ---
      // /metrics exposes operational counters and is auth-gated behind the same
      // shared secret as /settle (401 if it fails). In reference mode (no
      // SHARED_SECRET) it stays open, mirroring /settle.
      if (req.method === "GET" && req.url === "/metrics") {
        if (!authOk(req)) return send(res, 401, { error: "unauthorized" });
        const accept = String(req.headers["accept"] || "");
        if (/text\/plain/i.test(accept)) {
          const body = metricsPrometheus();
          res.writeHead(200, { "content-type": "text/plain; version=0.0.4", "content-length": Buffer.byteLength(body) });
          return res.end(body);
        }
        return send(res, 200, { ...metrics });
      }

      if (req.method === "GET" && req.url === "/supported")
        // x402 discovery: { kinds: [{ x402Version, scheme, network }] }. We add the
        // spec's `x402Version: 2` alongside the original {scheme, network}.
        return send(res, 200, { kinds: [{ x402Version: 2, scheme: "exact", network: NETWORK }] });

      // FEATURE 2 — GET /pubkey: the facilitator's ed25519 receipt verification key
      // (raw 32-byte hex). Public (a verification key is not a secret). Lets a resource
      // server verify signed receipts OFFLINE. No auth, rate-limited like other GETs.
      if (req.method === "GET" && req.url === "/pubkey") {
        const ip = clientIp(req);
        if (!(await rateLimiter.ok(ip))) { metricInc("rate_limited_total"); return send(res, 429, { error: "rate limited" }); }
        return send(res, 200, receiptPubkey());
      }

      // FEATURE 1 — GET /policy/:account: read the agent's on-ledger guardrail Hook
      // and surface its spending policy (per-tx LIM cap + DST allowlist) straight from
      // the chain. Read-only, public (on-ledger data). Needs XAHAU_WSS (like settle);
      // 503 if unset. FAIL-TRANSPARENT: node/decoding errors -> policy:null + a note,
      // never a fabricated limit.
      if (req.method === "GET" && typeof req.url === "string" && req.url.startsWith("/policy/")) {
        const ip = clientIp(req);
        if (!(await rateLimiter.ok(ip))) { metricInc("rate_limited_total"); return send(res, 429, { error: "rate limited" }); }
        const account = decodeURIComponent(req.url.slice("/policy/".length).split("?")[0]);
        if (!isValidRAddress(account)) return send(res, 400, { error: "invalid account address" });
        if (!process.env.XAHAU_WSS) return send(res, 503, { error: "node not configured (set XAHAU_WSS)" });
        let client;
        try { client = await getClient(); }
        catch {
          // Node unreachable -> fail transparent (never fabricate). 503 so the caller retries.
          return send(res, 503, { account, guardrailHookPresent: null, policy: null, source: "on-ledger", asOfLedger: null, note: "node unavailable — policy unknown" });
        }
        const out = await getPolicy(client, account);
        return send(res, 200, out);
      }

      // FEATURE 3 — GET /status/:id: look up a stored settlement by its replayId or a
      // `hash:<txhash>` key. AUTH-GATED (it exposes payment data) — 401 without the
      // shared secret when one is configured; open in reference mode. Honest "unknown"
      // when not found / expired. Pulls from the existing receipt store only.
      if (req.method === "GET" && typeof req.url === "string" && req.url.startsWith("/status/")) {
        if (!authOk(req)) return send(res, 401, { error: "unauthorized" });
        const ip = clientIp(req);
        if (!(await rateLimiter.ok(ip))) { metricInc("rate_limited_total"); return send(res, 429, { error: "rate limited" }); }
        const id = decodeURIComponent(req.url.slice("/status/".length).split("?")[0]);
        if (!id) return send(res, 400, { error: "missing id" });
        let receipt;
        try { receipt = await store.getReceipt(id); }
        catch { return send(res, 503, { found: false, status: "unknown", error: "store unavailable", retryable: true }); }
        if (receipt) {
          // A memoized receipt with success:false is a terminal on-ledger settlement;
          // status "settled" reflects that a final outcome was recorded (success flag
          // tells the rest of the story). We expose found + the stored receipt verbatim.
          return send(res, 200, { found: true, status: "settled", receipt });
        }
        // No receipt. The binding may still be live (in-flight) but we only expose the
        // receipt store here; report "unknown" honestly rather than guessing.
        return send(res, 200, { found: false, status: "unknown" });
      }

      // FEATURE 4 — POST /simulate: predict the guardrail Hook's accept/rollback for a
      // payment WITHOUT submitting (advisory). ONLY enabled when X402_MCP_URL is set;
      // otherwise 404 (feature entirely off, no coupling). Rate-limited; not auth-gated
      // (it's a read-only prediction, like /verify). Fails SOFT.
      if (req.method === "POST" && req.url === "/simulate") {
        if (!process.env.X402_MCP_URL) return send(res, 404, { error: "simulation not enabled (set X402_MCP_URL)" });
        const ip = clientIp(req);
        if (!(await rateLimiter.ok(ip))) { metricInc("rate_limited_total"); return send(res, 429, { error: "rate limited" }); }
        const b = await readBody(req, res);
        const sim = await simulatePayment(b.paymentPayload, b.paymentRequirements, {});
        return send(res, 200, { advisory: true, simulation: sim });
      }

      if (req.method === "POST" && req.url === "/verify") {
        // /verify decodes a full tx blob + runs signature crypto — an
        // unauthenticated, CPU-bound path. It MUST be rate-limited (but NOT
        // auth-gated: it is intentionally a public, pre-payment offline check, so
        // requiring a secret would break x402 semantics).
        const ip = clientIp(req);
        if (!(await rateLimiter.ok(ip))) { metricInc("rate_limited_total"); return send(res, 429, { error: "rate limited" }); }
        const b = await readBody(req, res);
        metricInc("verify_total");
        return send(res, 200, verifyExact(b.paymentPayload, b.paymentRequirements));
      }

      if (req.method === "POST" && req.url === "/settle") {
        if (!authOk(req)) return send(res, 401, { error: "unauthorized" });
        const ip = clientIp(req);
        if (!(await rateLimiter.ok(ip))) { metricInc("rate_limited_total"); return send(res, 429, { error: "rate limited" }); }
        const b = await readBody(req, res);
        // FEATURE 4 — an optional `dryRun:true` on the body returns the advisory
        // prediction and does NOT submit / reserve a slot. The fee-saving predicted-
        // reject short-circuit is opt-in via `preSimReject:true`. Both are advisory and
        // never weaken the real settle (a predicted-accept still runs the full settle).
        const dryRun = b && b.dryRun === true;
        const preSimReject = b && b.preSimReject === true;
        const out = await settle(b.paymentPayload, b.paymentRequirements, { store, rateLimiter, dryRun, preSimReject });
        // Replay store full of live (unexpired) bindings: fail closed with 503 so
        // the client retries later, rather than evicting a live binding (Hole 2).
        const status = out && out.retryable === true ? 503 : 200;
        return send(res, status, out);
      }

      send(res, 404, { error: "not found" });
    } catch (e) {
      // readBody already wrote a clean response (e.g. 413 on oversize body) —
      // never send a second one.
      if (e === ALREADY_RESPONDED) return;
      // (6b) Do not reflect raw error messages to clients; log server-side as a
      // structured event (no stack/secret leaked to the client).
      const status = e?.statusCode || 500;
      logError("request_error", { method: req.method, path: req.url, status, error: String(e?.message || e) });
      if (!res.headersSent) send(res, status, { error: status === 500 ? "internal error" : "bad request" });
    }
  });

  // Track in-flight requests so graceful shutdown can drain them before exit.
  let inFlight = 0;
  server.on("request", (req, res) => {
    inFlight++;
    res.on("finish", () => { inFlight--; });
    res.on("close", () => { /* finish already decremented; close after finish is a no-op */ });
  });

  // Slowloris / flood bounds (set HERE on the live server, never at import). A slow
  // client cannot drip a request indefinitely (requestTimeout/headersTimeout) and a
  // connection flood cannot exhaust file descriptors (maxConnections).
  server.requestTimeout = REQUEST_TIMEOUT_MS;
  server.headersTimeout = HEADERS_TIMEOUT_MS;
  server.maxConnections = MAX_CONNECTIONS;

  server.listen(PORT, () => logInfo("listening", { port: Number(PORT), network: NETWORK, networkID: EXPECTED_NETWORK_ID }));

  // (5) Graceful shutdown — attached ONLY here (never at import) so tests don't get
  // signal handlers / process.exit. On SIGTERM/SIGINT: stop accepting new conns
  // (server.close), let in-flight finish within a bounded drain, then close the xrpl
  // client + Redis, then exit. A second signal forces immediate exit.
  let shuttingDown = false;
  const shutdown = (signal) => {
    if (shuttingDown) { logWarn("shutdown_forced", { signal }); process.exit(1); return; }
    shuttingDown = true;
    logInfo("shutdown_begin", { signal, inFlight });
    // Stop accepting new connections; callback fires once all conns are closed.
    server.close(async () => {
      await closeBackends();
      logInfo("shutdown_complete", {});
      process.exit(0);
    });
    // Close IDLE (keep-alive but not actively serving) connections immediately so a
    // slow/idle client holding a socket open can't ride out the entire drain budget
    // and stall server.close(). In-flight requests (their sockets are NOT idle) are
    // left alone to finish within the bounded drain below. Guarded: older Node may
    // lack closeIdleConnections.
    try { if (typeof server.closeIdleConnections === "function") server.closeIdleConnections(); }
    catch (e) { logWarn("shutdown_close_idle_failed", { error: String(e?.message || e) }); }
    // Bounded drain: if in-flight work doesn't finish in time, force-close + exit.
    const timer = setTimeout(async () => {
      logWarn("shutdown_drain_timeout", { inFlight, drainMs: SHUTDOWN_DRAIN_MS });
      await closeBackends();
      process.exit(0);
    }, SHUTDOWN_DRAIN_MS);
    if (typeof timer.unref === "function") timer.unref();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));

  return server;
}

/**
 * Best-effort close of external connections (xrpl client + Redis). Never throws;
 * each is independently guarded so one failing doesn't block the other. Factored
 * out so shutdown logic is testable in isolation.
 */
export async function closeBackends() {
  try { if (_client && typeof _client.disconnect === "function") await _client.disconnect(); }
  catch (e) { logWarn("xrpl_close_failed", { error: String(e?.message || e) }); }
  _client = null;
  try { if (_redisClient && typeof _redisClient.quit === "function") await _redisClient.quit(); }
  catch (e) { logWarn("redis_close_failed", { error: String(e?.message || e) }); }
}

// run only when invoked directly (not when imported by test.mjs)
if (import.meta.url === `file://${process.argv[1]}`) serve();

// ---------------------------------------------------------------------------
// test hooks
// ---------------------------------------------------------------------------
// The replay-store internals are now methods on the default InMemoryStore `store`.
// These shims preserve the previous hook surface but are ASYNC where the store is
// (tests await them). `consumed` is exposed as a live getter onto store.map so the
// existing tests that manipulate the raw Map directly (.set/.clear/.has/.size) keep
// working against whichever in-memory store is current.
//
// _markConsumed maps to the store's unconditional, cap-honoring upsert (`set`) —
// EXACTLY the previous markConsumed semantics (overwrite an existing key -> true;
// full + key absent -> false). `reserve` is the separate ATOMIC test-and-set
// primitive used by settle (returns "reserved"|"exists"|"full").
async function _sweepConsumed(now) { store._sweep(now ?? Date.now()); return store.map; }
async function _markConsumed(key, ctx, now) { return store.set(key, consumedExpiryFor(ctx, now), now); }
async function _isConsumed(key, now) { return store.isConsumed(key, now); }
function _consumedExpiryFor(ctx, now) { return consumedExpiryFor(ctx, now); }
async function _reserveConsumed(key, ctx, now) { return store.reserve(key, consumedExpiryFor(ctx, now), now); }
// Swap the default store/limiter (e.g. tests injecting a fresh InMemoryStore).
function __setStore(s) { store = s; }
function __setRateLimiter(l) { rateLimiter = l; }

export const __test = {
  parseStrictDrops, isValidRAddress, verifyTxSignature, deriveAddressFromPubKey,
  replayKeyFor, settle, _sweepBuckets, rateLimitOk, submitDefinitelyNotApplied,
  RATE_MAX,
  // (#3) on-ledger auth seams: pure decision fn + the multisigning/verify primitives.
  authorizeOnLedger_decide, keypairVerify, encodeForMultisigning,
  // (#4) proxy-aware client IP + the token-bucket Lua source.
  clientIp, REDIS_TOKEN_BUCKET_LUA, RL_SCALE,
  // Issued-amount (IOU/token) helpers.
  parseTokenValue, cmpTokenValue, canonicalizeCurrency, tokenValueToString,
  checkIssuedAmount, deliveredIssued, deliveredDrops,
  // READ-ONLY Hook-execution transparency (informational; not in the signed proof).
  decodeHookExecutions, decodeHookReturnString,
  TOKEN_EXP_MIN, TOKEN_EXP_MAX, TOKEN_MAX_MANT_DIGITS,
  // Hole-1/Hole-2 hooks: replay-store internals + the chosen bounds.
  _sweepConsumed, _markConsumed, _isConsumed, _consumedExpiryFor, _reserveConsumed,
  REPLAY_TTL_MS, REPLAY_MAX_ENTRIES, MAX_VALIDITY_LEDGERS, LEDGER_CLOSE_MS, REPLAY_EXPIRY_MARGIN_MS,
  // Injectable backends + seams for the Redis-contract tests.
  InMemoryStore, RedisStore, InMemoryRateLimiter, RedisRateLimiter,
  consumedExpiryFor, __setStore, __setRateLimiter,
  // Operational-hardening seams: config validator, health builder, metrics,
  // metric helpers (so tests can assert counters move on real events).
  validateConfig, buildHealth, metricsPrometheus, recordSettleReject, closeBackends,
  metrics, metricInc,
  // FEATURE 1 — on-ledger policy introspection seams.
  getPolicy, hookParamsMap, decode8ByteDropsHex, accountIdHexToRAddress,
  HOOK_PARAM_LIM, HOOK_PARAM_DST,
  // FEATURE 2 — receipt signing/verification seams.
  canonicalJSONStringify, receiptSignablePayload, signReceipt, verifyReceipt,
  receiptPubkey, initReceiptKey, parseReceiptSecret, ed25519KeyFromSeed,
  // FEATURE 4 — advisory simulation seam.
  simulatePayment,
  // Live view of the default store's backing map (back-compat with raw-Map tests).
  get consumed() { return store.map; },
  get store() { return store; },
};
