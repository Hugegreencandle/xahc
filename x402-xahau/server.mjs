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
 * Signatures are bound to Account (deriveAddress == Account); RegularKey/multisig
 * are offline-unverifiable and are flagged (signatureVerified:false), not passed.
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
import { decode } from "xrpl-binary-codec-prerelease";

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
      const m = require_("ripple-address-codec");
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

/**
 * Cryptographically verify the tx blob's signature against its SigningPubKey
 * (single-sig) using the xrpl library. Returns true/false; null if xrpl is not
 * installed (caller decides how to treat "cannot verify").
 */
let _xrplVerify = undefined;
function verifyTxSignature(txBlob) {
  if (_xrplVerify === undefined) {
    try { _xrplVerify = require_("xrpl").verifySignature; }
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
    try { _deriveAddress = require_("ripple-keypairs").deriveAddress; }
    catch { _deriveAddress = null; }
  }
  if (typeof _deriveAddress !== "function") return null;
  try { return _deriveAddress(pubKey); }
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
    if (paid > maxDrops)
      return { isValid: false, invalidReason: "Amount > maxAmountRequired" };
  } else {
    // Issued-amount (IOU/token) path.
    if (typeof tx.Amount === "string")
      return { isValid: false, invalidReason: "asset mismatch: issued amount required but Amount is native XAH" };
    const chk = checkIssuedAmount(tx.Amount, asset, maxTokenValue);
    if (chk.error) return { isValid: false, invalidReason: chk.error };
    paidTokenValue = chk.value;
  }

  if (tx.LastLedgerSequence == null)
    return { isValid: false, invalidReason: "missing LastLedgerSequence (no expiry window)" };

  // (2) Signature is cryptographically VERIFIED, not merely present.
  const isMultisig = Array.isArray(tx.Signers) && tx.Signers.length > 0;
  if (!tx.TxnSignature && !isMultisig)
    return { isValid: false, invalidReason: "unsigned (no TxnSignature/Signers)" };
  const sigOk = verifyTxSignature(payload.txBlob);
  if (sigOk === false)
    return { isValid: false, invalidReason: "invalid signature" };

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
  //   - single-sig: require deriveAddress(SigningPubKey) === Account, else FAIL;
  //   - multisig:   cannot bind offline -> signatureVerified:false (flagged,
  //                 not silently passed); the on-chain settle is the authority.
  let signatureVerified = false;
  if (isMultisig) {
    // Offline single-sig path can't validate a SignerList. Flag, don't pass.
    signatureVerified = false;
  } else if (sigOk === true) {
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
  try { ({ Client } = await import("xrpl")); }
  catch { throw new Error("xrpl not installed"); }
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
// settle
// ---------------------------------------------------------------------------
/**
 * Submit the signed tx to Xahau. Re-validates EVERYTHING (does not trust /verify
 * was called), enforces single-use replay binding, and checks delivered_amount.
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

/**
 * Optional Redis fixed-window limiter (multi-instance SHARED). SEMANTICS, stated
 * honestly: this is a FIXED-WINDOW counter, NOT a continuous-refill token bucket.
 * Each IP gets a per-window key (`rl:<ip>:<windowIndex>`); the first request in a
 * window INCRs to 1 and PEXPIREs the key to the window length; subsequent requests
 * INCR and are allowed while the count <= max. At a window boundary the counter
 * resets to 0, so the worst-case burst is up to 2*max across a boundary — the
 * standard, accepted trade-off for a cheap distributed limiter. (A Lua token bucket
 * would smooth this but is heavier; fixed-window is sufficient and documented.)
 */
export class RedisRateLimiter {
  constructor(redis, { max = RATE_MAX, windowMs = RATE_WINDOW_MS } = {}) {
    this.redis = redis;
    this.max = max;
    this.windowMs = windowMs;
  }
  async ok(ip) {
    const now = Date.now();
    const windowIndex = Math.floor(now / this.windowMs);
    const key = `rl:${ip}:${windowIndex}`;
    const n = await this.redis.incr(key);
    if (n === 1) await this.redis.pexpire(key, this.windowMs);
    return n <= this.max;
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

      if (req.method === "POST" && req.url === "/verify") {
        // /verify decodes a full tx blob + runs signature crypto — an
        // unauthenticated, CPU-bound path. It MUST be rate-limited (but NOT
        // auth-gated: it is intentionally a public, pre-payment offline check, so
        // requiring a secret would break x402 semantics).
        const ip = req.socket.remoteAddress || "unknown";
        if (!(await rateLimiter.ok(ip))) { metricInc("rate_limited_total"); return send(res, 429, { error: "rate limited" }); }
        const b = await readBody(req, res);
        metricInc("verify_total");
        return send(res, 200, verifyExact(b.paymentPayload, b.paymentRequirements));
      }

      if (req.method === "POST" && req.url === "/settle") {
        if (!authOk(req)) return send(res, 401, { error: "unauthorized" });
        const ip = req.socket.remoteAddress || "unknown";
        if (!(await rateLimiter.ok(ip))) { metricInc("rate_limited_total"); return send(res, 429, { error: "rate limited" }); }
        const b = await readBody(req, res);
        const out = await settle(b.paymentPayload, b.paymentRequirements, { store, rateLimiter });
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
  // Issued-amount (IOU/token) helpers.
  parseTokenValue, cmpTokenValue, canonicalizeCurrency, tokenValueToString,
  checkIssuedAmount, deliveredIssued, deliveredDrops,
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
  // Live view of the default store's backing map (back-compat with raw-Map tests).
  get consumed() { return store.map; },
  get store() { return store; },
};
