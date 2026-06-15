#!/usr/bin/env node
/**
 * exact-xahau — a reference x402 facilitator for Xahau (hardened).
 *
 * Implements the x402 facilitator surface for the proposed `exact-xahau` scheme
 * (see ../docs/X402-XAHAU.md):
 *   GET  /supported  -> advertise {scheme:"exact", network:"xahau"}
 *   POST /verify     -> offline checks on a signed Xahau Payment vs the requirements
 *   POST /settle     -> submit the signed tx to Xahau (needs XAHAU_WSS)
 *
 * Threat model: hostile clients. Every check is enforced; absence of a bound is
 * treated as a FAILURE, never a skip. Signatures are cryptographically verified.
 * The payer's on-chain xahc **guardrail Hook** is the L1 spending authority, but
 * the facilitator (a) honestly reports whether that Hook is actually installed and
 * (b) re-validates everything at /settle and checks delivered_amount — it never
 * trusts that /verify was called, and it refuses to settle the same payment twice.
 *
 * This is REFERENCE-GRADE HARDENED, not production: the replay store is in-memory
 * (does not survive restart, not shared across instances) and rate-limiting is a
 * single-process token bucket. Both in-memory stores are BOUNDED so they can't
 * grow without bound under load / IP-spray. The replay store is also REPLAY-SAFE:
 * each binding's expiry is tied to the tx's actual on-ledger validity window (so a
 * binding never expires while its tx is still submittable), settle rejects any tx
 * whose window exceeds the bound, and the hard-cap eviction is fail-CLOSED (drops
 * only EXPIRED entries; refuses new reservations with 503 when full of live ones —
 * never evicts a live binding). A submit that fails AMBIGUOUSLY (LastLedgerSequence
 * passed mid-wait / disconnect / timeout) RETAINS the reservation — only a
 * provably-not-applied preliminary `tem*` result releases it, so a maybe-applied tx
 * can never be settled twice. Both public POST paths (/verify and /settle) are
 * rate-limited; /settle additionally requires the shared secret. A production
 * deployment still needs a shared/durable nonce store (e.g. Redis/DB) and a
 * distributed rate limiter.
 * Signatures are bound to Account (deriveAddress == Account); RegularKey/multisig
 * are offline-unverifiable and are flagged (signatureVerified:false), not passed.
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
  const maxDrops = parseStrictDrops(req.maxAmountRequired);
  if (maxDrops === null)
    return { isValid: false, invalidReason: "incomplete payment requirements (maxAmountRequired missing/invalid)" };

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

  // Native XAH only in this reference. Issued amounts are an open spec item.
  if (typeof tx.Amount !== "string")
    return { isValid: false, invalidReason: "issued-amount verify not implemented in this shim (native XAH only)" };
  const paid = parseStrictDrops(tx.Amount);
  if (paid === null)
    return { isValid: false, invalidReason: "Amount malformed (must be positive drops string)" };
  if (paid > maxDrops)
    return { isValid: false, invalidReason: "Amount > maxAmountRequired" };

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

  return {
    isValid: true,
    invalidReason: null,
    payer: tx.Account,
    amount: paid.toString(),
    signatureVerified,
    replayId,
  };
}

/** Stable replay key for a decoded tx: InvoiceID if present, else acct:seq. */
function replayKeyFor(tx) {
  if (typeof tx.InvoiceID === "string" && tx.InvoiceID.length) return `inv:${tx.InvoiceID}`;
  return `acct:${tx.Account}:${tx.Sequence}`;
}

// ---------------------------------------------------------------------------
// replay store (reference-grade, in-memory — does NOT survive restart)
// ---------------------------------------------------------------------------
// Map<key, expiryEpochMs>. Entries (replayId + tx hash) expire so the store cannot
// grow without bound (slow memory-exhaustion DoS). A tx is (re)submittable until
// its LastLedgerSequence is passed by the validated ledger, so each entry's expiry
// is bound to that REAL on-ledger window (consumedExpiryFor: now + ledgerGap*~4s +
// margin), NOT a flat TTL — a flat TTL shorter than the window would expire the
// binding while the tx is still replayable (Hole 1). settle independently REJECTS
// any tx whose window exceeds MAX_VALIDITY_LEDGERS (derived so the longest accepted
// window still fits inside REPLAY_TTL_MS), so the flat TTL is a safe outer bound.
// Eviction under the HARD CAP is expiry-aware + fail-CLOSED: only EXPIRED entries
// are reclaimed; if the store is full of live bindings a new reservation is
// REFUSED (503) rather than dropping a live binding (Hole 2).
const REPLAY_TTL_MS = Number(process.env.X402_REPLAY_TTL_MS) || 60 * 60 * 1000; // 1h
const REPLAY_MAX_ENTRIES = Number(process.env.X402_REPLAY_MAX) || 100_000;
const consumed = new Map(); // key -> expiry (epoch ms)

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
 * Drop expired replay entries. Returns true if the store has room for a new
 * reservation (size < cap) AFTER expired entries are reclaimed. Eviction is
 * fail-CLOSED: we NEVER drop an unexpired (still-binding) entry to make room —
 * doing so would reopen replay for a live payment (Hole 2). If the store is at
 * the cap with all-unexpired entries, the caller must REFUSE the reservation.
 */
function sweepConsumed(now = Date.now()) {
  for (const [k, exp] of consumed) {
    if (exp <= now) consumed.delete(k);
  }
  return consumed.size < REPLAY_MAX_ENTRIES;
}

/** True if `key` is an unexpired consumed binding (lazily evicts if expired). */
function isConsumed(key, now = Date.now()) {
  const exp = consumed.get(key);
  if (exp === undefined) return false;
  if (exp <= now) { consumed.delete(key); return false; }
  return true;
}

/**
 * Record `key` as consumed. `ctx` may carry { lastLedgerSequence, currentLedger }
 * to bind the expiry to the tx's real on-ledger window (Hole 1). Sweeps expired
 * entries first; if the store is still full of UNEXPIRED entries, refuses
 * fail-closed (Hole 2) and returns false WITHOUT recording — the caller must
 * surface a 503 rather than evict a live binding. Returns true on success.
 *
 * Re-marking an existing key (e.g. hash after replayId) always succeeds and does
 * not count against the cap (it overwrites, never grows the store).
 */
function markConsumed(key, ctx = {}, now = Date.now()) {
  const hasRoom = sweepConsumed(now);
  if (!hasRoom && !consumed.has(key)) return false; // fail closed, never evict live
  consumed.set(key, consumedExpiryFor(ctx, now));
  return true;
}

/** Release a reservation (e.g. submit failed before the tx was applied). */
function unmarkConsumed(key) {
  consumed.delete(key);
}

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
async function getClient() {
  const wss = process.env.XAHAU_WSS;
  if (!wss) throw new Error("XAHAU_WSS not set");
  let Client;
  try { ({ Client } = await import("xrpl")); }
  catch { throw new Error("xrpl not installed"); }
  if (_client && _client.isConnected()) return _client;
  _client = new Client(wss);
  await _client.connect();
  return _client;
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

// ---------------------------------------------------------------------------
// settle
// ---------------------------------------------------------------------------
/**
 * Submit the signed tx to Xahau. Re-validates EVERYTHING (does not trust /verify
 * was called), enforces single-use replay binding, and checks delivered_amount.
 */
async function settle(payload, req, _deps = {}) {
  if (!process.env.XAHAU_WSS) return { success: false, network: NETWORK, errorReason: "set XAHAU_WSS to settle" };

  // (4a) Re-run full verification inside settle.
  const v = verifyExact(payload, req);
  if (!v.isValid) return { success: false, network: NETWORK, errorReason: `verify failed: ${v.invalidReason}` };

  // (4b) Replay protection — refuse a payment whose binding was already consumed.
  if (isConsumed(v.replayId))
    return { success: false, network: NETWORK, errorReason: "replay: payment already consumed" };

  let tx;
  try { tx = decode(payload.txBlob); } catch { return { success: false, network: NETWORK, errorReason: "undecodable txBlob" }; }
  const required = BigInt(v.amount); // exact-xahau: client pays >= server's price up to max

  // Dependency seams (injectable for tests): client, ledger fetcher, clock.
  const now = typeof _deps.now === "function" ? _deps.now() : Date.now();
  const getLedger = _deps.currentValidatedLedger || currentValidatedLedger;

  let client;
  try { client = _deps.client || await getClient(); }
  catch (e) { return { success: false, network: NETWORK, errorReason: e.message }; }

  // (Hole 1) Bound the tx's on-ledger validity window. A tx is replayable until
  // its LastLedgerSequence is passed; if that window exceeds what the replay TTL
  // can cover, the consumed entry would expire while the tx is still submittable.
  // So: fetch the current validated ledger and REJECT any tx whose
  // LastLedgerSequence is more than MAX_VALIDITY_LEDGERS ahead. We fail CLOSED if
  // the ledger can't be read — without it we cannot prove the entry will outlive
  // the window.
  const lastLedger = Number(tx.LastLedgerSequence);
  const curLedger = await getLedger(client);
  if (!Number.isFinite(curLedger))
    return { success: false, network: NETWORK, errorReason: "could not read current ledger (cannot bound validity window)" };
  if (!Number.isFinite(lastLedger) || lastLedger <= curLedger)
    return { success: false, network: NETWORK, errorReason: "LastLedgerSequence not in the future" };
  if (lastLedger - curLedger > MAX_VALIDITY_LEDGERS)
    return { success: false, network: NETWORK, errorReason: `validity window too large (LastLedgerSequence > ${MAX_VALIDITY_LEDGERS} ledgers ahead)` };

  const replayCtx = { lastLedgerSequence: lastLedger, currentLedger: curLedger };

  // (3) Honestly report whether the payer's guardrail Hook is installed.
  const hookPresent = await guardrailHookPresent(client, tx.Account);

  // Reserve the replay slot before submission so two concurrent /settle calls for
  // the same payment can't both proceed. The expiry is bound to the tx's REAL
  // on-ledger window (replayCtx), never the flat TTL (Hole 1). markConsumed fails
  // CLOSED if the store is full of unexpired entries (Hole 2) — surface 503.
  if (isConsumed(v.replayId, now))
    return { success: false, network: NETWORK, errorReason: "replay: payment already consumed" };
  if (!markConsumed(v.replayId, replayCtx, now))
    return { success: false, network: NETWORK, errorReason: "replay store full, retry later", retryable: true };

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
      unmarkConsumed(v.replayId);
      return { success: false, network: NETWORK, errorReason: "submit rejected (tem, not applied)", guardrailHookPresent: hookPresent };
    }
    console.error("[x402] settle: ambiguous submit failure, reservation RETAINED:", e?.message || e);
    return { success: false, network: NETWORK, errorReason: "submit result unknown — reservation retained until validity window expires", guardrailHookPresent: hookPresent };
  }

  const meta = r.result.meta || {};
  const code = meta.TransactionResult;
  const hash = r.result.hash;
  // The hash binding shares the tx's window. If the store is momentarily full it
  // is fine to skip the redundant hash entry — replayId already holds the slot.
  if (hash) markConsumed(`hash:${hash}`, replayCtx, now);

  if (code !== "tesSUCCESS") {
    // tecHOOK_REJECTED here == the payer's guardrail Hook blocked an over-policy
    // payment. The tx is on-ledger (sequence consumed) so keep the replay slot.
    return {
      success: false,
      transaction: hash,
      network: NETWORK,
      errorReason: code || "no result",
      guardrailHookPresent: hookPresent,
    };
  }

  // (4c) Validate delivered_amount >= required (not just tesSUCCESS).
  const delivered = deliveredDrops(meta);
  if (delivered === null) {
    return { success: false, transaction: hash, network: NETWORK, errorReason: "could not read delivered_amount", guardrailHookPresent: hookPresent };
  }
  if (delivered < required) {
    return { success: false, transaction: hash, network: NETWORK, errorReason: "delivered_amount < required", guardrailHookPresent: hookPresent };
  }

  return {
    success: true,
    transaction: hash,
    network: NETWORK,
    errorReason: null,
    delivered: delivered.toString(),
    guardrailHookPresent: hookPresent,
  };
}

/** delivered_amount (native XAH) as bigint drops, or null. */
function deliveredDrops(meta) {
  const d = meta.delivered_amount ?? meta.DeliveredAmount;
  if (typeof d === "string" && STRICT_DROPS.test(d)) { try { return BigInt(d); } catch { return null; } }
  return null;
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
const buckets = new Map(); // ip -> { tokens, ts }
// A bucket that has had RATE_WINDOW_MS pass since last touch is fully refilled and
// indistinguishable from a fresh one, so it can be dropped. Without eviction an
// attacker spraying distinct source IPs grows this map without bound (memory DoS).
let _lastBucketSweep = 0;
const BUCKET_SWEEP_INTERVAL_MS = RATE_WINDOW_MS;
function sweepBuckets(now = Date.now()) {
  for (const [ip, b] of buckets) {
    // Fully-refilled-and-idle buckets carry no state worth keeping.
    if (now - b.ts >= RATE_WINDOW_MS) buckets.delete(ip);
  }
}
function rateLimitOk(ip) {
  const now = Date.now();
  // Periodic sweep (amortized, on access) so the map stays bounded under IP-spray.
  if (now - _lastBucketSweep >= BUCKET_SWEEP_INTERVAL_MS) {
    sweepBuckets(now);
    _lastBucketSweep = now;
  }
  let b = buckets.get(ip);
  if (!b) { b = { tokens: RATE_MAX, ts: now }; buckets.set(ip, b); }
  // refill
  const refill = ((now - b.ts) / RATE_WINDOW_MS) * RATE_MAX;
  b.tokens = Math.min(RATE_MAX, b.tokens + refill);
  b.ts = now;
  if (b.tokens < 1) return false;
  b.tokens -= 1;
  return true;
}
// test hook: expose the bucket sweeper + store for assertions.
function _sweepBuckets(now) { sweepBuckets(now); return buckets; }

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------
function serve() {
  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/supported")
        return send(res, 200, { kinds: [{ scheme: "exact", network: NETWORK }] });

      if (req.method === "POST" && req.url === "/verify") {
        // /verify decodes a full tx blob + runs signature crypto — an
        // unauthenticated, CPU-bound path. It MUST be rate-limited (but NOT
        // auth-gated: it is intentionally a public, pre-payment offline check, so
        // requiring a secret would break x402 semantics).
        const ip = req.socket.remoteAddress || "unknown";
        if (!rateLimitOk(ip)) return send(res, 429, { error: "rate limited" });
        const b = await readBody(req, res);
        return send(res, 200, verifyExact(b.paymentPayload, b.paymentRequirements));
      }

      if (req.method === "POST" && req.url === "/settle") {
        if (!authOk(req)) return send(res, 401, { error: "unauthorized" });
        const ip = req.socket.remoteAddress || "unknown";
        if (!rateLimitOk(ip)) return send(res, 429, { error: "rate limited" });
        const b = await readBody(req, res);
        const out = await settle(b.paymentPayload, b.paymentRequirements);
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
      // (6b) Do not reflect raw error messages to clients; log server-side.
      const status = e?.statusCode || 500;
      console.error("[x402] request error:", e?.stack || e?.message || e);
      if (!res.headersSent) send(res, status, { error: status === 500 ? "internal error" : "bad request" });
    }
  });
  server.listen(PORT, () => console.error(`exact-xahau facilitator on :${PORT} (network=${NETWORK}, networkID=${EXPECTED_NETWORK_ID})`));
  return server;
}

// run only when invoked directly (not when imported by test.mjs)
if (import.meta.url === `file://${process.argv[1]}`) serve();

// test hooks
function _sweepConsumed(now) { sweepConsumed(now); return consumed; }
function _markConsumed(key, ctx, now) { return markConsumed(key, ctx, now); }
function _isConsumed(key, now) { return isConsumed(key, now); }
function _consumedExpiryFor(ctx, now) { return consumedExpiryFor(ctx, now); }
export const __test = {
  parseStrictDrops, isValidRAddress, verifyTxSignature, deriveAddressFromPubKey,
  replayKeyFor, settle, consumed, _sweepBuckets, rateLimitOk, submitDefinitelyNotApplied,
  RATE_MAX,
  // Hole-1/Hole-2 hooks: replay-store internals + the chosen bounds.
  _sweepConsumed, _markConsumed, _isConsumed, _consumedExpiryFor,
  REPLAY_TTL_MS, REPLAY_MAX_ENTRIES, MAX_VALIDITY_LEDGERS, LEDGER_CLOSE_MS, REPLAY_EXPIRY_MARGIN_MS,
};
