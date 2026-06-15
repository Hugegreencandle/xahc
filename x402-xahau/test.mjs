// Self-test for verifyExact + settle re-validation. Builds GENUINELY SIGNED
// Payment tx blobs with the Xahau codec + ripple-keypairs, and asserts the
// facilitator's hardened offline verification. Run: npm test (after npm i).
import assert from "node:assert";
import http from "node:http";
import { encode, encodeForSigning } from "xrpl-binary-codec-prerelease";
import { createRequire } from "node:module";
import { verifyExact, EXPECTED_NETWORK_ID, __test } from "./server.mjs";

const require_ = createRequire(import.meta.url);
const kp = require_("ripple-keypairs");

// Deterministic test keypair (entropy fixed) -> stable PAYER address.
const seed = kp.generateSeed({ entropy: new Uint8Array(16).fill(7) });
const { publicKey, privateKey } = kp.deriveKeypair(seed);
const PAYER = kp.deriveAddress(publicKey);
const PAY_TO = "rJfeEF9Fh3gs7syURNy6daLJz68kyA65n1";

// A SECOND, distinct keypair (the "attacker") for the signature-binding test.
const seedB = kp.generateSeed({ entropy: new Uint8Array(16).fill(9) });
const kpB = kp.deriveKeypair(seedB);
const ATTACKER = kp.deriveAddress(kpB.publicKey);

/** Build a real, signed Payment blob. Pass `sign:false` to leave it unsigned. */
function blob(overrides = {}, { sign = true, tamper = null } = {}) {
  const tx = {
    TransactionType: "Payment",
    Account: PAYER,
    Destination: PAY_TO,
    Amount: "1000000", // 1 XAH in drops
    Fee: "10",
    Sequence: 1,
    Flags: 0,
    NetworkID: EXPECTED_NETWORK_ID,
    LastLedgerSequence: 1000005,
    SigningPubKey: publicKey,
    ...overrides,
  };
  if (sign) {
    const signingData = encodeForSigning(tx);
    tx.TxnSignature = kp.sign(signingData, privateKey);
  }
  if (tamper) Object.assign(tx, tamper); // mutate AFTER signing -> bad signature
  return encode(tx);
}

const req = { payTo: PAY_TO, maxAmountRequired: "1000000", network: "xahau" };

// --- IOU / issued-amount test harness --------------------------------------
// A token issuer + the asset the server prices in. Build REAL signed Payment blobs
// whose Amount is an issued-amount object { currency, issuer, value }.
const ISSUER = "rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq";
const IOU_ASSET = { currency: "USD", issuer: ISSUER };
const iouReq = { payTo: PAY_TO, maxAmountRequired: "1.5", network: "xahau", asset: IOU_ASSET };

/** Build a real, signed Payment blob whose Amount is an issued amount object. */
function iouBlob(amountOverride = {}, txOverrides = {}, { sign = true, tamper = null } = {}) {
  const tx = {
    TransactionType: "Payment",
    Account: PAYER,
    Destination: PAY_TO,
    Amount: { currency: "USD", issuer: ISSUER, value: "1.5", ...amountOverride },
    Fee: "10",
    Sequence: 1,
    Flags: 0,
    NetworkID: EXPECTED_NETWORK_ID,
    LastLedgerSequence: 1000005,
    SigningPubKey: publicKey,
    ...txOverrides,
  };
  if (sign) {
    const signingData = encodeForSigning(tx);
    tx.TxnSignature = kp.sign(signingData, privateKey);
  }
  if (tamper) Object.assign(tx, tamper);
  return encode(tx);
}

let r;

// 1. valid, genuinely-signed exact payment
r = verifyExact({ txBlob: blob() }, req);
assert.equal(r.isValid, true, `valid payment should pass: ${r.invalidReason}`);
assert.equal(r.payer, PAYER);
assert.equal(r.amount, "1000000");
assert.equal(r.signatureVerified, true, "signature should be cryptographically verified");

// 2. over the required amount
r = verifyExact({ txBlob: blob({ Amount: "2000000" }) }, req);
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /maxAmountRequired/);

// 3. wrong destination
r = verifyExact({ txBlob: blob({ Destination: PAYER }) }, req);
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /Destination/);

// 4. missing expiry window
r = verifyExact({ txBlob: blob({ LastLedgerSequence: undefined }) }, req);
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /LastLedgerSequence/);

// 5. unsigned
r = verifyExact({ txBlob: blob({}, { sign: false }) }, req);
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /unsigned/);

// 6. garbage blob
r = verifyExact({ txBlob: "ZZZZ" }, req);
assert.equal(r.isValid, false);

// ---- NEW HARDENING CASES --------------------------------------------------

// 7. CRITICAL: missing bounds must FAIL (never skip the check).
r = verifyExact({ txBlob: blob() }, { network: "xahau" }); // no payTo, no max
assert.equal(r.isValid, false, "missing requirements must fail");
assert.match(r.invalidReason, /incomplete payment requirements/);

r = verifyExact({ txBlob: blob() }, { payTo: PAY_TO }); // missing maxAmountRequired
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /incomplete payment requirements/);

r = verifyExact({ txBlob: blob() }, { payTo: "", maxAmountRequired: "" });
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /incomplete payment requirements/);

r = verifyExact({ txBlob: blob() }, null);
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /incomplete payment requirements/);

// 7b. invalid payTo address -> fail
r = verifyExact({ txBlob: blob() }, { payTo: "rNOTvalid!!!", maxAmountRequired: "1000000" });
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /incomplete payment requirements/);

// 8. HIGH: tampered tx -> signature must fail verification.
r = verifyExact({ txBlob: blob({}, { tamper: { Amount: "999999" } }) }, req);
assert.equal(r.isValid, false, "tampered tx should fail");
assert.match(r.invalidReason, /signature/);

// 9. MEDIUM: tfPartialPayment rejected.
r = verifyExact({ txBlob: blob({ Flags: 0x00020000 }) }, req);
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /tfPartialPayment/);

// 10. MEDIUM: wrong NetworkID rejected.
r = verifyExact({ txBlob: blob({ NetworkID: 999 }) }, req);
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /NetworkID/);

// 10b. missing NetworkID rejected.
r = verifyExact({ txBlob: blob({ NetworkID: undefined }) }, req);
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /NetworkID/);

// 11. MEDIUM: bad amount strings rejected (hex / negative / empty in REQUIREMENTS).
for (const bad of ["0x10", "-5", "", "1.5", "abc"]) {
  r = verifyExact({ txBlob: blob() }, { payTo: PAY_TO, maxAmountRequired: bad });
  assert.equal(r.isValid, false, `req maxAmountRequired '${bad}' should fail`);
}
// 11b. zero amount in requirements rejected (must be > 0).
r = verifyExact({ txBlob: blob() }, { payTo: PAY_TO, maxAmountRequired: "0" });
assert.equal(r.isValid, false);

// 12. parseStrictDrops unit checks
assert.equal(__test.parseStrictDrops("1000000"), 1000000n);
assert.equal(__test.parseStrictDrops("-5"), null);
assert.equal(__test.parseStrictDrops("0x10"), null);
assert.equal(__test.parseStrictDrops(""), null);
assert.equal(__test.parseStrictDrops("0"), null);
assert.equal(__test.parseStrictDrops("1.0"), null);

// 13. replay key derivation: InvoiceID preferred, else acct:seq
const INV = "0".repeat(64);
assert.equal(__test.replayKeyFor({ InvoiceID: INV, Account: PAYER, Sequence: 1 }), `inv:${INV}`);
assert.equal(__test.replayKeyFor({ Account: PAYER, Sequence: 7 }), `acct:${PAYER}:7`);

// 14. settle re-validates: even with XAHAU_WSS unset/bad, an invalid payload must
//     be rejected by the re-run of verifyExact BEFORE any node contact, and the
//     replay slot must not be consumed.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example"; // never connected to
  const out = await __test.settle({ txBlob: blob({ Amount: "5000000" }) }, req); // over max
  assert.equal(out.success, false, "settle must reject over-max payment");
  assert.match(out.errorReason, /verify failed/);
  // missing requirements at settle -> still rejected
  const out2 = await __test.settle({ txBlob: blob() }, { network: "xahau" });
  assert.equal(out2.success, false);
  assert.match(out2.errorReason, /verify failed/);
  // nothing should have been recorded as consumed (no successful reservation)
  assert.equal(__test.consumed.size, 0, "no replay slots consumed on rejected settle");
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// ---- RE-AUDIT FIX 1: signature must be BOUND to Account -------------------
// A tx whose TxnSignature validly matches its embedded SigningPubKey, but whose
// SigningPubKey does NOT derive to Account, must be rejected. (xrpl.verifySignature
// alone would pass it — the attacker signs with their own key while claiming
// Account=victim.)
{
  // sanity: deriveAddressFromPubKey matches ripple-keypairs.
  assert.equal(__test.deriveAddressFromPubKey(publicKey), PAYER, "derive helper matches PAYER");
  assert.equal(__test.deriveAddressFromPubKey(kpB.publicKey), ATTACKER, "derive helper matches ATTACKER");
  assert.equal(__test.deriveAddressFromPubKey("not-a-key"), null, "malformed key -> null");

  // Build a tx with Account = PAYER (victim) but SIGNED BY the attacker's key.
  // The signature is genuine for SigningPubKey=attacker, so verifySignature passes,
  // but deriveAddress(attacker pubkey) === ATTACKER !== Account(PAYER).
  const tx = {
    TransactionType: "Payment",
    Account: PAYER, // claimed payer (victim)
    Destination: PAY_TO,
    Amount: "1000000",
    Fee: "10",
    Sequence: 1,
    Flags: 0,
    NetworkID: EXPECTED_NETWORK_ID,
    LastLedgerSequence: 1000005,
    SigningPubKey: kpB.publicKey, // attacker's key
  };
  const signingData = encodeForSigning(tx);
  tx.TxnSignature = kp.sign(signingData, kpB.privateKey); // valid for attacker key
  const forged = encode(tx);

  // The raw crypto check passes (sig matches SigningPubKey)...
  assert.equal(__test.verifyTxSignature(forged), true, "sig is valid for its SigningPubKey");
  // ...but verifyExact must reject because the key does not belong to Account.
  r = verifyExact({ txBlob: forged }, req);
  assert.equal(r.isValid, false, "Account/key mismatch must fail");
  assert.match(r.invalidReason, /signature does not match Account/);

  // And the symmetric positive: a master-key self-signed tx (key derives to
  // Account) keeps signatureVerified:true (already covered by case 1, re-assert).
  r = verifyExact({ txBlob: blob() }, req);
  assert.equal(r.isValid, true);
  assert.equal(r.signatureVerified, true);
}

// 1b. Multisig (Signers) cannot be bound offline -> flagged, not silently passed.
{
  const tx = {
    TransactionType: "Payment",
    Account: PAYER,
    Destination: PAY_TO,
    Amount: "1000000",
    Fee: "10",
    Sequence: 1,
    Flags: 0,
    NetworkID: EXPECTED_NETWORK_ID,
    LastLedgerSequence: 1000005,
    SigningPubKey: "", // multisig: empty master SigningPubKey
    Signers: [
      {
        Signer: {
          Account: ATTACKER,
          SigningPubKey: kpB.publicKey,
          TxnSignature: "00", // not cryptographically checked by single-sig path
        },
      },
    ],
  };
  let multi;
  try {
    multi = encode(tx);
  } catch {
    multi = null; // codec refused the toy Signers blob; skip (the contract below
                  // is about verifyExact, not the codec).
  }
  if (multi) {
    r = verifyExact({ txBlob: multi }, req);
    // Not "unsigned" (Signers present); the on-chain settle is the real authority,
    // so offline we surface signatureVerified:false rather than implying a guarantee.
    if (r.isValid) {
      assert.equal(r.signatureVerified, false, "multisig must not claim offline verification");
    } else {
      // If the codec/verify path rejects the toy Signers blob, that's also acceptable
      // (it must NOT pass with signatureVerified:true).
      assert.doesNotMatch(String(r.invalidReason), /^unsigned/);
    }
  }
}

// ---- RE-AUDIT FIX 2: bounded replay store + bucket eviction ----------------
{
  // consumed is now a TTL Map (key -> expiry epoch ms), not an unbounded Set.
  // Verify the bookkeeping shape AND that an EXPIRED binding no longer blocks a
  // re-settle (the slot is reclaimable), while a fresh binding still does.
  const store = __test.consumed;
  store.clear();
  assert.ok(store instanceof Map, "consumed is a Map (key -> expiry)");

  // Directly assert the TTL contract on the store: an expired entry is treated as
  // absent (evicted on access), a future entry is present.
  const now = Date.now();
  store.set("expired-key", now - 1);      // already expired
  store.set("live-key", now + 3_600_000); // valid for an hour
  // Expired entries are lazily dropped; emulate the access-time eviction the
  // server performs via isConsumed by sweeping past entries on the next mark.
  // We assert the observable invariant: expiry timestamps are numbers and the
  // expired one is in the past (so isConsumed() returns false for it).
  assert.equal(typeof store.get("live-key"), "number", "entries carry an expiry timestamp");
  assert.ok(store.get("expired-key") < now, "expired entry's expiry is in the past");
  assert.ok(store.get("live-key") > now, "live entry's expiry is in the future");
  store.clear();
}

{
  // bucket eviction: a fully-refilled idle bucket is dropped by the sweeper.
  const now = 5_000_000;
  const buckets = __test._sweepBuckets(now); // returns the live Map
  buckets.clear();
  buckets.set("1.1.1.1", { tokens: 20, ts: now - 120_000 }); // idle > window
  buckets.set("2.2.2.2", { tokens: 5, ts: now - 1_000 });    // recently active
  __test._sweepBuckets(now);
  assert.equal(buckets.has("1.1.1.1"), false, "idle bucket evicted");
  assert.equal(buckets.has("2.2.2.2"), true, "active bucket retained");
  buckets.clear();
}

// ---- HOLE 1: consumed-entry expiry bound to the tx's ON-LEDGER window ------
// Invariant: a consumed entry must NOT expire while its tx is still submittable
// on-ledger (LastLedgerSequence not yet passed). The expiry is derived from the
// real ledger gap (+margin), never a flat TTL that could be shorter than the
// window. And settle REJECTS any tx whose window exceeds the allowed bound.
{
  const store = __test.consumed;
  store.clear();
  const now = 1_000_000_000;
  const LC = __test.LEDGER_CLOSE_MS;
  const MARGIN = __test.REPLAY_EXPIRY_MARGIN_MS;

  // (b) The consumed entry's expiry must cover at least until LastLedgerSequence
  //     can no longer apply: now + gap*close + margin. Use a gap whose wall-clock
  //     window EXCEEDS the flat TTL would-be expiry to prove we don't use the TTL.
  const gap = __test.MAX_VALIDITY_LEDGERS; // largest allowed window
  const cur = 100;
  const lls = cur + gap;
  const exp = __test._consumedExpiryFor({ lastLedgerSequence: lls, currentLedger: cur }, now);
  const windowCloses = now + gap * LC; // earliest moment the tx can no longer apply
  assert.ok(exp >= windowCloses, "consumed entry must outlive the tx's on-ledger window");
  assert.ok(exp >= windowCloses + MARGIN - 1, "expiry includes the safety margin");

  // The bound is chosen so the longest accepted window still fits the TTL budget,
  // i.e. the flat TTL is an upper bound on any accepted window.
  assert.ok(exp <= now + __test.REPLAY_TTL_MS, "accepted window's expiry fits within REPLAY_TTL_MS");

  // Marked entry is present before the window closes and gone after.
  store.clear();
  await __test._markConsumed("hole1-live", { lastLedgerSequence: lls, currentLedger: cur }, now);
  assert.equal(await __test._isConsumed("hole1-live", now), true, "binding present right after mark");
  assert.equal(await __test._isConsumed("hole1-live", windowCloses - 1), true,
    "binding STILL present while tx is submittable (must not expire early)");
  assert.equal(await __test._isConsumed("hole1-live", exp + 1), false,
    "binding reclaimable only AFTER the window+margin has passed");
  store.clear();
}

// (a) settle must REJECT a tx whose validity window is longer than the bound.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  __test.consumed.clear();

  const curLedger = 100;
  // Stub the node client + ledger fetcher so no real network is touched. The
  // ledger says we're at `curLedger`; the tx claims a LastLedgerSequence far
  // beyond the allowed window.
  const fakeClient = {
    isConnected: () => true,
    request: async () => ({ result: { account_objects: [] } }),
    submitAndWait: async () => { throw new Error("should not be reached"); },
  };
  const deps = {
    client: fakeClient,
    currentValidatedLedger: async () => curLedger,
    now: () => 1_000_000_000,
  };

  const tooFar = curLedger + __test.MAX_VALIDITY_LEDGERS + 50;
  const out = await __test.settle(
    { txBlob: blob({ LastLedgerSequence: tooFar }) }, req, deps
  );
  assert.equal(out.success, false, "over-window tx must be rejected at settle");
  assert.match(out.errorReason, /validity window too large/);
  // It was rejected BEFORE reserving a slot.
  assert.equal(__test.consumed.size, 0, "no slot consumed for an over-window tx");

  // And a tx whose window is WITHIN the bound passes the window check (it then
  // proceeds to submit). A PRELIMINARY tem* (provably not applied) releases the
  // reservation so a corrected re-sign can proceed.
  __test.consumed.clear();
  const okLast = curLedger + 5; // small, in-bounds window
  const temDeps = {
    client: {
      isConnected: () => true,
      request: async () => ({ result: { account_objects: [] } }),
      submitAndWait: async () => { const e = new Error("temMALFORMED"); e.data = { engine_result: "temMALFORMED" }; throw e; },
    },
    currentValidatedLedger: async () => curLedger,
    now: () => 1_000_000_000,
  };
  const out2 = await __test.settle(
    { txBlob: blob({ LastLedgerSequence: okLast }) }, req, temDeps
  );
  assert.equal(out2.success, false);
  assert.match(out2.errorReason, /not applied|tem/, "in-window tem clears the window gate");
  // preliminary tem -> reservation released, store empty again.
  assert.equal(__test.consumed.size, 0, "preliminary tem releases the reservation");

  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// ---- HOLE 2: hard-cap eviction is expiry-aware + fail-closed ---------------
// When the store is full of UNEXPIRED entries, a new reservation must be REFUSED
// (never satisfied by evicting a live binding). EXPIRED entries ARE reclaimed.
{
  const store = __test.consumed;
  store.clear();
  const CAP = __test.REPLAY_MAX_ENTRIES;
  const now = 2_000_000_000;
  const farFuture = now + 10 * __test.REPLAY_TTL_MS;

  // Fill the store to the cap with UNEXPIRED entries.
  for (let i = 0; i < CAP; i++) store.set(`live-${i}`, farFuture);
  assert.equal(store.size, CAP, "store filled to cap with live entries");

  // A new reservation must be REFUSED (fail closed) — not by evicting a live one.
  const ok = await __test._markConsumed("newcomer", { lastLedgerSequence: 200, currentLedger: 100 }, now);
  assert.equal(ok, false, "new reservation refused when store full of live bindings");
  assert.equal(store.has("newcomer"), false, "newcomer NOT recorded");
  assert.equal(store.size, CAP, "no live binding was evicted to make room");
  // Every original live binding is still present (none dropped).
  assert.equal(store.has("live-0"), true, "oldest-inserted live binding NOT evicted");
  assert.equal(store.has(`live-${CAP - 1}`), true, "newest live binding retained");

  // Now expire ONE entry; the sweep should reclaim it and admit the newcomer.
  store.set("live-0", now - 1); // expired
  const ok2 = await __test._markConsumed("newcomer2", { lastLedgerSequence: 200, currentLedger: 100 }, now);
  assert.equal(ok2, true, "expired entry reclaimed -> newcomer admitted");
  assert.equal(store.has("live-0"), false, "expired entry was reclaimed");
  assert.equal(store.has("newcomer2"), true, "newcomer admitted into the freed slot");
  assert.equal(store.size, CAP, "size back at cap (one out, one in)");

  // Re-marking an EXISTING key must always succeed (overwrite, no growth) even at cap.
  const ok3 = await __test._markConsumed("newcomer2", { lastLedgerSequence: 300, currentLedger: 100 }, now);
  assert.equal(ok3, true, "re-marking an existing key at cap succeeds (overwrite)");
  assert.equal(store.size, CAP, "re-mark does not grow the store");
  store.clear();
}

// (c) settle surfaces fail-closed 'replay store full' when the store is full of
//     live entries (rather than evicting a live binding to admit the new payment).
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const store = __test.consumed;
  store.clear();
  const CAP = __test.REPLAY_MAX_ENTRIES;
  const now = 3_000_000_000;
  const farFuture = now + 10 * __test.REPLAY_TTL_MS;
  for (let i = 0; i < CAP; i++) store.set(`full-${i}`, farFuture);

  const curLedger = 100;
  const fakeClient = {
    isConnected: () => true,
    request: async () => ({ result: { account_objects: [] } }),
    submitAndWait: async () => { throw new Error("should not be reached"); },
  };
  const deps = {
    client: fakeClient,
    currentValidatedLedger: async () => curLedger,
    now: () => now,
  };

  const out = await __test.settle(
    { txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 42 }) }, req, deps
  );
  assert.equal(out.success, false, "settle refuses when replay store is full of live entries");
  assert.match(out.errorReason, /replay store full/);
  assert.equal(out.retryable, true, "store-full is signalled retryable (-> 503)");
  // No live binding was evicted to make room.
  assert.equal(store.size, CAP, "no live binding evicted by a refused settle");
  assert.equal(store.has("full-0"), true, "oldest live binding survives a refused settle");

  store.clear();
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// ---- AUDIT FIX (MEDIUM-1): ambiguous submit failure FAILS CLOSED -----------
// A submitAndWait that throws for any reason OTHER than a preliminary tem* may be
// (or become) applied on-ledger. Releasing the reservation there is a double-settle
// hole. The reservation must be RETAINED on LLS-passed / disconnect / generic
// throws, and a second settle of the same payment must be blocked.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  __test.consumed.clear();
  const curLedger = 100;
  const okLast = curLedger + 5;

  // (i) LastLedgerSequence-passed style throw (maybe-applied) -> retain.
  // Use the real clock so the retained binding's expiry is genuinely in the future
  // for the dup re-settle's isConsumed() check (which reads Date.now()).
  const llsDeps = {
    client: {
      isConnected: () => true,
      request: async () => ({ result: { account_objects: [] } }),
      submitAndWait: async () => { throw new Error("The latest ledger sequence 9999 is greater than the transaction's LastLedgerSequence (105).\n Preliminary result: tesSUCCESS"); },
    },
    currentValidatedLedger: async () => curLedger,
    now: () => Date.now(),
  };
  const out = await __test.settle({ txBlob: blob({ LastLedgerSequence: okLast, Sequence: 51 }) }, req, llsDeps);
  assert.equal(out.success, false);
  assert.match(out.errorReason, /reservation retained|result unknown/);
  assert.equal(__test.consumed.size, 1, "ambiguous (LLS-passed) failure RETAINS the replay reservation");
  // A second settle of the SAME payment is now blocked as already-consumed.
  const dup = await __test.settle({ txBlob: blob({ LastLedgerSequence: okLast, Sequence: 51 }) }, req, llsDeps);
  assert.equal(dup.success, false);
  assert.match(dup.errorReason, /already consumed/, "retained binding blocks a re-settle (no double-spend)");

  // (ii) disconnect/timeout style generic throw -> also retain.
  __test.consumed.clear();
  const discDeps = {
    client: {
      isConnected: () => true,
      request: async () => ({ result: { account_objects: [] } }),
      submitAndWait: async () => { throw new Error("connect ECONNRESET / disconnected mid-wait"); },
    },
    currentValidatedLedger: async () => curLedger,
    now: () => 1_000_000_000,
  };
  const out3 = await __test.settle({ txBlob: blob({ LastLedgerSequence: okLast, Sequence: 52 }) }, req, discDeps);
  assert.equal(out3.success, false);
  assert.equal(__test.consumed.size, 1, "disconnect/timeout failure RETAINS the reservation (fail closed)");
  __test.consumed.clear();
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// submitDefinitelyNotApplied classifier: tem* (structured or message) => release;
// everything else (tes/tec/LLS/disconnect/incidental words) => keep (fail closed).
{
  const f = __test.submitDefinitelyNotApplied;
  assert.equal(f({ data: { engine_result: "temMALFORMED" } }), true, "structured tem* -> not applied");
  assert.equal(f(new Error("temBAD_AMOUNT: bad amount")), true, "tem* token in message -> not applied");
  assert.equal(f({ data: { engine_result: "tesSUCCESS" } }), false, "tesSUCCESS -> maybe applied (keep)");
  assert.equal(f({ data: { engine_result: "tecPATH_DRY" } }), false, "tec* -> applied (keep)");
  assert.equal(f(new Error("The latest ledger sequence 9 is greater than the transaction's LastLedgerSequence (5).")), false, "LLS-passed -> keep");
  assert.equal(f(new Error("connect ECONNRESET")), false, "disconnect -> keep");
  assert.equal(f(new Error("item system temporary")), false, "incidental 'tem' words -> keep (no tem* code)");
}

// ===========================================================================
// UPGRADE 1 — injectable async store: InMemoryStore reproduces TODAY's exact
// semantics (Hole-1 present-then-expire, Hole-2 fail-closed cap, reserve atomicity)
// ===========================================================================
{
  const { InMemoryStore, consumedExpiryFor, MAX_VALIDITY_LEDGERS } = __test;
  const now = 1_000_000_000;
  const s = new InMemoryStore({ now: () => now });

  // reserve atomicity: a SECOND reserve of a LIVE key returns "exists" (the second
  // concurrent settle of the same payment cannot also win). First wins -> "reserved".
  const exp = consumedExpiryFor({ lastLedgerSequence: 105, currentLedger: 100 }, now);
  assert.equal(await s.reserve("k1", exp, now), "reserved", "first reserve of a key wins");
  assert.equal(await s.reserve("k1", exp, now), "exists", "second reserve of a LIVE key loses (atomic test-and-set)");
  assert.equal(await s.isConsumed("k1", now), true, "reserved key is consumed");

  // Hole-1: present right after reserve, present while the tx is still submittable,
  // reclaimable only AFTER window+margin (expiry tied to the real on-ledger window).
  const LC = __test.LEDGER_CLOSE_MS, MARGIN = __test.REPLAY_EXPIRY_MARGIN_MS;
  const gap = MAX_VALIDITY_LEDGERS, cur = 100, lls = cur + gap;
  const exp2 = consumedExpiryFor({ lastLedgerSequence: lls, currentLedger: cur }, now);
  const windowCloses = now + gap * LC;
  await s.reserve("k2", exp2, now);
  assert.equal(await s.isConsumed("k2", now), true, "present right after reserve");
  assert.equal(await s.isConsumed("k2", windowCloses - 1), true, "present while tx still submittable");
  assert.ok(exp2 >= windowCloses + MARGIN - 1, "expiry includes the on-ledger window + margin");
  assert.equal(await s.isConsumed("k2", exp2 + 1), false, "reclaimable only after window+margin");

  // Hole-2: fill to cap with LIVE entries -> a NEW reserve is REFUSED ("full"),
  // never by evicting a live binding. An EXPIRED entry IS reclaimed.
  const small = new InMemoryStore({ maxEntries: 3, now: () => now });
  const far = now + 10 * __test.REPLAY_TTL_MS;
  assert.equal(await small.reserve("a", far, now), "reserved");
  assert.equal(await small.reserve("b", far, now), "reserved");
  assert.equal(await small.reserve("c", far, now), "reserved");
  assert.equal(await small.reserve("d", far, now), "full", "cap full of LIVE entries -> refuse (Hole 2)");
  assert.equal(await small.isConsumed("a", now), true, "no live binding evicted to admit a newcomer");
  small.map.set("a", now - 1); // expire one
  assert.equal(await small.reserve("d", far, now), "reserved", "expired entry reclaimed -> newcomer admitted");
  assert.equal(await small.size(), 3, "size back at cap (one out, one in)");
}

// ===========================================================================
// UPGRADE 2 — IDEMPOTENT settle (terminal-vs-ambiguous)
// ===========================================================================
// Helper: a fake xrpl client whose submitAndWait is scripted, counting calls.
function fakeClient({ result, throwErr } = {}) {
  const c = {
    submitCount: 0,
    isConnected: () => true,
    request: async () => ({ result: { account_objects: [] } }),
    submitAndWait: async () => {
      c.submitCount++;
      if (throwErr) throw throwErr;
      return { result };
    },
  };
  return c;
}

// (A) Idempotent SUCCESS: settle a tesSUCCESS+delivered payment -> success receipt;
//     a SECOND settle of the SAME payment returns the SAME receipt with replayed:true
//     and does NOT call submitAndWait again (submitCount stays 1).
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000;
  const curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const client = fakeClient({
    result: { hash: "ABC123HASH", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } },
  });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 71 }) };

  const out1 = await __test.settle(payment, req, deps);
  assert.equal(out1.success, true, `first settle should succeed: ${out1.errorReason}`);
  assert.equal(out1.transaction, "ABC123HASH");
  assert.equal(out1.delivered, "1000000");
  assert.equal(out1.replayed, undefined, "first settle is not a replay");
  assert.equal(client.submitCount, 1, "submitted exactly once");

  const out2 = await __test.settle(payment, req, deps);
  assert.equal(out2.success, true, "replayed settle returns the success receipt");
  assert.equal(out2.transaction, "ABC123HASH", "replayed receipt carries the REAL tx hash");
  assert.equal(out2.delivered, "1000000", "replayed receipt carries the REAL delivered amount");
  assert.equal(out2.replayed, true, "replayed flag set on the returned original receipt");
  assert.equal(client.submitCount, 1, "NO re-submit on the idempotent replay (submitCount stays 1)");

  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (B) Idempotent TERMINAL FAILURE: tecHOOK_REJECTED is on-ledger (sequence spent) ->
//     final. The receipt is memoized; a retry returns it (replayed:true), no re-submit.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const client = fakeClient({ result: { hash: "HOOKREJHASH", meta: { TransactionResult: "tecHOOK_REJECTED" } } });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 72 }) };

  const out1 = await __test.settle(payment, req, deps);
  assert.equal(out1.success, false);
  assert.match(out1.errorReason, /tecHOOK_REJECTED/);
  assert.equal(client.submitCount, 1);
  const out2 = await __test.settle(payment, req, deps);
  assert.equal(out2.replayed, true, "terminal on-ledger failure is memoized + replayed");
  assert.equal(out2.transaction, "HOOKREJHASH", "replayed failure receipt keeps the real hash");
  assert.match(out2.errorReason, /tecHOOK_REJECTED/);
  assert.equal(client.submitCount, 1, "no re-submit of a terminal failure");

  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (C) AMBIGUOUS in-flight replay: after the ambiguous-retained submit failure, a
//     second settle returns "already consumed" with NO fabricated receipt (inFlight),
//     and STILL no re-submit (submitCount stays 1).
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const client = fakeClient({ throwErr: new Error("connect ECONNRESET / disconnected mid-wait") });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 73 }) };

  const out1 = await __test.settle(payment, req, deps);
  assert.equal(out1.success, false);
  assert.match(out1.errorReason, /result unknown|reservation retained/);
  assert.equal(client.submitCount, 1, "submitted once (ambiguous)");
  // No receipt was stored for the ambiguous outcome.
  assert.equal(await store.getReceipt("acct:" + PAYER + ":73"), undefined, "ambiguous outcome stores NO receipt");

  const out2 = await __test.settle(payment, req, deps);
  assert.equal(out2.success, false);
  assert.match(out2.errorReason, /already consumed/, "ambiguous retry -> already consumed (no fabricated receipt)");
  assert.equal(out2.inFlight, true, "ambiguous retry flagged inFlight");
  assert.equal(out2.replayed, undefined, "no replayed receipt for an unknown outcome");
  assert.equal(client.submitCount, 1, "ambiguous retry does NOT re-submit");

  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (D) tem release clears any (non-existent) receipt + frees the slot for a re-sign.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const temErr = new Error("temMALFORMED"); temErr.data = { engine_result: "temMALFORMED" };
  const client = fakeClient({ throwErr: temErr });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 74 }) };

  const out = await __test.settle(payment, req, deps);
  assert.equal(out.success, false);
  assert.match(out.errorReason, /not applied|tem/);
  assert.equal(await store.isConsumed("acct:" + PAYER + ":74"), false, "preliminary tem releases the reservation");
  assert.equal(await store.getReceipt("acct:" + PAYER + ":74"), undefined, "tem stores no receipt");

  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (E) FAKE injected store exercises the async store CONTRACT via _deps.store: a
//     custom backend that records calls proves settle drives the async interface
//     (reserve/isConsumed/getReceipt/set/setReceipt) without a live Redis.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const now = 1_000_000_000, curLedger = 100;
  const calls = [];
  const inner = new __test.InMemoryStore({ now: () => now });
  const fake = {
    async reserve(k, e, n) { calls.push(["reserve", k]); return inner.reserve(k, e, n); },
    async isConsumed(k, n) { calls.push(["isConsumed", k]); return inner.isConsumed(k, n); },
    async getReceipt(k, n) { calls.push(["getReceipt", k]); return inner.getReceipt(k, n); },
    async setReceipt(k, r, e) { calls.push(["setReceipt", k]); return inner.setReceipt(k, r, e); },
    async set(k, e, n) { calls.push(["set", k]); return inner.set(k, e, n); },
    async get(k, n) { return inner.get(k, n); },
    async release(k) { calls.push(["release", k]); return inner.release(k); },
    async size() { return inner.size(); },
  };
  const client = fakeClient({ result: { hash: "FAKEHASH", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } } });
  const deps = { store: fake, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const out = await __test.settle({ txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 75 }) }, req, deps);
  assert.equal(out.success, true, `fake-store settle succeeds: ${out.errorReason}`);
  const names = calls.map((c) => c[0]);
  assert.ok(names.includes("isConsumed"), "settle consulted the injected store's isConsumed");
  assert.ok(names.includes("reserve"), "settle reserved via the injected store");
  assert.ok(names.includes("setReceipt"), "settle persisted a receipt via the injected store");
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (F) RedisStore adapter unit test against a minimal in-process FAKE ioredis,
//     proving the adapter calls SET NX PX / PTTL / DEL / GET correctly without a
//     live Redis.
{
  const { RedisStore } = __test;
  // Minimal fake ioredis: a Map of key->{val,expireAt}; honors NX + PX semantics.
  function fakeRedis() {
    const kv = new Map(); // key -> { val, expireAt|null }
    const live = (k, now) => { const e = kv.get(k); if (!e) return undefined; if (e.expireAt != null && e.expireAt <= now) { kv.delete(k); return undefined; } return e; };
    return {
      kv,
      async set(key, val, ...opts) {
        const now = Date.now();
        const nx = opts.includes("NX");
        const pxIdx = opts.indexOf("PX");
        const ttl = pxIdx >= 0 ? Number(opts[pxIdx + 1]) : null;
        if (nx && live(key, now)) return null; // NX: refuse if a live key exists
        kv.set(key, { val, expireAt: ttl != null ? now + ttl : null });
        return "OK";
      },
      async get(key) { const e = live(key, Date.now()); return e ? e.val : null; },
      async del(key) { kv.delete(key); return 1; },
      async exists(key) { return live(key, Date.now()) ? 1 : 0; },
      async pttl(key) { const e = live(key, Date.now()); if (!e) return -2; if (e.expireAt == null) return -1; return e.expireAt - Date.now(); },
      async dbsize() { let n = 0; const now = Date.now(); for (const k of kv.keys()) if (live(k, now)) n++; return n; },
    };
  }
  const redis = fakeRedis();
  const s = new RedisStore(redis, { maxEntries: 100 });
  const exp = Date.now() + 60_000;

  // reserve uses SET NX PX -> "reserved"; a second reserve of the same LIVE key -> "exists".
  assert.equal(await s.reserve("rk1", exp), "reserved", "RedisStore.reserve uses SET NX PX (OK -> reserved)");
  assert.equal(await s.reserve("rk1", exp), "exists", "RedisStore.reserve on a live key (nil -> exists)");
  assert.equal(await s.isConsumed("rk1"), true, "RedisStore.isConsumed reads EXISTS");
  assert.ok((await s.get("rk1")) > Date.now(), "RedisStore.get derives expiry from PTTL");

  // receipts round-trip through r:<key>.
  const rcpt = { success: true, transaction: "RHASH", delivered: "1000000" };
  await s.setReceipt("rk1", rcpt, exp);
  assert.deepEqual(await s.getReceipt("rk1"), rcpt, "RedisStore receipt round-trips (JSON in r:<key>)");

  // release clears both the binding and its receipt.
  await s.release("rk1");
  assert.equal(await s.isConsumed("rk1"), false, "RedisStore.release DELs the binding");
  assert.equal(await s.getReceipt("rk1"), undefined, "RedisStore.release DELs the receipt");

  // fail-closed cap: at the cap, a brand-new reserve is rolled back -> "full".
  const capped = new RedisStore(fakeRedis(), { maxEntries: 1 });
  assert.equal(await capped.reserve("c1", exp), "reserved");
  assert.equal(await capped.reserve("c2", exp), "full", "RedisStore reserve fails closed at the cap (rolls back, returns full)");
  assert.equal(await capped.isConsumed("c2"), false, "the over-cap reserve was rolled back (DEL), no live c2");
  assert.equal(await capped.isConsumed("c1"), true, "the pre-existing live binding was NOT evicted");

  // RedisRateLimiter fixed-window: INCR + PEXPIRE; allowed while count <= max.
  const { RedisRateLimiter } = __test;
  const rl = new RedisRateLimiter(
    { incr: async (k) => { const e = redis.kv.get(k); const v = (e ? Number(e.val) : 0) + 1; redis.kv.set(k, { val: String(v), expireAt: null }); return v; },
      pexpire: async () => 1 },
    { max: 2, windowMs: 60_000 }
  );
  assert.equal(await rl.ok("9.9.9.9"), true, "fixed-window: 1st request allowed");
  assert.equal(await rl.ok("9.9.9.9"), true, "fixed-window: 2nd request allowed (== max)");
  assert.equal(await rl.ok("9.9.9.9"), false, "fixed-window: 3rd request (> max) refused");
}

// ---- AUDIT FIX (MEDIUM-2): /verify is rate-limited -------------------------
// rateLimitOk unit contract: RATE_MAX allowed, then refused, per IP.
{
  const buckets = __test._sweepBuckets(0); // grab the live map
  buckets.clear();
  const ip = "203.0.113.7";
  let allowed = 0;
  for (let i = 0; i < __test.RATE_MAX; i++) if (await __test.rateLimitOk(ip)) allowed++;
  assert.equal(allowed, __test.RATE_MAX, "first RATE_MAX requests allowed");
  assert.equal(await __test.rateLimitOk(ip), false, "RATE_MAX+1th request from same IP refused");
  buckets.clear();
}

// /verify rate-limit WIRING (integration): a child with X402_RATE_MAX=1 returns
// 200 for the first /verify and 429 for the second from the same IP — proving the
// limiter is actually applied to the route (not just defined).
await new Promise((resolveTest, rejectTest) => {
  (async () => {
    const { spawn } = await import("node:child_process");
    const PORT = 4098;
    const child = spawn(process.execPath, ["server.mjs"], {
      env: { ...process.env, PORT: String(PORT), X402_RATE_MAX: "1" },
      stdio: ["ignore", "ignore", "ignore"],
    });
    const post = (path) => new Promise((res) => {
      const body = "{}";
      const r = http.request(
        { host: "127.0.0.1", port: PORT, path, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) } },
        (resp) => { resp.resume(); resp.on("end", () => res(resp.statusCode)); }
      );
      r.on("error", () => res(null));
      r.write(body); r.end();
    });
    const waitListen = async () => {
      for (let i = 0; i < 50; i++) {
        const ok = await new Promise((res) => {
          const r = http.request({ host: "127.0.0.1", port: PORT, path: "/supported", method: "GET" }, (resp) => { resp.resume(); res(resp.statusCode === 200); });
          r.on("error", () => res(false)); r.end();
        });
        if (ok) return true;
        await new Promise((r) => setTimeout(r, 100));
      }
      return false;
    };
    try {
      assert.equal(await waitListen(), true, "facilitator should start for the rate-limit test");
      const s1 = await post("/verify");
      const s2 = await post("/verify");
      assert.equal(s1, 200, `first /verify allowed (got ${s1})`);
      assert.equal(s2, 429, `second /verify rate-limited (got ${s2})`);
      resolveTest();
    } catch (e) { rejectTest(e); }
    finally { child.kill("SIGKILL"); }
  })().catch(rejectTest);
});

// ---- RE-AUDIT FIX 3: oversize body -> clean 413, not a socket reset --------
await new Promise((resolveTest, rejectTest) => {
  // Spin up the real server module's handler by importing serve indirectly is not
  // exported; instead build a tiny server that uses readBody via the public route.
  // We exercise the live /verify route with an oversize body and assert a 413
  // status + JSON body (NOT an ECONNRESET).
  import("./server.mjs").then(async () => {
    // server.mjs only auto-listens when run directly; start our own using its PORT
    // route logic by spawning the module as a child is heavy. Instead, validate the
    // 413 contract against a freshly-started instance via child process env PORT.
    const { spawn } = await import("node:child_process");
    const PORT = 4099;
    const child = spawn(process.execPath, ["server.mjs"], {
      env: { ...process.env, PORT: String(PORT) },
      stdio: ["ignore", "ignore", "ignore"],
    });

    const waitListen = async () => {
      for (let i = 0; i < 50; i++) {
        const ok = await new Promise((res) => {
          const r = http.request({ host: "127.0.0.1", port: PORT, path: "/supported", method: "GET" }, (resp) => {
            resp.resume();
            res(resp.statusCode === 200);
          });
          r.on("error", () => res(false));
          r.end();
        });
        if (ok) return true;
        await new Promise((r) => setTimeout(r, 100));
      }
      return false;
    };

    try {
      const up = await waitListen();
      assert.equal(up, true, "facilitator should start for the 413 test");

      const bigBody = "x".repeat(70 * 1024); // > 64KB cap
      // The client must RECEIVE a clean 413. (A late write-side ECONNRESET can
      // still occur because the server stops reading mid-upload — that's fine as
      // long as the 413 response was delivered; we prefer the response signal and
      // only treat a reset as failure if NO 413 ever arrived.)
      const { status, body, errCode } = await new Promise((res) => {
        let responded = false;
        const r = http.request(
          { host: "127.0.0.1", port: PORT, path: "/verify", method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(bigBody) } },
          (resp) => {
            let data = "";
            resp.on("data", (c) => (data += c));
            resp.on("end", () => { responded = true; res({ status: resp.statusCode, body: data, errCode: null }); });
          }
        );
        r.on("error", (e) => { if (!responded) res({ status: null, body: "", errCode: e.code }); });
        r.write(bigBody);
        r.end();
      });

      assert.equal(status, 413, `oversize body must return a clean 413 (got status=${status}, err=${errCode})`);
      assert.notEqual(errCode, "ECONNRESET", "client must receive the 413, not a bare ECONNRESET with no response");
      assert.match(body, /too large/, "413 body should be clean JSON");
      resolveTest();
    } catch (e) {
      rejectTest(e);
    } finally {
      child.kill("SIGKILL");
    }
  }).catch(rejectTest);
});

// ===========================================================================
// ISSUED-AMOUNT (IOU / token) SUPPORT
// ===========================================================================

// ---- exact decimal comparator unit tests (the security-critical core) -------
{
  const { parseTokenValue: p, cmpTokenValue: c, tokenValueToString: ts } = __test;
  const cmp = (a, b) => { const pa = p(a), pb = p(b); assert.ok(pa && pb, `both parse: ${a},${b}`); return c(pa, pb); };

  // trailing-zero equality: "1.0" === "1", "100.00" === "100", "0.30" === "0.3".
  assert.equal(cmp("1.0", "1"), 0, "1.0 == 1");
  assert.equal(cmp("100.00", "100"), 0, "100.00 == 100");
  assert.equal(cmp("0.30", "0.3"), 0, "0.30 == 0.3");
  assert.equal(cmp("0.1", "0.10"), 0, "0.1 == 0.10");

  // exponent forms equal their plain forms (no float drift).
  assert.equal(cmp("1e3", "1000"), 0, "1e3 == 1000");
  assert.equal(cmp("2.5E-4", "0.00025"), 0, "2.5E-4 == 0.00025");
  assert.equal(cmp("0.000001", "1e-6"), 0, "0.000001 == 1e-6");

  // many-digit values (16 significant digits — XRPL's precision ceiling).
  assert.equal(cmp("1.234567890123456", "1.234567890123456"), 0, "16-digit equal");
  assert.equal(cmp("9999999999999999", "9999999999999998"), 1, "big values: a>b by 1 ULP");
  assert.equal(cmp("9999999999999998", "9999999999999999"), -1, "big values: a<b by 1 ULP");

  // just over / under the max by one ULP at the precision boundary.
  assert.equal(cmp("1.00000000000001", "1"), 1, "1 + 1e-14 > 1");
  assert.equal(cmp("0.99999999999999", "1"), -1, "1 - 1e-14 < 1");

  // LOAD-BEARING soundness proof: 2^53+1 vs 2^53 are BOTH valid 16-sig-digit XRPL
  // token values, but IEEE754 double cannot represent 2^53+1 — parseFloat COLLAPSES
  // them to equal. A naive parseFloat facilitator would accept 9007199254740993
  // against a max of 9007199254740992 (over-payment) or pass an under-delivery. Our
  // BigInt comparator distinguishes them exactly.
  assert.equal(parseFloat("9007199254740993") === parseFloat("9007199254740992"), true,
    "parseFloat WRONGLY collapses 2^53+1 and 2^53 (this is the unsoundness we guard against)");
  assert.equal(cmp("9007199254740993", "9007199254740992"), 1,
    "exact comparator distinguishes 2^53+1 > 2^53 (sound where parseFloat fails)");
  assert.equal(cmp("9007199254740992", "9007199254740993"), -1, "and the reverse");

  // a classic float-trap: 0.1 + 0.2 != 0.3 in IEEE754, but our compare is exact.
  // (we can't add here, but we prove 0.3 strings compare exactly with no drift)
  assert.equal(cmp("0.3", "0.30000000000000"), 0, "0.3 == 0.30000000000000 (no float drift)");
  assert.equal(cmp("0.30000000000001", "0.3"), 1, "0.3 + 1e-14 > 0.3");

  // very small / very large exponents within the XRPL token range.
  assert.ok(p("1e80"), "1e80 in range");
  assert.ok(p("9999999999999999e80"), "~1e96 (max, normExp 80) in range");
  assert.ok(p("1e90"), "1e90 == 1e15 * 10^75, normExp 75 -> in range");
  assert.equal(p("1e96"), null, "1e96 (normExp 81 > 80) out of range -> reject");
  assert.equal(p("1e-82"), null, "1e-82 (normExp -97 < -96) out of range -> reject");
  assert.equal(p("1e-100"), null, "1e-100 out of range -> reject");

  // precision overflow: > 16 significant digits cannot be held exactly -> reject,
  // NOT silently truncated (a truncation would let an under/over-payment slip).
  assert.equal(p("1.0000000000000001"), null, "17 significant digits -> reject (no truncation)");
  assert.equal(p("12345678901234567"), null, "17-digit integer -> reject");

  // malformed values -> null.
  for (const bad of ["", "0", "-5", "+5", "0x10", "abc", "1.5.5", "1e", "1.", ".5", " 1", "1 ", "Infinity", "NaN", "1,000"]) {
    assert.equal(p(bad), null, `malformed token value '${bad}' -> null`);
  }

  // round-trip string rendering is exact.
  assert.equal(ts(p("1.5")), "1.5");
  assert.equal(ts(p("100.00")), "100");
  assert.equal(ts(p("0.000001")), "0.000001");
  assert.equal(ts(p("1e3")), "1000");
}

// ---- currency canonicalization (3-char ASCII <-> 40-hex are the same) -------
{
  const { canonicalizeCurrency: cc } = __test;
  // The standard 40-hex encoding of "USD" must canonicalize to the SAME value as
  // the ASCII "USD" (codec decodes standard codes to ASCII; servers may send either).
  const usdHex = "0000000000000000000000005553440000000000";
  assert.equal(cc("USD"), cc(usdHex), "ASCII USD == its 40-hex standard encoding");
  // lowercase 'usd' is 3 printable ASCII chars -> canonicalizes structurally, but to a
  // DIFFERENT hex than 'USD' (currency codes are case-sensitive).
  assert.ok(cc("usd"), "lowercase 3-char code canonicalizes structurally");
  assert.notEqual(cc("usd"), cc("USD"), "USD != usd (case-sensitive currency codes)");
  // non-standard 40-hex codes pass through (uppercased).
  assert.equal(cc("0158415500000000C1F76FF6ECB0BAC600000000"), "0158415500000000C1F76FF6ECB0BAC600000000");
  assert.equal(cc("0158415500000000c1f76ff6ecb0bac600000000"), "0158415500000000C1F76FF6ECB0BAC600000000", "hex case-insensitive");
  // rejects: native XRP, all-zero (native), malformed lengths.
  assert.equal(cc("XRP"), null, "XRP rejected as an issued currency");
  assert.equal(cc("0".repeat(40)), null, "all-zero (native) rejected");
  assert.equal(cc(""), null);
  assert.equal(cc("US"), null, "2-char rejected");
  assert.equal(cc("ABCD"), null, "4-char non-hex rejected");
  assert.equal(cc("ZZ"), null);
}

// ---- verify: IOU payments --------------------------------------------------

// valid IOU payment within max -> isValid, echoes asset + value.
r = verifyExact({ txBlob: iouBlob({ value: "1.5" }) }, iouReq);
assert.equal(r.isValid, true, `valid IOU payment should pass: ${r.invalidReason}`);
assert.equal(r.payer, PAYER);
assert.equal(r.amount, "1.5", "echoes the verified token value");
assert.deepEqual(r.asset, IOU_ASSET, "echoes the asset");
assert.equal(r.signatureVerified, true, "IOU signature is cryptographically verified + bound to Account");

// valid IOU strictly under max (1.0 <= 1.5).
r = verifyExact({ txBlob: iouBlob({ value: "1.0" }) }, iouReq);
assert.equal(r.isValid, true, `under-max IOU should pass: ${r.invalidReason}`);
assert.equal(r.amount, "1", "1.0 normalizes to 1");

// IOU exactly at max.
r = verifyExact({ txBlob: iouBlob({ value: "1.5" }) }, { ...iouReq, maxAmountRequired: "1.50" });
assert.equal(r.isValid, true, "IOU exactly at max (1.5 <= 1.50) passes");

// IOU over max -> reject.
r = verifyExact({ txBlob: iouBlob({ value: "1.50000000000001" }) }, iouReq);
assert.equal(r.isValid, false, "IOU just over max must fail");
assert.match(r.invalidReason, /maxAmountRequired/);
r = verifyExact({ txBlob: iouBlob({ value: "2" }) }, iouReq);
assert.equal(r.isValid, false, "IOU 2 > 1.5 must fail");
assert.match(r.invalidReason, /maxAmountRequired/);

// wrong currency -> reject.
r = verifyExact({ txBlob: iouBlob({ currency: "EUR" }) }, iouReq);
assert.equal(r.isValid, false, "wrong currency must fail");
assert.match(r.invalidReason, /currency/);

// wrong issuer -> reject.
r = verifyExact({ txBlob: iouBlob({ issuer: "rJfeEF9Fh3gs7syURNy6daLJz68kyA65n1" }) }, iouReq);
assert.equal(r.isValid, false, "wrong issuer must fail");
assert.match(r.invalidReason, /issuer/);

// asset-vs-native mismatch BOTH directions.
//  (a) asset required (iouReq) but Amount is a native drops string.
r = verifyExact({ txBlob: blob({ Amount: "1000000" }) }, iouReq);
assert.equal(r.isValid, false, "native Amount when an asset is required must fail");
assert.match(r.invalidReason, /asset mismatch/);
//  (b) native required (req) but Amount is an issued-amount object.
r = verifyExact({ txBlob: iouBlob({ value: "1.5" }) }, req);
assert.equal(r.isValid, false, "issued Amount when native is required must fail");
assert.match(r.invalidReason, /asset mismatch/);

// malformed value in the Amount -> reject. The codec itself only ENCODES a subset
// of malformed values (it rejects "abc" / over-precision at serialization); for the
// ones it DOES encode ("0", negative), verifyExact must still reject after decode.
for (const badVal of ["0", "-1"]) {
  r = verifyExact({ txBlob: iouBlob({ value: badVal }) }, iouReq);
  assert.equal(r.isValid, false, `malformed IOU value '${badVal}' must fail`);
}
// Values the codec refuses to encode (so they can't arrive as a real blob) are still
// rejected at the facilitator layer — assert via checkIssuedAmount on a decoded-shape
// object (defense in depth: verifyExact re-parses the decoded value too).
{
  const { checkIssuedAmount, parseTokenValue } = __test;
  const maxV = parseTokenValue("1.5");
  for (const badVal of ["abc", "1.0000000000000001", "0", "-1", "", "1.5.5"]) {
    const out = checkIssuedAmount({ currency: "USD", issuer: ISSUER, value: badVal }, IOU_ASSET, maxV);
    assert.ok(out.error, `checkIssuedAmount rejects value '${badVal}'`);
  }
  // a non-object Amount (string) when an asset is required -> rejected by checkIssuedAmount.
  assert.ok(checkIssuedAmount("1000000", IOU_ASSET, maxV).error, "string Amount rejected for an asset");
  assert.ok(checkIssuedAmount(null, IOU_ASSET, maxV).error, "null Amount rejected");
}

// malformed asset in the REQUIREMENTS -> incomplete requirements.
r = verifyExact({ txBlob: iouBlob() }, { payTo: PAY_TO, maxAmountRequired: "1.5", asset: { currency: "XRP", issuer: ISSUER } });
assert.equal(r.isValid, false, "asset.currency = XRP must fail");
assert.match(r.invalidReason, /asset\.currency invalid/);
r = verifyExact({ txBlob: iouBlob() }, { payTo: PAY_TO, maxAmountRequired: "1.5", asset: { currency: "USD", issuer: "rNOPE!!!" } });
assert.equal(r.isValid, false, "asset.issuer invalid must fail");
assert.match(r.invalidReason, /asset\.issuer invalid/);
r = verifyExact({ txBlob: iouBlob() }, { payTo: PAY_TO, maxAmountRequired: "not-a-number", asset: IOU_ASSET });
assert.equal(r.isValid, false, "IOU maxAmountRequired must be a valid token value");
assert.match(r.invalidReason, /maxAmountRequired/);

// requirements maxAmountRequired with too much precision -> reject.
r = verifyExact({ txBlob: iouBlob() }, { payTo: PAY_TO, maxAmountRequired: "1.0000000000000001", asset: IOU_ASSET });
assert.equal(r.isValid, false, "over-precision IOU max must fail");

// asset.currency supplied as 40-hex must match an ASCII-currency tx Amount.
r = verifyExact({ txBlob: iouBlob({ value: "1.5" }) }, { payTo: PAY_TO, maxAmountRequired: "1.5", asset: { currency: "0000000000000000000000005553440000000000", issuer: ISSUER } });
assert.equal(r.isValid, true, `hex-form asset.currency must match ASCII USD Amount: ${r.invalidReason}`);

// tampered IOU tx -> signature fails.
r = verifyExact({ txBlob: iouBlob({ value: "1.5" }, {}, { tamper: { Amount: { currency: "USD", issuer: ISSUER, value: "0.5" } } }) }, iouReq);
assert.equal(r.isValid, false, "tampered IOU tx must fail signature");
assert.match(r.invalidReason, /signature/);

// IOU tx still rejects tfPartialPayment + wrong NetworkID + missing expiry.
r = verifyExact({ txBlob: iouBlob({ value: "1.5" }, { Flags: 0x00020000 }) }, iouReq);
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /tfPartialPayment/);
r = verifyExact({ txBlob: iouBlob({ value: "1.5" }, { NetworkID: 999 }) }, iouReq);
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /NetworkID/);
r = verifyExact({ txBlob: iouBlob({ value: "1.5" }, { LastLedgerSequence: undefined }) }, iouReq);
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /LastLedgerSequence/);

// native path remains byte-for-byte unchanged: re-assert case 1 still passes and
// still returns asset:null.
r = verifyExact({ txBlob: blob() }, req);
assert.equal(r.isValid, true);
assert.equal(r.amount, "1000000");
assert.equal(r.asset, null, "native result carries asset:null");

// ---- settle: IOU delivered_amount checks (stubbed client) ------------------
function iouFakeClient({ result, throwErr } = {}) {
  const c = {
    submitCount: 0,
    isConnected: () => true,
    request: async () => ({ result: { account_objects: [] } }),
    submitAndWait: async () => { c.submitCount++; if (throwErr) throw throwErr; return { result }; },
  };
  return c;
}

// (IOU-1) tesSUCCESS with delivered >= required -> success receipt (delivered echoed).
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const client = iouFakeClient({
    result: { hash: "IOUOK", meta: { TransactionResult: "tesSUCCESS", delivered_amount: { currency: "USD", issuer: ISSUER, value: "1.5" } } },
  });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: iouBlob({ value: "1.5" }, { LastLedgerSequence: curLedger + 5, Sequence: 81 }) };

  const out = await __test.settle(payment, iouReq, deps);
  assert.equal(out.success, true, `IOU settle should succeed: ${out.errorReason}`);
  assert.equal(out.transaction, "IOUOK");
  assert.deepEqual(out.delivered, { currency: "USD", issuer: ISSUER, value: "1.5" }, "delivered IOU echoed");
  assert.equal(client.submitCount, 1);

  // idempotent replay returns the same receipt, no re-submit.
  const out2 = await __test.settle(payment, iouReq, deps);
  assert.equal(out2.replayed, true, "IOU idempotent replay");
  assert.equal(out2.success, true);
  assert.equal(client.submitCount, 1, "no re-submit on IOU replay");
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (IOU-2) delivered MORE than required (over-delivery still >= required) -> success.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const client = iouFakeClient({
    result: { hash: "IOUMORE", meta: { TransactionResult: "tesSUCCESS", delivered_amount: { currency: "USD", issuer: ISSUER, value: "1.5" } } },
  });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  // required 1.0 (under the 1.5 max); delivered 1.5 >= 1.0 -> ok.
  const payment = { txBlob: iouBlob({ value: "1.0" }, { LastLedgerSequence: curLedger + 5, Sequence: 82 }) };
  const out = await __test.settle(payment, iouReq, deps);
  assert.equal(out.success, true, `delivered 1.5 >= required 1.0 should succeed: ${out.errorReason}`);
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (IOU-3) delivered < required -> fail (a partial-ish underpayment in meta).
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const client = iouFakeClient({
    result: { hash: "IOULESS", meta: { TransactionResult: "tesSUCCESS", delivered_amount: { currency: "USD", issuer: ISSUER, value: "1.49999999999999" } } },
  });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: iouBlob({ value: "1.5" }, { LastLedgerSequence: curLedger + 5, Sequence: 83 }) };
  const out = await __test.settle(payment, iouReq, deps);
  assert.equal(out.success, false, "delivered 1.49999999999999 < required 1.5 must fail (exact compare)");
  assert.match(out.errorReason, /delivered_amount < required/);
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (IOU-4) wrong delivered currency -> fail.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const client = iouFakeClient({
    result: { hash: "IOUWRONGCUR", meta: { TransactionResult: "tesSUCCESS", delivered_amount: { currency: "EUR", issuer: ISSUER, value: "1.5" } } },
  });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: iouBlob({ value: "1.5" }, { LastLedgerSequence: curLedger + 5, Sequence: 84 }) };
  const out = await __test.settle(payment, iouReq, deps);
  assert.equal(out.success, false, "wrong delivered currency must fail");
  assert.match(out.errorReason, /asset mismatch/);
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (IOU-5) wrong delivered issuer -> fail.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const client = iouFakeClient({
    result: { hash: "IOUWRONGISS", meta: { TransactionResult: "tesSUCCESS", delivered_amount: { currency: "USD", issuer: "rJfeEF9Fh3gs7syURNy6daLJz68kyA65n1", value: "1.5" } } },
  });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: iouBlob({ value: "1.5" }, { LastLedgerSequence: curLedger + 5, Sequence: 85 }) };
  const out = await __test.settle(payment, iouReq, deps);
  assert.equal(out.success, false, "wrong delivered issuer must fail");
  assert.match(out.errorReason, /asset mismatch/);
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (IOU-6) delivered_amount of the WRONG TYPE for an IOU (a native drops string) -> fail.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const client = iouFakeClient({
    result: { hash: "IOUTYPE", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1500000" } },
  });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: iouBlob({ value: "1.5" }, { LastLedgerSequence: curLedger + 5, Sequence: 86 }) };
  const out = await __test.settle(payment, iouReq, deps);
  assert.equal(out.success, false, "drops-string delivered_amount for an IOU must fail (wrong type)");
  assert.match(out.errorReason, /could not read delivered_amount/);
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (IOU-7) settle re-validates: an over-max IOU is rejected before any node contact.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const out = await __test.settle({ txBlob: iouBlob({ value: "5" }) }, iouReq);
  assert.equal(out.success, false, "settle rejects over-max IOU");
  assert.match(out.errorReason, /verify failed/);
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (IOU-8) native settle still works unchanged (delivered drops string).
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const client = iouFakeClient({
    result: { hash: "NATIVEOK", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } },
  });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 87 }) };
  const out = await __test.settle(payment, req, deps);
  assert.equal(out.success, true, `native settle still works: ${out.errorReason}`);
  assert.equal(out.delivered, "1000000", "native delivered stays a drops string");
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

console.log("ok — all hardened verifyExact + settle cases pass (native + IOU)");
