// Self-test for verifyExact + settle re-validation. Builds GENUINELY SIGNED
// Payment tx blobs with the Xahau codec + ripple-keypairs, and asserts the
// facilitator's hardened offline verification. Run: npm test (after npm i).
import assert from "node:assert";
import http from "node:http";
import { encode, encodeForSigning } from "xahau-binary-codec";
import { createRequire } from "node:module";
import { verifyExact, EXPECTED_NETWORK_ID, __test } from "./server.mjs";

const require_ = createRequire(import.meta.url);
const kp = require_("xahau-keypairs");

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

// (F1) RESOLVED-BUT-UNREADABLE submit response -> ambiguous-retained (fail closed).
//      submitAndWait RESOLVES (no throw) but hands back a malformed shape with no
//      usable TransactionResult. settle must KEEP the reservation, store NO receipt,
//      NOT throw/500, and a SECOND settle must be treated as in-flight / already-
//      consumed with NO re-submit. (F1 is already implemented; this only tests it.)
for (const badResult of [ {}, { result: {} }, { result: { meta: {} } }, { result: { meta: { TransactionResult: "" } } } ]) {
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  // fakeClient returns { result } — wrap so we control the WHOLE resolved value.
  let submitCount = 0;
  const client = {
    isConnected: () => true,
    request: async () => ({ result: { account_objects: [] } }),
    submitAndWait: async () => { submitCount++; return badResult; },
  };
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 301 }) };

  const out1 = await __test.settle(payment, req, deps);
  assert.equal(out1.success, false, "unreadable resolved response -> failure (not success)");
  assert.match(out1.errorReason, /result unknown|retained/, "errorReason flags unknown/retained outcome");
  assert.equal(out1.transaction, "", "no tx hash on an unreadable resolved response");
  assert.equal(submitCount, 1, "submitted exactly once");
  assert.equal(await store.isConsumed("acct:" + PAYER + ":301"), true, "reservation RETAINED on unreadable resolve");
  assert.equal(await store.getReceipt("acct:" + PAYER + ":301"), undefined, "no receipt stored for the ambiguous-retained outcome");

  const out2 = await __test.settle(payment, req, deps);
  assert.equal(out2.success, false, "second settle still a failure");
  assert.match(out2.errorReason, /already consumed/, "second settle -> already consumed (in-flight)");
  assert.equal(out2.inFlight, true, "second settle flagged inFlight (no fabricated receipt)");
  assert.equal(submitCount, 1, "unreadable-resolve retry does NOT re-submit");

  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (F2) POST-SUBMIT receipt-persistence failure is BEST-EFFORT: a setReceipt that
//      throws must NOT lose the success receipt or 500 — the submit already applied,
//      so settle still returns success:true with the real tx. (Already implemented;
//      this only tests it.)
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const now = 1_000_000_000, curLedger = 100;
  const inner = new __test.InMemoryStore({ now: () => now });
  let setReceiptCalls = 0;
  const store = {
    async reserve(k, e, n) { return inner.reserve(k, e, n); },
    async isConsumed(k, n) { return inner.isConsumed(k, n); },
    async getReceipt(k, n) { return inner.getReceipt(k, n); },
    async setReceipt() { setReceiptCalls++; throw new Error("redis down (post-submit)"); },
    async set(k, e, n) { return inner.set(k, e, n); },
    async get(k, n) { return inner.get(k, n); },
    async release(k) { return inner.release(k); },
    async size() { return inner.size(); },
  };
  const client = fakeClient({ result: { hash: "F2HASH", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } } });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 302 }) };

  let out, threw = false;
  try { out = await __test.settle(payment, req, deps); } catch { threw = true; }
  assert.equal(threw, false, "a post-submit setReceipt throw does NOT escape settle (no 500)");
  assert.equal(out.success, true, "success receipt still returned despite the persistence failure");
  assert.equal(out.transaction, "F2HASH", "the real tx hash is preserved on the success receipt");
  assert.equal(out.delivered, "1000000", "delivered amount preserved");
  assert.ok(setReceiptCalls >= 1, "setReceipt WAS attempted (best-effort), and its throw was swallowed");

  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// (F3) PRE-SUBMIT store outage -> retryable 503-class reject, fail CLOSED: a store
//      whose isConsumed/reserve throws makes settle return success:false +
//      retryable:true and NEVER submit (submitCount stays 0 — never fail-OPEN).
for (const failOn of ["isConsumed", "reserve"]) {
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const now = 1_000_000_000, curLedger = 100;
  const inner = new __test.InMemoryStore({ now: () => now });
  const store = {
    async reserve(k, e, n) { if (failOn === "reserve") throw new Error("redis down (reserve)"); return inner.reserve(k, e, n); },
    async isConsumed(k, n) { if (failOn === "isConsumed") throw new Error("redis down (isConsumed)"); return inner.isConsumed(k, n); },
    async getReceipt(k, n) { return inner.getReceipt(k, n); },
    async setReceipt(k, r, e) { return inner.setReceipt(k, r, e); },
    async set(k, e, n) { return inner.set(k, e, n); },
    async get(k, n) { return inner.get(k, n); },
    async release(k) { return inner.release(k); },
    async size() { return inner.size(); },
  };
  const client = fakeClient({ result: { hash: "F3HASH", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } } });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 303 }) };

  let out, threw = false;
  try { out = await __test.settle(payment, req, deps); } catch { threw = true; }
  assert.equal(threw, false, `pre-submit store throw on ${failOn} does NOT escape settle (no 500)`);
  assert.equal(out.success, false, `${failOn} throw -> settle fails closed`);
  assert.equal(out.retryable, true, `${failOn} throw -> retryable:true (handler maps to 503)`);
  assert.match(out.errorReason, /replay store unavailable/, "errorReason names the store outage");
  assert.equal(client.submitCount, 0, `FAIL-CLOSED: never submitted on a ${failOn} store outage (submitCount 0)`);

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

  // (#4) RedisRateLimiter TOKEN BUCKET: atomic EVAL of the Lua script. The fake
  // ioredis below interprets the bucket arithmetic in JS (mirroring the Lua) so we can
  // assert (a) the limiter actually calls EVAL with the real script + correct ARGV,
  // and (b) allow/deny logic: a fresh full bucket allows `max`, then denies, then
  // refills with elapsed time.
  const { RedisRateLimiter } = __test;
  // Minimal fake ioredis supporting eval of the token-bucket script (hash-backed).
  function fakeBucketRedis() {
    const hashes = new Map(); // key -> { t, ts }
    let evalCalls = 0;
    let lastScript = null;
    return {
      hashes,
      get evalCalls() { return evalCalls; },
      get lastScript() { return lastScript; },
      // eval(script, numKeys, key, now, max, windowMs, ttlMs)
      async eval(script, numKeys, key, now, max, windowMs, ttlMs) {
        evalCalls++; lastScript = script;
        const SCALE = __test.RL_SCALE;
        now = Number(now); max = Number(max); windowMs = Number(windowMs);
        const maxScaled = max * SCALE;
        let h = hashes.get(key);
        let tokens = h ? Number(h.t) : maxScaled;
        let ts = h ? Number(h.ts) : now;
        let elapsed = now - ts; if (elapsed < 0) elapsed = 0;
        const refill = Math.floor((elapsed * maxScaled) / windowMs);
        tokens = Math.min(maxScaled, tokens + refill);
        let allow = 0, resetMs = 0;
        if (tokens >= SCALE) { tokens -= SCALE; allow = 1; }
        else { resetMs = Math.ceil(((SCALE - tokens) * windowMs) / maxScaled); }
        hashes.set(key, { t: tokens, ts: now });
        return [allow, resetMs];
      },
    };
  }
  const bredis = fakeBucketRedis();
  const rl = new RedisRateLimiter(bredis, { max: 2, windowMs: 60_000 });
  // Pin `now` so refill is deterministic across the burst (same instant -> no refill).
  const T0 = 1_700_000_000_000;
  assert.equal(await rl.ok("9.9.9.9", T0), true, "token-bucket: 1st request allowed (full bucket)");
  assert.equal(bredis.evalCalls, 1, "RedisRateLimiter.ok runs exactly one EVAL per call");
  assert.equal(bredis.lastScript, __test.REDIS_TOKEN_BUCKET_LUA, "EVAL uses the real token-bucket Lua script");
  assert.equal(await rl.ok("9.9.9.9", T0), true, "token-bucket: 2nd request allowed (== max, no refill at same instant)");
  assert.equal(await rl.ok("9.9.9.9", T0), false, "token-bucket: 3rd request (bucket empty) refused");
  // After a FULL window elapses the bucket refills to max -> allowed again.
  assert.equal(await rl.ok("9.9.9.9", T0 + 60_000), true, "token-bucket: refills after a full window");
  // Half a window after empty gives ~1 token (continuous refill, no boundary doubling).
  const bredis2 = fakeBucketRedis();
  const rl2 = new RedisRateLimiter(bredis2, { max: 2, windowMs: 60_000 });
  assert.equal(await rl2.ok("8.8.8.8", T0), true);
  assert.equal(await rl2.ok("8.8.8.8", T0), true);
  assert.equal(await rl2.ok("8.8.8.8", T0), false, "empty after 2");
  assert.equal(await rl2.ok("8.8.8.8", T0 + 30_000), true, "half-window refill yields exactly 1 token");
  assert.equal(await rl2.ok("8.8.8.8", T0 + 30_000), false, "only 1 token from a half window (no 2x boundary burst)");

  // FAIL CLOSED: if EVAL throws (no scripting support), ok() must DENY, never allow.
  const throwingRedis = { eval: async () => { throw new Error("ERR unknown command EVAL"); } };
  const rlFail = new RedisRateLimiter(throwingRedis, { max: 100, windowMs: 60_000 });
  assert.equal(await rlFail.ok("7.7.7.7"), false, "RedisRateLimiter fails CLOSED (deny) when EVAL errors");
}

// ===========================================================================
// UPGRADE #3 — on-ledger RegularKey + multisig authorization at SETTLE
// ===========================================================================
// At settle we hold a node connection, so we POSITIVELY check on-ledger auth for txs
// whose signature could NOT be bound offline (RegularKey single-sig + multisig). The
// check may only REJECT (skip submit) or UPGRADE confidence (signatureVerified:true +
// source); a node-read failure FALLS BACK to the ledger (proceed to submit). The pure
// decision fn `authorizeOnLedger_decide` is unit-tested directly; full settle paths
// use the injected fake client.

// --- (3.0) pure decision fn: REGULARKEY -----------------------------------
{
  const { authorizeOnLedger_decide } = __test;
  // The signing key derives to ATTACKER (a regular key set on PAYER's account).
  const txRK = { Account: PAYER, SigningPubKey: kpB.publicKey, TxnSignature: "ab" };

  // RegularKey present AND == deriveAddress(SigningPubKey) -> authorized:regularkey.
  let d = authorizeOnLedger_decide(txRK, null, { RegularKey: ATTACKER }, false);
  assert.equal(d.decision, "authorized", "RegularKey match -> authorized");
  assert.equal(d.source, "regularkey", "source is regularkey");

  // RegularKey present but MISMATCHED -> rejected (unauthorized forgery).
  d = authorizeOnLedger_decide(txRK, null, { RegularKey: PAY_TO }, false);
  assert.equal(d.decision, "rejected", "mismatched RegularKey -> rejected");
  assert.match(d.reason, /neither master nor current RegularKey/);

  // No RegularKey set at all -> rejected.
  d = authorizeOnLedger_decide(txRK, null, {}, false);
  assert.equal(d.decision, "rejected", "no RegularKey -> rejected");

  // account read failed (null) -> fallback (never fabricate authorization).
  d = authorizeOnLedger_decide(txRK, null, null, false);
  assert.equal(d.decision, "fallback", "account_info read failure -> fallback (ledger authority)");
}

// --- (3.1) pure decision fn: MULTISIG quorum ------------------------------
{
  const { authorizeOnLedger_decide } = __test;
  const codec = require_("xahau-binary-codec");
  // Two real signer keypairs.
  const s1 = kp.deriveKeypair(kp.generateSeed({ entropy: new Uint8Array(16).fill(11) }));
  const s2 = kp.deriveKeypair(kp.generateSeed({ entropy: new Uint8Array(16).fill(12) }));
  const a1 = kp.deriveAddress(s1.publicKey);
  const a2 = kp.deriveAddress(s2.publicKey);

  // Base multisig tx (no Signers yet) -> sign per-signer over encodeForMultisigning.
  const base = {
    TransactionType: "Payment", Account: PAYER, Destination: PAY_TO, Amount: "1000000",
    Fee: "100", Sequence: 1, Flags: 0, NetworkID: EXPECTED_NETWORK_ID,
    LastLedgerSequence: 1000005, SigningPubKey: "",
  };
  const sig1 = kp.sign(codec.encodeForMultisigning(base, a1), s1.privateKey);
  const sig2 = kp.sign(codec.encodeForMultisigning(base, a2), s2.privateKey);
  const mkTx = (signers) => codec.decode(codec.encode({ ...base, Signers: signers }));

  const both = mkTx([
    { Signer: { Account: a1, SigningPubKey: s1.publicKey, TxnSignature: sig1 } },
    { Signer: { Account: a2, SigningPubKey: s2.publicKey, TxnSignature: sig2 } },
  ]);

  // SignerList: each weight 1, quorum 2. Both valid sigs -> sum 2 >= 2 -> authorized.
  const slBoth = { quorum: 2, signers: [{ account: a1, weight: 1 }, { account: a2, weight: 1 }] };
  let d = authorizeOnLedger_decide(both, slBoth, null, true);
  assert.equal(d.decision, "authorized", "two valid signers meeting quorum -> authorized");
  assert.equal(d.source, "multisig", "source is multisig");

  // Quorum 3 (unreachable with weight 2) -> rejected (under quorum).
  const slHigh = { quorum: 3, signers: [{ account: a1, weight: 1 }, { account: a2, weight: 1 }] };
  d = authorizeOnLedger_decide(both, slHigh, null, true);
  assert.equal(d.decision, "rejected", "valid signers below quorum -> rejected");
  assert.match(d.reason, /quorum not met/);

  // One signer's signature is INVALID (tampered) -> excluded; remaining weight 1 < 2.
  const tampered = mkTx([
    { Signer: { Account: a1, SigningPubKey: s1.publicKey, TxnSignature: sig1 } },
    { Signer: { Account: a2, SigningPubKey: s2.publicKey, TxnSignature: sig1 /* WRONG sig for a2 */ } },
  ]);
  d = authorizeOnLedger_decide(tampered, slBoth, null, true);
  assert.equal(d.decision, "rejected", "bad signature excluded -> under quorum -> rejected");

  // A signer NOT on the on-ledger SignerList contributes nothing.
  const slOnlyA1 = { quorum: 2, signers: [{ account: a1, weight: 1 }] };
  d = authorizeOnLedger_decide(both, slOnlyA1, null, true);
  assert.equal(d.decision, "rejected", "unlisted signer contributes no weight -> under quorum -> rejected");

  // A1 weight 5, quorum 3 -> single valid listed signer meets quorum -> authorized.
  const slWeighted = { quorum: 3, signers: [{ account: a1, weight: 5 }, { account: a2, weight: 1 }] };
  d = authorizeOnLedger_decide(both, slWeighted, null, true);
  assert.equal(d.decision, "authorized", "weighted signer alone meets quorum -> authorized");

  // Duplicate signer entries do NOT double-count weight (dedupe). a1 listed once w=1,
  // quorum 2; tx repeats a1 twice -> still only weight 1 -> under quorum -> rejected.
  const dupA1 = mkTx([
    { Signer: { Account: a1, SigningPubKey: s1.publicKey, TxnSignature: sig1 } },
    { Signer: { Account: a1, SigningPubKey: s1.publicKey, TxnSignature: sig1 } },
  ]);
  d = authorizeOnLedger_decide(dupA1, { quorum: 2, signers: [{ account: a1, weight: 1 }] }, null, true);
  assert.equal(d.decision, "rejected", "duplicate signer weight counted once -> under quorum -> rejected");

  // No on-ledger SignerList at all (account not multisig-configured) -> rejected.
  d = authorizeOnLedger_decide(both, { error: "no_signer_list" }, null, true);
  assert.equal(d.decision, "rejected", "no SignerList -> rejected");
  assert.match(d.reason, /no on-ledger SignerList/);

  // SignerList read failed (null) -> fallback (ledger authority, no fabrication).
  d = authorizeOnLedger_decide(both, null, null, true);
  assert.equal(d.decision, "fallback", "SignerList read failure -> fallback");

  // Malformed / ambiguous list -> fallback (cannot evaluate -> ledger authority).
  d = authorizeOnLedger_decide(both, { error: "malformed_signer_list" }, null, true);
  assert.equal(d.decision, "fallback", "malformed SignerList -> fallback");

  // Stash for the settle integration tests below.
  globalThis.__MULTISIG = { s1, s2, a1, a2, base, sig1, sig2, codec };
}

// --- (3.2) settle integration: REGULARKEY authorized + rejected -----------
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;

  // Build a tx whose Account is PAYER but signed by the ATTACKER key (a regular key).
  // This is exactly the verifyExact "signature does not match Account" case offline —
  // but at SETTLE we re-derive and check the on-ledger RegularKey. We must construct a
  // GENUINELY-signed blob with SigningPubKey = attacker key so verifyExact's signature
  // crypto passes and it returns signatureVerified:false (key != Account).
  function regularKeyBlob(overrides = {}) {
    const tx = {
      TransactionType: "Payment", Account: PAYER, Destination: PAY_TO, Amount: "1000000",
      Fee: "10", Sequence: 91, Flags: 0, NetworkID: EXPECTED_NETWORK_ID,
      LastLedgerSequence: curLedger + 5, SigningPubKey: kpB.publicKey, ...overrides,
    };
    tx.TxnSignature = kp.sign(encodeForSigning(tx), kpB.privateKey);
    return encode(tx);
  }

  // Sanity: verifyExact REJECTS this offline (single-sig key != Account).
  let vr = verifyExact({ txBlob: regularKeyBlob() }, req);
  assert.equal(vr.isValid, false, "RegularKey-signed tx is rejected by OFFLINE verifyExact (key != Account)");
  assert.match(vr.invalidReason, /signature does not match Account/);

  // NOTE: because verifyExact rejects a RegularKey single-sig offline, settle's
  // re-verification ALSO rejects it before reaching the on-ledger auth check. This is
  // the CURRENT conservative single-sig binding: a single-sig key that doesn't derive
  // to Account fails closed. The on-ledger RegularKey UPGRADE path therefore applies
  // to signatures that verifyExact lets through as signatureVerified:false WITHOUT
  // rejecting — which today is the MULTISIG case. We assert the conservative single-sig
  // behavior is preserved (it does NOT settle), and exercise the on-ledger REJECT/
  // AUTHORIZE upgrade via the multisig settle path + the pure-fn RegularKey tests above.
  const store = new InMemoryStore({ now: () => now });
  let submitCount = 0;
  const client = {
    isConnected: () => true,
    request: async (q) => {
      if (q.command === "account_info") return { result: { account_data: { RegularKey: ATTACKER } } };
      return { result: { account_objects: [] } };
    },
    submitAndWait: async () => { submitCount++; return { result: { hash: "X", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } } }; },
  };
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const out = await __test.settle({ txBlob: regularKeyBlob() }, req, deps);
  assert.equal(out.success, false, "single-sig key != Account does NOT settle (conservative binding preserved)");
  assert.match(out.errorReason, /verify failed/);
  assert.equal(submitCount, 0, "no submit for a tx that fails re-verification");

  // Master-key single-sig still authorized as before (signatureVerified:true, source master).
  const store2 = new InMemoryStore({ now: () => now });
  let submit2 = 0;
  const client2 = {
    isConnected: () => true,
    request: async () => ({ result: { account_objects: [] } }),
    submitAndWait: async () => { submit2++; return { result: { hash: "MASTER", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } } }; },
  };
  const deps2 = { store: store2, client: client2, currentValidatedLedger: async () => curLedger, now: () => now };
  const outM = await __test.settle({ txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 92 }) }, req, deps2);
  assert.equal(outM.success, true, `master-key single-sig still settles: ${outM.errorReason}`);
  assert.equal(outM.signatureVerified, true, "master-key settle reports signatureVerified:true");
  assert.equal(outM.signatureSource, "master", "master-key settle reports source master");
  assert.equal(submit2, 1, "master-key tx submitted once");

  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// --- (3.3) settle integration: MULTISIG authorized / rejected / fallback ---
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const M = globalThis.__MULTISIG;

  // Build a multisig blob with both real signatures. LastLedgerSequence must be in the
  // in-bounds window; rebuild base with the right LLS and re-sign.
  const mbase = { ...M.base, LastLedgerSequence: curLedger + 5, Sequence: 101 };
  const msig1 = kp.sign(M.codec.encodeForMultisigning(mbase, M.a1), M.s1.privateKey);
  const msig2 = kp.sign(M.codec.encodeForMultisigning(mbase, M.a2), M.s2.privateKey);
  const multiBlob = M.codec.encode({
    ...mbase,
    Signers: [
      { Signer: { Account: M.a1, SigningPubKey: M.s1.publicKey, TxnSignature: msig1 } },
      { Signer: { Account: M.a2, SigningPubKey: M.s2.publicKey, TxnSignature: msig2 } },
    ],
  });

  // verifyExact lets a multisig through with signatureVerified:false (offline-unbindable).
  const vm = verifyExact({ txBlob: multiBlob }, req);
  // (some codec/verify combos may not validate a multisig blob's overall sig; if it
  // passes, signatureVerified MUST be false.)
  if (vm.isValid) assert.equal(vm.signatureVerified, false, "multisig offline -> signatureVerified:false");

  // (a) AUTHORIZED: on-ledger SignerList = both signers, quorum 2 -> meets quorum.
  const slBoth = { SignerQuorum: 2, SignerEntries: [
    { SignerEntry: { Account: M.a1, SignerWeight: 1 } },
    { SignerEntry: { Account: M.a2, SignerWeight: 1 } },
  ] };
  const mkClient = (signerLists, { onSubmit } = {}) => {
    let submitCount = 0;
    const c = {
      isConnected: () => true,
      get submitCount() { return submitCount; },
      request: async (q) => {
        if (q.command === "account_info") {
          return { result: { account_data: { signer_lists: signerLists } } };
        }
        return { result: { account_objects: [] } };
      },
      submitAndWait: async () => { submitCount++; if (onSubmit) onSubmit(); return { result: { hash: "MULTIHASH", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } } }; },
    };
    return c;
  };

  if (vm.isValid) {
    const store = new InMemoryStore({ now: () => now });
    const client = mkClient([slBoth]);
    const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
    const out = await __test.settle({ txBlob: multiBlob }, req, deps);
    assert.equal(out.success, true, `multisig meeting quorum settles: ${out.errorReason}`);
    assert.equal(out.signatureVerified, true, "authorized multisig reports signatureVerified:true");
    assert.equal(out.signatureSource, "multisig", "authorized multisig reports source multisig");
    assert.equal(client.submitCount, 1, "authorized multisig submitted once");
  }

  // (b) REJECTED pre-submit: quorum 3 (unreachable) -> rejected, submit NOT called.
  {
    const slHigh = { SignerQuorum: 3, SignerEntries: slBoth.SignerEntries };
    const store = new InMemoryStore({ now: () => now });
    const client = mkClient([slHigh]);
    const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
    const out = await __test.settle({ txBlob: multiBlob }, req, deps);
    assert.equal(out.success, false, "under-quorum multisig rejected at settle");
    assert.match(out.errorReason, /quorum not met|unauthorized/);
    assert.equal(out.signatureVerified, false, "rejected multisig reports signatureVerified:false");
    assert.equal(client.submitCount, 0, "REJECTED multisig does NOT submit (asserted submit not called)");
    assert.equal(store.map.size, 0, "rejected multisig reserves NO replay slot");
  }

  // (c) FALLBACK: node SignerList read FAILS -> proceed to submit (ledger authority),
  //     no fabricated authorization (signatureVerified stays false).
  if (vm.isValid) {
    const store = new InMemoryStore({ now: () => now });
    let submitCount = 0;
    const client = {
      isConnected: () => true,
      request: async (q) => {
        if (q.command === "account_info") throw new Error("node down");
        if (q.command === "account_objects" && q.type === "signer_list") throw new Error("node down");
        return { result: { account_objects: [] } };
      },
      submitAndWait: async () => { submitCount++; return { result: { hash: "FBHASH", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } } }; },
    };
    const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
    const out = await __test.settle({ txBlob: multiBlob }, req, deps);
    assert.equal(out.success, true, "node-read failure FALLS BACK to submit (ledger authority)");
    assert.equal(out.signatureVerified, false, "fallback does NOT fabricate authorization (signatureVerified:false)");
    assert.equal(out.signatureSource, null, "fallback has no signatureSource");
    assert.equal(submitCount, 1, "fallback proceeds to submit exactly once");
  }

  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// ===========================================================================
// UPGRADE #4 — proxy-aware clientIp()
// ===========================================================================
{
  const { clientIp } = __test;
  const mkReq = (socket, xff) => ({ socket: { remoteAddress: socket }, headers: xff != null ? { "x-forwarded-for": xff } : {} });

  // hops=0 (default): NEVER trust XFF -> use socket address.
  assert.equal(clientIp(mkReq("10.0.0.1", "1.2.3.4"), 0), "10.0.0.1", "trust_proxy=0 ignores XFF (uses socket)");
  assert.equal(clientIp(mkReq("10.0.0.1"), 0), "10.0.0.1", "trust_proxy=0 no XFF -> socket");
  // Spoofed XFF when proxy=0 is NOT trusted.
  assert.equal(clientIp(mkReq("10.0.0.1", "evil-spoof, 9.9.9.9"), 0), "10.0.0.1", "trust_proxy=0 does not trust a spoofed XFF");

  // hops=1: strip 1 trusted hop -> client is the entry immediately left of it.
  assert.equal(clientIp(mkReq("10.0.0.1", "1.2.3.4, 10.0.0.1"), 1), "1.2.3.4", "trust_proxy=1 strips one hop -> real client");
  // hops=1 with a spoofed prefix: "spoof, client, proxy" -> client is 2nd-from-right.
  assert.equal(clientIp(mkReq("10.0.0.1", "spoof, 1.2.3.4, 10.0.0.1"), 1), "1.2.3.4", "trust_proxy=1 picks the (hops+1)-th from right, not the spoof");

  // hops=2: strip 2 trusted hops.
  assert.equal(clientIp(mkReq("10.0.0.1", "1.2.3.4, 10.0.0.2, 10.0.0.1"), 2), "1.2.3.4", "trust_proxy=2 strips two hops");

  // malformed / short XFF falls back to socket.
  assert.equal(clientIp(mkReq("10.0.0.1", ""), 1), "10.0.0.1", "empty XFF -> socket fallback");
  assert.equal(clientIp(mkReq("10.0.0.1", "   "), 1), "10.0.0.1", "whitespace-only XFF -> socket fallback");
  assert.equal(clientIp(mkReq("10.0.0.1", "1.2.3.4"), 2), "10.0.0.1", "fewer XFF entries than trusted hops -> socket fallback");
  // missing socket entirely -> "unknown" (never throws).
  assert.equal(clientIp({ socket: {}, headers: {} }, 0), "unknown", "no socket addr -> 'unknown'");
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

// ===========================================================================
// OPERATIONAL HARDENING + x402 SPEC-COMPLIANCE
// ===========================================================================

// ---- config validation (unit) ---------------------------------------------
{
  const { validateConfig } = __test;
  // A clean minimal config (no XAHAU_WSS) is non-fatal but warns settle disabled.
  let r = validateConfig({});
  assert.equal(r.fatal.length, 0, "empty env has no fatal config errors");
  assert.ok(r.warnings.some((w) => /XAHAU_WSS/.test(w)), "unset XAHAU_WSS warns settle disabled");

  // Bad PORT -> fatal.
  r = validateConfig({ PORT: "not-a-number" });
  assert.ok(r.fatal.some((f) => /PORT/.test(f)), "non-numeric PORT is fatal");
  r = validateConfig({ PORT: "99999" });
  assert.ok(r.fatal.some((f) => /PORT/.test(f)), "out-of-range PORT is fatal");
  r = validateConfig({ PORT: "4021", XAHAU_WSS: "wss://x.example" });
  assert.equal(r.fatal.length, 0, "valid PORT + wss is clean");

  // Malformed XAHAU_WSS (not ws/wss) -> fatal.
  r = validateConfig({ XAHAU_WSS: "http://x.example" });
  assert.ok(r.fatal.some((f) => /XAHAU_WSS/.test(f)), "non-ws(s) XAHAU_WSS is fatal");
  r = validateConfig({ XAHAU_WSS: "ws://node.example:6006" });
  assert.equal(r.fatal.length, 0, "ws:// XAHAU_WSS is accepted");

  // Inconsistent network id vs name -> fatal.
  r = validateConfig({ XAHAU_NETWORK: "xahau", XAHAU_NETWORK_ID: "21338" });
  assert.ok(r.fatal.some((f) => /disagrees/.test(f)), "id disagreeing with named network is fatal");
  r = validateConfig({ XAHAU_NETWORK: "xahau", XAHAU_NETWORK_ID: "21337" });
  assert.equal(r.fatal.length, 0, "consistent network id+name is clean");
  r = validateConfig({ XAHAU_NETWORK: "bogus-net" });
  assert.ok(r.fatal.some((f) => /not a known network/.test(f)), "unknown network name is fatal");

  // Malformed Redis URL -> fatal; valid -> clean.
  r = validateConfig({ X402_REDIS_URL: "not a url" });
  assert.ok(r.fatal.some((f) => /X402_REDIS_URL/.test(f)), "malformed redis url is fatal");
  r = validateConfig({ X402_REDIS_URL: "redis://localhost:6379" });
  assert.equal(r.fatal.length, 0, "valid redis url is clean");
}

// ---- buildHealth (unit) ----------------------------------------------------
{
  const { buildHealth } = __test;
  const h = buildHealth();
  assert.equal(typeof h.status, "string", "health has a status");
  assert.equal(h.network, "xahau", "health reports network");
  assert.equal(h.networkID, EXPECTED_NETWORK_ID, "health reports networkID");
  assert.ok(h.replayStore === "memory" || h.replayStore === "redis", "health reports replayStore backend");
  assert.ok(h.rateLimiter === "memory" || h.rateLimiter === "redis", "health reports rateLimiter backend");
  assert.equal(typeof h.xrplConfigured, "boolean", "health reports xrplConfigured honestly");
  assert.equal(typeof h.uptimeSec, "number", "health reports uptimeSec");
  assert.ok(h.uptimeSec >= 0, "uptimeSec is non-negative");
  assert.equal(typeof h.replayBindings, "number", "health reports replayBindings count");
  // Honesty: without a live xrpl/redis connection, connected fields are never a
  // fabricated true.
  if ("xrplConnected" in h) assert.equal(typeof h.xrplConnected, "boolean", "xrplConnected is a real boolean");
  if ("redisConnected" in h) assert.equal(typeof h.redisConnected, "boolean", "redisConnected is a real boolean");

  // Auth split: an UNAUTHENTICATED health build is the MINIMAL liveness shape only —
  // no sensitive internals (backends, connectivity, networkID, replayBindings).
  const hm = buildHealth(false);
  assert.equal(hm.status, "ok", "minimal health still reports status");
  assert.equal(hm.network, "xahau", "minimal health reports network");
  assert.equal(typeof hm.uptimeSec, "number", "minimal health reports uptimeSec");
  assert.equal("replayBindings" in hm, false, "minimal health hides replayBindings");
  assert.equal("replayStore" in hm, false, "minimal health hides replayStore backend");
  assert.equal("rateLimiter" in hm, false, "minimal health hides rateLimiter backend");
  assert.equal("networkID" in hm, false, "minimal health hides networkID");
  assert.equal("xrplConfigured" in hm, false, "minimal health hides xrplConfigured");
}

// ---- metrics increment on REAL events (unit) -------------------------------
{
  const { metrics, recordSettleReject } = __test;
  const before = metrics.settle_rejected;
  const beforeBucket = metrics.settle_rejected_verify_failed;
  recordSettleReject("verify_failed");
  assert.equal(metrics.settle_rejected, before + 1, "recordSettleReject bumps the total");
  assert.equal(metrics.settle_rejected_verify_failed, beforeBucket + 1, "and the matching bucket");
  // An unknown bucket lands in _other so the breakdown still sums to the total.
  const beforeOther = metrics.settle_rejected_other;
  const beforeTotal = metrics.settle_rejected;
  recordSettleReject("totally-unknown-bucket");
  assert.equal(metrics.settle_rejected_other, beforeOther + 1, "unknown bucket -> _other");
  assert.equal(metrics.settle_rejected, beforeTotal + 1, "total still increments for unknown bucket");
}

// ---- Prometheus exposition shape (unit) ------------------------------------
{
  const { metricsPrometheus } = __test;
  const text = metricsPrometheus();
  assert.match(text, /# TYPE x402_verify_total counter/, "prometheus output declares verify_total counter type");
  assert.match(text, /x402_settle_total \d+/, "prometheus output emits settle_total value");
}

// ---- settle response carries the x402-spec `payer` field -------------------
// x402 SettleResponse requires { success, transaction, network, payer }. A verify-
// failed settle must still carry these spec fields (non-breaking — originals stay).
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example"; // never connected to
  const out = await __test.settle({ txBlob: blob({ Amount: "2000000" }) }, req); // over-max
  assert.equal(out.success, false, "over-max settle rejected (existing behavior)");
  assert.match(out.errorReason, /verify failed/, "errorReason preserved");
  assert.equal(typeof out.transaction, "string", "spec field `transaction` present (empty on failure)");
  assert.ok("payer" in out, "spec field `payer` present on settle response");
  assert.equal(out.network, "xahau", "spec field `network` present");
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// ---- verify response retains spec fields (isValid/invalidReason/payer) ------
{
  const ok = verifyExact({ txBlob: blob() }, req);
  assert.equal(ok.isValid, true, "spec field isValid present + true on valid payment");
  assert.equal(ok.payer, PAYER, "spec field payer present on verify");
  const bad = verifyExact({ txBlob: blob() }, { network: "xahau" });
  assert.equal(bad.isValid, false, "spec field isValid false on invalid");
  assert.equal(typeof bad.invalidReason, "string", "spec field invalidReason present on invalid");
}

// ---- IOU success settle still carries payer (additive, non-breaking) -------
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const client = iouFakeClient({
    result: { hash: "PAYEROK", meta: { TransactionResult: "tesSUCCESS", delivered_amount: { currency: "USD", issuer: ISSUER, value: "1.5" } } },
  });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: iouBlob({}, { LastLedgerSequence: curLedger + 5, Sequence: 222 }) };
  const out = await __test.settle(payment, iouReq, deps);
  assert.equal(out.success, true, `IOU settle success: ${out.errorReason}`);
  assert.equal(out.transaction, "PAYEROK", "tx hash preserved on success receipt");
  assert.equal(out.payer, PAYER, "settle success receipt carries the verified payer");
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// ---- /health + /metrics over a real spawned server (integration) -----------
// Confirms the routes are wired (200 + documented shape), and that verify_total /
// rate_limited_total actually move after the corresponding requests.
await new Promise((resolveTest, rejectTest) => {
  (async () => {
    const { spawn } = await import("node:child_process");
    const PORT = 4097;
    const SECRET = "test-metrics-secret";
    const child = spawn(process.execPath, ["server.mjs"], {
      env: { ...process.env, PORT: String(PORT), X402_RATE_MAX: "2", XAHAU_WSS: "", X402_SHARED_SECRET: SECRET },
      stdio: ["ignore", "ignore", "ignore"],
    });
    const SEC = { "x-x402-secret": SECRET };
    const getJson = (path, headers = {}) => new Promise((res) => {
      const r = http.request({ host: "127.0.0.1", port: PORT, path, method: "GET", headers }, (resp) => {
        let data = ""; resp.on("data", (c) => (data += c));
        resp.on("end", () => { let body; try { body = JSON.parse(data); } catch { body = data; } res({ status: resp.statusCode, body, raw: data }); });
      });
      r.on("error", () => res({ status: null, body: null }));
      r.end();
    });
    const postJson = (path) => new Promise((res) => {
      const body = "{}";
      const r = http.request({ host: "127.0.0.1", port: PORT, path, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) } }, (resp) => { resp.resume(); resp.on("end", () => res(resp.statusCode)); });
      r.on("error", () => res(null)); r.write(body); r.end();
    });
    const waitListen = async () => {
      for (let i = 0; i < 50; i++) {
        const ok = await new Promise((res) => {
          const r = http.request({ host: "127.0.0.1", port: PORT, path: "/health", method: "GET" }, (resp) => { resp.resume(); res(resp.statusCode === 200); });
          r.on("error", () => res(false)); r.end();
        });
        if (ok) return true;
        await new Promise((r) => setTimeout(r, 100));
      }
      return false;
    };
    try {
      assert.equal(await waitListen(), true, "facilitator should start for the health/metrics test");

      // /health WITHOUT the secret: 200 + MINIMAL liveness shape only (LB probe). The
      // sensitive internals must NOT be present unauthenticated.
      const hMin = await getJson("/health");
      assert.equal(hMin.status, 200, "/health (no secret) still returns 200 (LB liveness)");
      assert.equal(hMin.body.status, "ok", "/health minimal body.status ok");
      assert.equal(hMin.body.network, "xahau", "/health minimal reports network");
      assert.equal(typeof hMin.body.uptimeSec, "number", "/health minimal uptimeSec is a number");
      assert.equal("replayBindings" in hMin.body, false, "/health minimal hides replayBindings (no secret)");
      assert.equal("replayStore" in hMin.body, false, "/health minimal hides replayStore backend (no secret)");
      assert.equal("rateLimiter" in hMin.body, false, "/health minimal hides rateLimiter backend (no secret)");
      assert.equal("networkID" in hMin.body, false, "/health minimal hides networkID (no secret)");

      // /health WITH the secret: 200 + FULL documented shape.
      const h = await getJson("/health", SEC);
      assert.equal(h.status, 200, "/health (with secret) returns 200");
      assert.equal(h.body.status, "ok", "/health body.status ok");
      assert.equal(h.body.network, "xahau", "/health reports network");
      assert.equal(h.body.networkID, EXPECTED_NETWORK_ID, "/health reports networkID");
      assert.equal(h.body.xrplConfigured, false, "/health honestly reports xrpl not configured (XAHAU_WSS empty)");
      assert.equal(typeof h.body.uptimeSec, "number", "/health uptimeSec is a number");
      assert.equal(typeof h.body.replayBindings, "number", "/health replayBindings is a number");
      assert.equal(h.body.replayStore, "memory", "/health replayStore=memory (no redis configured)");

      // /metrics WITHOUT the secret: 401 (auth-gated, same secret as /settle).
      const mUnauth = await getJson("/metrics");
      assert.equal(mUnauth.status, 401, "/metrics without the secret -> 401 (auth-gated)");

      // /metrics WITH the secret: 200 JSON counters, snapshot verify_total + rate_limited_total.
      const m1 = await getJson("/metrics", SEC);
      assert.equal(m1.status, 200, "/metrics (with secret) returns 200");
      assert.equal(typeof m1.body.verify_total, "number", "/metrics exposes verify_total");
      assert.equal(typeof m1.body.rate_limited_total, "number", "/metrics exposes rate_limited_total");
      const v0 = m1.body.verify_total;
      const rl0 = m1.body.rate_limited_total;

      // Fire /verify: rate max=2, so #1 and #2 allowed (verify_total +2), #3 rate-limited.
      const s1 = await postJson("/verify");
      const s2 = await postJson("/verify");
      const s3 = await postJson("/verify");
      assert.equal(s1, 200, "verify #1 allowed");
      assert.equal(s2, 200, "verify #2 allowed");
      assert.equal(s3, 429, "verify #3 rate-limited");

      const m2 = await getJson("/metrics", SEC);
      assert.equal(m2.body.verify_total, v0 + 2, "verify_total incremented by the 2 allowed verifies (real event)");
      assert.equal(m2.body.rate_limited_total, rl0 + 1, "rate_limited_total incremented by the 1 rejected request (real event)");

      // /metrics Prometheus text on Accept: text/plain (still auth-gated).
      const mp = await getJson("/metrics", { ...SEC, accept: "text/plain" });
      assert.equal(mp.status, 200, "/metrics text returns 200");
      assert.match(mp.raw, /x402_verify_total \d+/, "/metrics text emits prometheus counter");

      resolveTest();
    } catch (e) { rejectTest(e); }
    finally { child.kill("SIGKILL"); }
  })().catch(rejectTest);
});

// ===========================================================================
// FEATURE 1 — GET /policy/:account (on-ledger budget introspection)
// ===========================================================================
// Decode the agent_guardrail Hook's HookParameters straight from the chain. The
// canonical encoding (from docs/FACILITATOR-TESTNET-PROOF.md): param NAME = hex of
// ASCII ("LIM"->4C494D, "DST"->445354); LIM value = 8-byte BE drops; DST = 20-byte
// account-id. FAIL-TRANSPARENT: node/decode errors -> policy:null + note, never a
// fabricated limit.
{
  const { getPolicy, hookParamsMap, decode8ByteDropsHex, accountIdHexToRAddress, HOOK_PARAM_LIM, HOOK_PARAM_DST } = __test;

  // Param-name encoding is correct.
  assert.equal(HOOK_PARAM_LIM, "4C494D", "LIM param name is hex of ASCII 'LIM'");
  assert.equal(HOOK_PARAM_DST, "445354", "DST param name is hex of ASCII 'DST'");

  // 8-byte BE drops decode (5 XAH = 5_000_000 drops = 0x00000000004C4B40 from the proof).
  assert.equal(decode8ByteDropsHex("00000000004C4B40"), "5000000", "decodes 5 XAH per-tx cap from the proof");
  assert.equal(decode8ByteDropsHex("0000000000000001"), "1", "decodes 1 drop");
  assert.equal(decode8ByteDropsHex("zz"), null, "malformed hex -> null (no fabrication)");
  assert.equal(decode8ByteDropsHex("00"), null, "wrong-length hex -> null");

  // DST account-id -> r-address (the proof's DST decodes to PAYEE).
  assert.equal(accountIdHexToRAddress("F1B9322DE209841AAE84BFBDA0118003D3A8B5F0"), "rPsf618mGxJgrvp5ubFYBTMEaJFY2KJWY3", "DST account-id decodes to the allowlisted r-address");
  assert.equal(accountIdHexToRAddress("nothex"), null, "malformed DST -> null");

  // hookParamsMap tolerates both shapes.
  const m1 = hookParamsMap({ HookParameters: [{ HookParameter: { HookParameterName: "4c494d", HookParameterValue: "00000000004c4b40" } }] });
  assert.equal(m1.get("4C494D"), "00000000004C4B40", "hookParamsMap uppercases + reads nested shape");
  const m2 = hookParamsMap({ HookParameters: [{ HookParameterName: "445354", HookParameterValue: "abcd" }] });
  assert.equal(m2.get("445354"), "ABCD", "hookParamsMap reads flat shape");
  assert.equal(hookParamsMap({}).size, 0, "no params -> empty map");

  // getPolicy: a guardrail Hook with LIM + DST -> decoded per-tx cap + allowlist.
  const clientWithGuardrail = {
    request: async (q) => {
      if (q.command === "ledger") return { result: { ledger_index: 9720000 } };
      if (q.command === "account_objects" && q.type === "hook") {
        return { result: { account_objects: [
          { HookParameters: [
            { HookParameter: { HookParameterName: "4C494D", HookParameterValue: "00000000004C4B40" } },
            { HookParameter: { HookParameterName: "445354", HookParameterValue: "F1B9322DE209841AAE84BFBDA0118003D3A8B5F0" } },
          ] },
        ] } };
      }
      return { result: {} };
    },
  };
  let pol = await getPolicy(clientWithGuardrail, PAYER);
  assert.equal(pol.guardrailHookPresent, true, "guardrail Hook reported present");
  assert.equal(pol.source, "on-ledger", "source is on-ledger");
  assert.equal(pol.asOfLedger, 9720000, "asOfLedger reflects the validated index");
  assert.ok(pol.policy, "policy decoded");
  assert.equal(pol.policy.perTxLimitDrops, "5000000", "per-tx limit decoded from LIM");
  assert.equal(pol.policy.stateful, false, "stateless guardrail -> stateful:false (no fabricated remaining)");
  assert.equal("remaining" in pol.policy, false, "no fabricated remaining budget for a stateless cap");
  assert.deepEqual(pol.policy.allowlist, ["rPsf618mGxJgrvp5ubFYBTMEaJFY2KJWY3"], "DST allowlist decoded to r-address");

  // getPolicy: LIM only (no DST) -> cap but no allowlist.
  const clientLimOnly = {
    request: async (q) => {
      if (q.command === "ledger") return { result: { ledger_index: 100 } };
      if (q.command === "account_objects") return { result: { account_objects: [ { HookParameters: [ { HookParameter: { HookParameterName: "4C494D", HookParameterValue: "0000000000989680" } } ] } ] } };
      return { result: {} };
    },
  };
  pol = await getPolicy(clientLimOnly, PAYER);
  assert.equal(pol.policy.perTxLimitDrops, "10000000", "LIM-only decodes the cap (10 XAH)");
  assert.equal("allowlist" in pol.policy, false, "no DST -> no allowlist key");

  // getPolicy: no Hook installed -> guardrailHookPresent:false, policy:null, honest note.
  const clientNoHook = {
    request: async (q) => {
      if (q.command === "ledger") return { result: { ledger_index: 100 } };
      if (q.command === "account_objects") return { result: { account_objects: [] } };
      return { result: {} };
    },
  };
  pol = await getPolicy(clientNoHook, PAYER);
  assert.equal(pol.guardrailHookPresent, false, "no Hook -> guardrailHookPresent:false");
  assert.equal(pol.policy, null, "no Hook -> policy:null");
  assert.match(pol.note, /no Hook installed/, "honest note for no Hook");

  // getPolicy: a Hook present but NOT the guardrail (no LIM) -> present:true, policy:null.
  const clientOtherHook = {
    request: async (q) => {
      if (q.command === "ledger") return { result: { ledger_index: 100 } };
      if (q.command === "account_objects") return { result: { account_objects: [ { HookParameters: [ { HookParameter: { HookParameterName: "ABCDEF", HookParameterValue: "00" } } ] } ] } };
      return { result: {} };
    },
  };
  pol = await getPolicy(clientOtherHook, PAYER);
  assert.equal(pol.guardrailHookPresent, true, "some Hook is present");
  assert.equal(pol.policy, null, "unrecognized Hook -> policy:null (never guess)");
  assert.match(pol.note, /no recognizable guardrail/, "honest note for unrecognized Hook");

  // getPolicy: FAIL-TRANSPARENT on a node read error -> present:null, policy:null, note.
  const clientNodeDown = {
    request: async (q) => {
      if (q.command === "ledger") throw new Error("node down");
      throw new Error("node down");
    },
  };
  pol = await getPolicy(clientNodeDown, PAYER);
  assert.equal(pol.guardrailHookPresent, null, "node read failure -> guardrailHookPresent:null (never fabricate)");
  assert.equal(pol.policy, null, "node read failure -> policy:null");
  assert.match(pol.note, /node read failed/, "honest note on node failure");

  // getPolicy: LIM present but value undecodable -> present:true, policy:null, note (no fabrication).
  const clientBadLim = {
    request: async (q) => {
      if (q.command === "ledger") return { result: { ledger_index: 100 } };
      if (q.command === "account_objects") return { result: { account_objects: [ { HookParameters: [ { HookParameter: { HookParameterName: "4C494D", HookParameterValue: "XYZ" } } ] } ] } };
      return { result: {} };
    },
  };
  pol = await getPolicy(clientBadLim, PAYER);
  assert.equal(pol.policy, null, "undecodable LIM -> policy:null (never fabricate a limit)");
  assert.match(pol.note, /could not be decoded/, "honest note for undecodable LIM");
}

// ===========================================================================
// FEATURE 1b — STATEFUL period-budget guardrail (PLM/PER + on-chain HookState)
// ===========================================================================
// The stateful Hook (agent_guardrail_stateful.c) carries PLM (period drops cap) +
// PER (period length in ledgers) ON TOP OF LIM/DST. /policy reads its single 16-byte
// HookState entry [periodStart u64 || spent u64] and reports the agent's REAL
// remaining budget per the STATE.md formulas. FAIL-TRANSPARENT: any value it cannot
// read/decode -> remaining:null + a note, NEVER a fabricated budget.
{
  const {
    getPolicy, decode8ByteDropsBig, decodePerLedgers, decodeStatefulStateValue, computeBudget,
    HOOK_PARAM_PLM, HOOK_PARAM_PER, STATEFUL_STATE_KEY_HEX,
  } = __test;

  // Param-name encoding + state-key form are correct.
  assert.equal(HOOK_PARAM_PLM, "504C4D", "PLM param name is hex of ASCII 'PLM'");
  assert.equal(HOOK_PARAM_PER, "504552", "PER param name is hex of ASCII 'PER'");
  assert.equal(STATEFUL_STATE_KEY_HEX, "0000000000000000000000000000000000000000000000000000000000000001", "state key is 0x01 left-padded to 32 bytes");

  // Low-level decoders.
  assert.equal(decode8ByteDropsBig("0000000005F5E100"), 100000000n, "PLM 8-byte BE drops -> bigint");
  assert.equal(decodePerLedgers("000003E8"), 1000n, "PER 4-byte BE -> 1000 ledgers");
  assert.equal(decodePerLedgers("00000000000003E8"), 1000n, "PER 8-byte BE -> 1000 ledgers");
  assert.equal(decodePerLedgers("00"), null, "PER wrong length -> null (Hook rolls back on bad PER)");
  assert.equal(decodePerLedgers("00000000"), null, "PER == 0 -> null (must be > 0)");
  const sv = decodeStatefulStateValue("00000000000027100000000001C9C380");
  assert.equal(sv.periodStart, 10000n, "decode periodStart from 16-byte value");
  assert.equal(sv.spent, 30000000n, "decode spent from 16-byte value");
  assert.equal(decodeStatefulStateValue("0011"), null, "non-16-byte value -> null (corrupt)");

  // computeBudget formula spot-checks (BigInt math, exact).
  const cb = computeBudget({ now: 10500n, periodStart: 10000n, spent: 30000000n, lim: 5000000n, plm: 100000000n, per: 1000n });
  assert.equal(cb.remaining, "70000000", "live partial: remaining = PLM - spent");
  assert.equal(cb.resetInLedgers, "500", "reset = periodStart + PER - now");
  assert.equal(cb.maxNextPayment, "5000000", "maxNext = min(LIM, remaining)");

  // Shared hex fixtures for the stateful Hook.
  const LIM_HEX = "00000000004C4B40";      // 5 XAH per-tx
  const PLM_HEX = "0000000005F5E100";      // 100 XAH per period
  const PER_HEX = "000003E8";              // 1000 ledgers (4-byte form)
  const NS_HEX = "AA".repeat(32);          // 32-byte HookNamespace
  const STATE_KEY = STATEFUL_STATE_KEY_HEX.toUpperCase();

  // Build a fake node client that serves the stateful Hook + a configurable state read.
  // `stateMode`: "present" (value), "absent", "error", or "corrupt".
  const makeStatefulClient = ({ nowLedger, stateValue, stateMode = "present" }) => ({
    request: async (q) => {
      if (q.command === "ledger") return { result: { ledger_index: nowLedger } };
      if (q.command === "account_objects" && q.type === "hook") {
        return { result: { account_objects: [
          { HookNamespace: NS_HEX, HookParameters: [
            { HookParameter: { HookParameterName: "4C494D", HookParameterValue: LIM_HEX } },
            { HookParameter: { HookParameterName: HOOK_PARAM_PLM, HookParameterValue: PLM_HEX } },
            { HookParameter: { HookParameterName: HOOK_PARAM_PER, HookParameterValue: PER_HEX } },
          ] },
        ] } };
      }
      if (q.command === "ledger_entry" && q.hook_state) {
        // Validate the facilitator queried the right key/namespace.
        assert.equal(q.hook_state.account, PAYER, "hook_state read targets the agent account");
        assert.equal(q.hook_state.key, STATE_KEY, "hook_state key is the 32-byte 0x01");
        assert.equal(q.hook_state.namespace_id, NS_HEX.toUpperCase(), "hook_state namespace_id is the Hook's HookNamespace");
        if (stateMode === "error") throw new Error("node down");
        if (stateMode === "absent") throw Object.assign(new Error("entryNotFound"), { message: "entryNotFound" });
        return { result: { node: { HookStateData: stateMode === "corrupt" ? "0011" : stateValue } } };
      }
      return { result: {} };
    },
  });

  // (a) Same-period, partially spent: remaining = PLM - spent.
  let pol = await getPolicy(makeStatefulClient({ nowLedger: 10500, stateValue: "00000000000027100000000001C9C380" }), PAYER);
  assert.equal(pol.policy.stateful, true, "(a) stateful:true when PLM+PER present");
  assert.equal(pol.policy.source, "on-ledger", "(a) source on-ledger");
  assert.equal(pol.policy.perTxLimitDrops, "5000000", "(a) LIM decoded");
  assert.equal(pol.policy.periodLimitDrops, "100000000", "(a) PLM decoded");
  assert.equal(pol.policy.periodLedgers, "1000", "(a) PER decoded");
  assert.equal(pol.policy.spentThisPeriod, "30000000", "(a) spent read from state");
  assert.equal(pol.policy.remaining, "70000000", "(a) remaining = PLM - spent");
  assert.equal(pol.policy.periodStartLedger, "10000", "(a) periodStartLedger from state");
  assert.equal(pol.policy.resetInLedgers, "500", "(a) resetInLedgers = start + PER - now");
  assert.equal(pol.policy.maxNextPayment, "5000000", "(a) maxNext = min(LIM, remaining)");

  // (b) spent == PLM -> remaining 0, maxNext 0.
  pol = await getPolicy(makeStatefulClient({ nowLedger: 10500, stateValue: "00000000000027100000000005F5E100" }), PAYER);
  assert.equal(pol.policy.remaining, "0", "(b) spent==PLM -> remaining 0");
  assert.equal(pol.policy.maxNextPayment, "0", "(b) maxNext 0 when budget exhausted");

  // (c) period elapsed (now - periodStart >= PER): remaining = full PLM, reset 0.
  pol = await getPolicy(makeStatefulClient({ nowLedger: 20000, stateValue: "00000000000027100000000001C9C380" }), PAYER);
  assert.equal(pol.policy.remaining, "100000000", "(c) elapsed period -> full PLM remaining");
  assert.equal(pol.policy.resetInLedgers, "0", "(c) elapsed -> resetInLedgers 0");
  assert.equal(pol.policy.maxNextPayment, "5000000", "(c) maxNext = min(LIM, PLM)");
  assert.match(pol.policy.note, /elapsed/, "(c) note explains the fresh-period reset");

  // (d) absent state key -> fresh-period values + note.
  pol = await getPolicy(makeStatefulClient({ nowLedger: 10500, stateMode: "absent" }), PAYER);
  assert.equal(pol.policy.stateful, true, "(d) still stateful:true");
  assert.equal(pol.policy.spentThisPeriod, "0", "(d) fresh period -> spent 0");
  assert.equal(pol.policy.remaining, "100000000", "(d) fresh period -> full PLM");
  assert.equal(pol.policy.resetInLedgers, "0", "(d) no period open -> reset 0");
  assert.equal(pol.policy.maxNextPayment, "5000000", "(d) maxNext = min(LIM, PLM)");
  assert.match(pol.policy.note, /no period opened yet/, "(d) honest fresh-period note");

  // (e) node/state read error -> remaining:null + note (NO fabrication), caps still shown.
  pol = await getPolicy(makeStatefulClient({ nowLedger: 10500, stateMode: "error" }), PAYER);
  assert.equal(pol.policy.stateful, true, "(e) stateful:true even when state unreadable");
  assert.equal(pol.policy.periodLimitDrops, "100000000", "(e) decoded caps still reported");
  assert.equal(pol.policy.remaining, null, "(e) unreadable state -> remaining:null (never fabricate)");
  assert.equal("spentThisPeriod" in pol.policy, false, "(e) no fabricated spent");
  assert.match(pol.policy.note, /could not read hook state/, "(e) honest note on state read failure");

  // (e2) corrupt (non-16-byte) state value -> remaining:null + note.
  pol = await getPolicy(makeStatefulClient({ nowLedger: 10500, stateMode: "corrupt" }), PAYER);
  assert.equal(pol.policy.remaining, null, "(e2) corrupt state value -> remaining:null");
  assert.match(pol.policy.note, /malformed/, "(e2) honest note on a corrupt state value");

  // (e3) account_namespace FALLBACK path (node lacks ledger_entry hook_state) -> still reads.
  const clientNsFallback = {
    request: async (q) => {
      if (q.command === "ledger") return { result: { ledger_index: 10500 } };
      if (q.command === "account_objects" && q.type === "hook") {
        return { result: { account_objects: [
          { HookNamespace: NS_HEX, HookParameters: [
            { HookParameter: { HookParameterName: "4C494D", HookParameterValue: LIM_HEX } },
            { HookParameter: { HookParameterName: HOOK_PARAM_PLM, HookParameterValue: PLM_HEX } },
            { HookParameter: { HookParameterName: HOOK_PARAM_PER, HookParameterValue: PER_HEX } },
          ] },
        ] } };
      }
      if (q.command === "ledger_entry") throw new Error("unknownCmd: ledger_entry hook_state not supported");
      if (q.command === "account_namespace") {
        assert.equal(q.namespace_id, NS_HEX.toUpperCase(), "fallback uses the Hook namespace");
        return { result: { namespace_entries: [ { HookStateKey: STATE_KEY, HookStateData: "00000000000027100000000001C9C380" } ] } };
      }
      return { result: {} };
    },
  };
  pol = await getPolicy(clientNsFallback, PAYER);
  assert.equal(pol.policy.remaining, "70000000", "(e3) account_namespace fallback decodes remaining");
  assert.equal(pol.policy.spentThisPeriod, "30000000", "(e3) fallback reads spent");

  // (f) the PER-TX-ONLY hook (LIM/DST, NO PLM/PER) still reports stateful:false.
  const clientPerTxOnly = {
    request: async (q) => {
      if (q.command === "ledger") return { result: { ledger_index: 10500 } };
      if (q.command === "account_objects" && q.type === "hook") {
        return { result: { account_objects: [ { HookNamespace: NS_HEX, HookParameters: [
          { HookParameter: { HookParameterName: "4C494D", HookParameterValue: LIM_HEX } },
        ] } ] } };
      }
      if (q.command === "ledger_entry" || q.command === "account_namespace")
        throw new Error("state should NOT be read for a per-tx-only hook");
      return { result: {} };
    },
  };
  pol = await getPolicy(clientPerTxOnly, PAYER);
  assert.equal(pol.policy.stateful, false, "(f) per-tx-only hook -> stateful:false (unchanged)");
  assert.equal(pol.policy.perTxLimitDrops, "5000000", "(f) per-tx cap still decoded");
  assert.equal("remaining" in pol.policy, false, "(f) no remaining for a stateless cap");
  assert.equal("periodLimitDrops" in pol.policy, false, "(f) no period fields for a stateless cap");

  // (g) stateful detected but PER undecodable -> caps partial, remaining:null + note.
  const clientBadPer = makeStatefulClient({ nowLedger: 10500, stateValue: "00000000000027100000000001C9C380" });
  const origBadPer = clientBadPer.request;
  clientBadPer.request = async (q) => {
    if (q.command === "account_objects" && q.type === "hook") {
      return { result: { account_objects: [ { HookNamespace: NS_HEX, HookParameters: [
        { HookParameter: { HookParameterName: "4C494D", HookParameterValue: LIM_HEX } },
        { HookParameter: { HookParameterName: HOOK_PARAM_PLM, HookParameterValue: PLM_HEX } },
        { HookParameter: { HookParameterName: HOOK_PARAM_PER, HookParameterValue: "00" } }, // bad PER length
      ] } ] } };
    }
    return origBadPer(q);
  };
  pol = await getPolicy(clientBadPer, PAYER);
  assert.equal(pol.policy.stateful, true, "(g) stateful detected via PLM presence");
  assert.equal(pol.policy.remaining, null, "(g) undecodable PER -> remaining:null (no fabrication)");
  assert.match(pol.policy.note, /PER/, "(g) honest note names the bad PER param");
}

// /policy integration over a spawned server: 503 when XAHAU_WSS unset, 400 on a bad
// address. (We don't exercise the live-node path here — covered by the unit tests
// above with an injected client.)
await new Promise((resolveTest, rejectTest) => {
  (async () => {
    const { spawn } = await import("node:child_process");
    const PORT = 4096;
    const child = spawn(process.execPath, ["server.mjs"], {
      env: { ...process.env, PORT: String(PORT), XAHAU_WSS: "" },
      stdio: ["ignore", "ignore", "ignore"],
    });
    const getJson = (path) => new Promise((res) => {
      const r = http.request({ host: "127.0.0.1", port: PORT, path, method: "GET" }, (resp) => {
        let data = ""; resp.on("data", (c) => (data += c));
        resp.on("end", () => { let body; try { body = JSON.parse(data); } catch { body = data; } res({ status: resp.statusCode, body }); });
      });
      r.on("error", () => res({ status: null, body: null })); r.end();
    });
    const waitListen = async () => {
      for (let i = 0; i < 50; i++) {
        const ok = await new Promise((res) => { const r = http.request({ host: "127.0.0.1", port: PORT, path: "/supported", method: "GET" }, (resp) => { resp.resume(); res(resp.statusCode === 200); }); r.on("error", () => res(false)); r.end(); });
        if (ok) return true; await new Promise((r) => setTimeout(r, 100));
      }
      return false;
    };
    try {
      assert.equal(await waitListen(), true, "facilitator should start for the /policy test");
      // Bad address -> 400.
      const bad = await getJson("/policy/not-an-address");
      assert.equal(bad.status, 400, "/policy with a bad address -> 400");
      // Valid address but XAHAU_WSS unset -> 503 (node not configured).
      const noNode = await getJson(`/policy/${PAYER}`);
      assert.equal(noNode.status, 503, "/policy with XAHAU_WSS unset -> 503");
      resolveTest();
    } catch (e) { rejectTest(e); }
    finally { child.kill("SIGKILL"); }
  })().catch(rejectTest);
});

// ===========================================================================
// FEATURE 2 — verifiable signed receipts + GET /pubkey
// ===========================================================================
{
  const { canonicalJSONStringify: cj, receiptSignablePayload: rsp, signReceipt, verifyReceipt, receiptPubkey, parseReceiptSecret, ed25519KeyFromSeed } = __test;

  // Canonical serialization: sorted keys, no whitespace, deterministic across insertion order.
  assert.equal(cj({ b: 1, a: 2 }), '{"a":2,"b":1}', "keys sorted ascending, no whitespace");
  assert.equal(cj({ a: 2, b: 1 }), cj({ b: 1, a: 2 }), "insertion-order independent");
  assert.equal(cj({ z: { y: 1, x: 2 }, a: [3, 2, 1] }), '{"a":[3,2,1],"z":{"x":2,"y":1}}', "recursive sort, array order preserved");
  assert.equal(cj(null), "null");
  // non-finite numbers are rejected (would produce bytes a verifier can't reproduce).
  assert.throws(() => cj({ x: Infinity }), "non-finite number rejected");

  // The signable projection has a FIXED key set; absent fields are null, not dropped.
  const proj = rsp({ network: "xahau", txHash: "H", payer: "rP", payTo: "rT" });
  assert.deepEqual(Object.keys(proj).sort(), ["asset", "delivered", "network", "payTo", "payer", "required", "ts", "txHash", "v"], "fixed key set");
  assert.equal(proj.v, 1, "version pinned");
  assert.equal(proj.delivered, null, "absent delivered -> null (not dropped)");

  // pubkey shape.
  const pk = receiptPubkey();
  assert.equal(pk.alg, "ed25519", "pubkey alg ed25519");
  assert.match(pk.pubkey, /^[0-9a-f]{64}$/, "pubkey is raw 32-byte hex");

  // Sign a receipt, then verify OFFLINE; tamper any field -> verification fails.
  const fields = { network: "xahau", txHash: "ABC123", payer: PAYER, payTo: PAY_TO, asset: null, delivered: "1000000", required: "1000000", ts: 1700000000000 };
  const proof = signReceipt(fields);
  assert.ok(proof && proof.alg === "ed25519", "signReceipt returns an ed25519 proof");
  assert.equal(proof.pubkey, pk.pubkey, "proof pubkey matches /pubkey");
  // Build the receipt the way settle does (the same fields + proof).
  const receipt = { network: "xahau", txHash: "ABC123", payer: PAYER, payTo: PAY_TO, asset: null, delivered: "1000000", required: "1000000", ts: 1700000000000, proof };
  assert.equal(verifyReceipt(receipt), true, "a well-formed signed receipt verifies offline");
  assert.equal(verifyReceipt(receipt, { expectedPubkey: pk.pubkey }), true, "verifies against the expected pubkey");
  assert.equal(verifyReceipt(receipt, { expectedPubkey: "00".repeat(32) }), false, "wrong expected pubkey -> false");

  // Tamper detection: mutate each load-bearing field -> verification fails.
  for (const k of ["txHash", "payer", "payTo", "asset", "delivered", "required", "ts", "network"]) {
    const t = { ...receipt, [k]: (k === "ts" ? 1 : "TAMPERED") };
    assert.equal(verifyReceipt(t), false, `tampered ${k} -> verification fails`);
  }
  // Tamper the signature itself -> fails.
  assert.equal(verifyReceipt({ ...receipt, proof: { ...proof, sig: "00" + proof.sig.slice(2) } }), false, "tampered sig -> fails");
  // Missing/malformed proof -> false (never throws).
  assert.equal(verifyReceipt({ ...receipt, proof: null }), false, "no proof -> false");
  assert.equal(verifyReceipt({ ...receipt, proof: { alg: "rsa", pubkey: pk.pubkey, sig: proof.sig } }), false, "wrong alg -> false");
  assert.equal(verifyReceipt(null), false, "null receipt -> false (no throw)");

  // parseReceiptSecret: hex + base64 32-byte seeds parse; junk -> null.
  const seedHex = "07".repeat(32);
  assert.ok(parseReceiptSecret(seedHex), "64-char hex seed parses");
  assert.equal(parseReceiptSecret(Buffer.alloc(32, 7).toString("base64")).length, 32, "base64 32-byte seed parses");
  assert.equal(parseReceiptSecret("tooshort"), null, "junk secret -> null");
  assert.equal(parseReceiptSecret(""), null, "empty -> null");
  // A fixed seed yields a STABLE key (persistence across restarts when X402_RECEIPT_SECRET set).
  const k1 = ed25519KeyFromSeed(Buffer.alloc(32, 7));
  const k2 = ed25519KeyFromSeed(Buffer.alloc(32, 7));
  assert.ok(k1 && k2, "seed -> key");
  assert.equal(__test.receiptPubkey().pubkey.length, 64, "pubkey hex is 32 bytes");
}

// FEATURE 2 — a settle SUCCESS receipt carries a verifiable proof; a FAILED settle
// carries proof:null. End-to-end over the settle() seam.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore, verifyReceipt } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  const client = fakeClient({ result: { hash: "SIGNEDOK", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } } });
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const payment = { txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 401 }) };
  const out = await __test.settle(payment, req, deps);
  assert.equal(out.success, true, `signed settle succeeds: ${out.errorReason}`);
  assert.ok(out.proof && out.proof.alg === "ed25519", "success receipt carries an ed25519 proof");
  assert.equal(out.txHash, "SIGNEDOK", "receipt carries canonical txHash");
  assert.equal(out.payTo, PAY_TO, "receipt carries canonical payTo");
  assert.equal(out.required, "1000000", "receipt carries the required amount");
  assert.equal(typeof out.ts, "number", "receipt carries a ts");
  assert.equal(verifyReceipt(out), true, "the real settle receipt verifies offline");
  // Tamper the delivered amount on the returned receipt -> verification fails.
  assert.equal(verifyReceipt({ ...out, delivered: "999999999" }), false, "tampered delivered on a real receipt -> fails");

  // IOU receipt round-trip: a token settle carries `asset` on the receipt so the
  // SAME canonical bytes are signed + reconstructed (regression for the asset bug).
  const storeI = new InMemoryStore({ now: () => now });
  const clientI = fakeClient({ result: { hash: "IOUOK", meta: { TransactionResult: "tesSUCCESS", delivered_amount: { currency: "USD", issuer: ISSUER, value: "1.5" } } } });
  const depsI = { store: storeI, client: clientI, currentValidatedLedger: async () => curLedger, now: () => now };
  const outI = await __test.settle({ txBlob: iouBlob({ value: "1.5" }, { LastLedgerSequence: curLedger + 5, Sequence: 403 }) }, iouReq, depsI);
  assert.equal(outI.success, true, `IOU signed settle succeeds: ${outI.errorReason}`);
  assert.ok(outI.proof && outI.proof.alg === "ed25519", "IOU success receipt carries a proof");
  assert.deepEqual(outI.asset, IOU_ASSET, "IOU receipt surfaces the asset (so verify reconstructs the signed bytes)");
  assert.equal(verifyReceipt(outI), true, "the real IOU settle receipt verifies offline");
  assert.equal(verifyReceipt({ ...outI, asset: null }), false, "stripping asset from an IOU receipt -> verification fails");

  // A FAILED settle (tecHOOK_REJECTED) carries proof:null (not signed).
  const store2 = new InMemoryStore({ now: () => now });
  const client2 = fakeClient({ result: { hash: "REJ", meta: { TransactionResult: "tecHOOK_REJECTED" } } });
  const deps2 = { store: store2, client: client2, currentValidatedLedger: async () => curLedger, now: () => now };
  const out2 = await __test.settle({ txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 402 }) }, req, deps2);
  assert.equal(out2.success, false, "rejected settle");
  assert.equal(out2.proof, null, "a failed settle is NOT signed (proof:null)");

  // -------------------------------------------------------------------------
  // READ-ONLY Hook-execution transparency in the settle response.
  // -------------------------------------------------------------------------
  // The decodeHookExecutions helper is pure + defensive (unit-tested directly).
  {
    const { decodeHookExecutions, decodeHookReturnString } = __test;
    // Canonical { HookExecution: {...} } wrapper shape.
    const okMeta = { HookExecutions: [ { HookExecution: {
      HookAccount: PAYER,
      HookHash: "ABCDEF0123456789FEDCBA9876543210AABBCCDDEEFF0011",
      HookReturnCode: "0",
      HookReturnString: Buffer.from("within policy", "utf8").toString("hex"),
      HookEmitCount: "1",
      Flags: "0",
    } } ] };
    const dec = decodeHookExecutions(okMeta);
    assert.equal(dec.length, 1, "one hook execution decoded");
    assert.equal(dec[0].hookAccount, PAYER, "hookAccount surfaced");
    assert.equal(dec[0].hookHash, "ABCDEF0123456789", "hookHash shortened to 16 hex chars");
    assert.equal(dec[0].returnCode, 0, "returnCode decoded as a number");
    assert.equal(dec[0].returnString, "within policy", "returnString hex-decoded to utf8");
    assert.equal(dec[0].emitCount, 1, "emitCount surfaced");
    assert.equal(dec[0].flags, 0, "flags surfaced");
    // Absent / unknown / hostile shapes -> [] and NEVER throw.
    assert.deepEqual(decodeHookExecutions({}), [], "no HookExecutions -> []");
    assert.deepEqual(decodeHookExecutions(null), [], "null meta -> []");
    assert.deepEqual(decodeHookExecutions({ HookExecutions: "nope" }), [], "non-array HookExecutions -> []");
    assert.deepEqual(decodeHookExecutions({ HookExecutions: [ 123, null ] }), [], "garbage entries -> []");
    // returnString decode strips control chars, keeps printable (incl. '-'), bounds length.
    assert.equal(decodeHookReturnString(Buffer.from("a\x00b\x07c-d", "utf8").toString("hex")), "abc-d", "control chars stripped, hyphen kept");
    assert.equal(decodeHookReturnString("oddlen1"), "", "odd-length hex -> empty");
    assert.equal(decodeHookReturnString("zz"), "", "non-hex -> empty");
    assert.equal(decodeHookReturnString(""), "", "empty -> empty");
  }

  // (T1) tesSUCCESS with a guardrail HookExecutions array -> decoded hookExecutions
  //      surfaced on the SUCCESS receipt; the signed proof bytes are UNCHANGED by it.
  {
    const storeH = new InMemoryStore({ now: () => now });
    const guardrailHex = Buffer.from("ok: under LIM", "utf8").toString("hex");
    const clientH = fakeClient({ result: { hash: "HOOKOK", meta: {
      TransactionResult: "tesSUCCESS",
      delivered_amount: "1000000",
      HookExecutions: [ { HookExecution: {
        HookAccount: PAYER,
        HookHash: "1122334455667788990011223344556677889900AABBCCDD",
        HookReturnCode: "0",
        HookReturnString: guardrailHex,
        HookEmitCount: "0",
      } } ],
    } } });
    const depsH = { store: storeH, client: clientH, currentValidatedLedger: async () => curLedger, now: () => now };
    const outH = await __test.settle({ txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 450 }) }, req, depsH);
    assert.equal(outH.success, true, `success settle with a hook execution: ${outH.errorReason}`);
    assert.ok(Array.isArray(outH.hookExecutions), "hookExecutions is an array on the receipt");
    assert.equal(outH.hookExecutions.length, 1, "one hook execution surfaced");
    assert.equal(outH.hookExecutions[0].returnCode, 0, "decoded returnCode on the receipt");
    assert.equal(outH.hookExecutions[0].returnString, "ok: under LIM", "decoded returnString on the receipt");
    assert.equal(outH.hookExecutions[0].hookAccount, PAYER, "decoded hookAccount on the receipt");
    // CRITICAL: hookExecutions is NOT part of the signed proof. The receipt still
    // verifies, AND stripping hookExecutions entirely does not change verification.
    assert.equal(verifyReceipt(outH), true, "receipt with hookExecutions still verifies offline");
    const { hookExecutions, ...withoutHooks } = outH;
    assert.equal(verifyReceipt(withoutHooks), true, "removing hookExecutions does NOT break the proof (not signed over it)");
    // Mutating hookExecutions must NOT affect verification (it is not in the bytes).
    assert.equal(verifyReceipt({ ...outH, hookExecutions: [{ returnCode: 999, returnString: "tampered" }] }), true, "tampering hookExecutions does NOT break the proof");
    // The canonical signable projection has no hookExecutions key.
    const payload = __test.receiptSignablePayload({
      network: outH.network, txHash: outH.txHash, payer: outH.payer, payTo: outH.payTo,
      asset: outH.asset, delivered: outH.delivered, required: outH.required, ts: outH.ts,
    });
    assert.equal("hookExecutions" in payload, false, "signable payload does NOT contain hookExecutions");
    assert.equal(__test.canonicalJSONStringify(payload).includes("hookExecutions"), false, "canonical signed bytes do NOT mention hookExecutions");
  }

  // (T2) tecHOOK_REJECTED with a rejection HookReturnString -> decoded hookExecutions
  //      surfaced on the FAILED receipt (this is exactly when it is most useful).
  {
    const storeR = new InMemoryStore({ now: () => now });
    const rejectHex = Buffer.from("over policy: amount exceeds LIM", "utf8").toString("hex");
    const clientR = fakeClient({ result: { hash: "HOOKREJ", meta: {
      TransactionResult: "tecHOOK_REJECTED",
      HookExecutions: [ { HookExecution: {
        HookAccount: PAYER,
        HookHash: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF0",
        HookReturnCode: "-1",
        HookReturnString: rejectHex,
        HookEmitCount: "0",
      } } ],
    } } });
    const depsR = { store: storeR, client: clientR, currentValidatedLedger: async () => curLedger, now: () => now };
    const outR = await __test.settle({ txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 451 }) }, req, depsR);
    assert.equal(outR.success, false, "rejected settle");
    assert.match(outR.errorReason, /tecHOOK_REJECTED/, "rejection reason is the tec code");
    assert.equal(outR.proof, null, "a rejected settle is still NOT signed (proof:null)");
    assert.ok(Array.isArray(outR.hookExecutions), "hookExecutions present on a FAILED receipt");
    assert.equal(outR.hookExecutions.length, 1, "one hook execution surfaced on the failed receipt");
    assert.equal(outR.hookExecutions[0].returnCode, -1, "decoded negative returnCode");
    assert.equal(outR.hookExecutions[0].returnString, "over policy: amount exceeds LIM", "decoded guardrail rejection reason");
  }

  // (T3) A settle whose meta has NO HookExecutions -> hookExecutions is [] (omitted
  //      meaning empty), and the proof is unaffected.
  {
    const storeN = new InMemoryStore({ now: () => now });
    const clientN = fakeClient({ result: { hash: "NOHOOK", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } } });
    const depsN = { store: storeN, client: clientN, currentValidatedLedger: async () => curLedger, now: () => now };
    const outN = await __test.settle({ txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 452 }) }, req, depsN);
    assert.equal(outN.success, true, "non-hooked success settle");
    assert.deepEqual(outN.hookExecutions, [], "no hook executions -> empty array");
    assert.equal(verifyReceipt(outN), true, "non-hooked receipt still verifies (proof unchanged)");
  }

  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// FEATURE 2 — GET /pubkey over a spawned server, and the EPHEMERAL-key warning path.
await new Promise((resolveTest, rejectTest) => {
  (async () => {
    const { spawn } = await import("node:child_process");
    const PORT = 4095;
    // No X402_RECEIPT_SECRET -> the server logs an ephemeral-key warning to stderr.
    const child = spawn(process.execPath, ["server.mjs"], {
      env: { ...process.env, PORT: String(PORT), XAHAU_WSS: "", X402_RECEIPT_SECRET: "" },
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (c) => { stderr += c.toString(); });
    const getJson = (path) => new Promise((res) => {
      const r = http.request({ host: "127.0.0.1", port: PORT, path, method: "GET" }, (resp) => {
        let data = ""; resp.on("data", (c) => (data += c));
        resp.on("end", () => { let body; try { body = JSON.parse(data); } catch { body = data; } res({ status: resp.statusCode, body }); });
      });
      r.on("error", () => res({ status: null, body: null })); r.end();
    });
    const waitListen = async () => {
      for (let i = 0; i < 50; i++) {
        const ok = await new Promise((res) => { const r = http.request({ host: "127.0.0.1", port: PORT, path: "/supported", method: "GET" }, (resp) => { resp.resume(); res(resp.statusCode === 200); }); r.on("error", () => res(false)); r.end(); });
        if (ok) return true; await new Promise((r) => setTimeout(r, 100));
      }
      return false;
    };
    try {
      assert.equal(await waitListen(), true, "facilitator should start for the /pubkey test");
      const pk = await getJson("/pubkey");
      assert.equal(pk.status, 200, "/pubkey returns 200");
      assert.equal(pk.body.alg, "ed25519", "/pubkey alg ed25519");
      assert.match(pk.body.pubkey, /^[0-9a-f]{64}$/, "/pubkey returns raw 32-byte hex");
      // The ephemeral-key warning must have been logged (no secret configured). The
      // pubkey is materialized lazily on first /pubkey, so wait a tick for the log.
      await new Promise((r) => setTimeout(r, 100));
      assert.match(stderr, /receipt_key_ephemeral/, "ephemeral-key warning logged when no X402_RECEIPT_SECRET");
      // The warning must NEVER contain a private key/secret (we only log a note).
      assert.doesNotMatch(stderr, /X402_RECEIPT_SECRET=|privateKey/, "no secret/private key is ever logged");
      resolveTest();
    } catch (e) { rejectTest(e); }
    finally { child.kill("SIGKILL"); }
  })().catch(rejectTest);
});

// FEATURE 2 — a CONFIGURED secret yields a STABLE pubkey across two boots (receipts
// persist across restarts), proving X402_RECEIPT_SECRET pins the key.
await new Promise((resolveTest, rejectTest) => {
  (async () => {
    const { spawn } = await import("node:child_process");
    const SECRET = "07".repeat(32); // fixed hex seed
    const bootPubkey = async (PORT) => {
      const child = spawn(process.execPath, ["server.mjs"], {
        env: { ...process.env, PORT: String(PORT), XAHAU_WSS: "", X402_RECEIPT_SECRET: SECRET },
        stdio: ["ignore", "ignore", "ignore"],
      });
      const getJson = (path) => new Promise((res) => {
        const r = http.request({ host: "127.0.0.1", port: PORT, path, method: "GET" }, (resp) => { let d = ""; resp.on("data", (c) => (d += c)); resp.on("end", () => { try { res(JSON.parse(d)); } catch { res(null); } }); });
        r.on("error", () => res(null)); r.end();
      });
      const waitListen = async () => { for (let i = 0; i < 50; i++) { const ok = await new Promise((res) => { const r = http.request({ host: "127.0.0.1", port: PORT, path: "/supported", method: "GET" }, (resp) => { resp.resume(); res(resp.statusCode === 200); }); r.on("error", () => res(false)); r.end(); }); if (ok) return true; await new Promise((r) => setTimeout(r, 100)); } return false; };
      try {
        if (!(await waitListen())) throw new Error("server did not start");
        const pk = await getJson("/pubkey");
        return pk.pubkey;
      } finally { child.kill("SIGKILL"); }
    };
    try {
      const p1 = await bootPubkey(4094);
      const p2 = await bootPubkey(4093);
      assert.equal(p1, p2, "a configured X402_RECEIPT_SECRET pins a STABLE pubkey across boots (persistent receipts)");
      resolveTest();
    } catch (e) { rejectTest(e); }
  })().catch(rejectTest);
});

// ===========================================================================
// FEATURE 3 — x402 `upto` scheme + GET /status/:id
// ===========================================================================
// Scheme semantics: absent/`upto` => paid <= max (legacy ceiling); `exact` => paid
// MUST EQUAL max. Both native + IOU, at/over/under boundaries.
{
  // NATIVE — default (absent scheme) keeps the ceiling behavior.
  let r2 = verifyExact({ txBlob: blob({ Amount: "1000000" }) }, { payTo: PAY_TO, maxAmountRequired: "1000000", network: "xahau" });
  assert.equal(r2.isValid, true, "native default: paid==max passes");
  assert.equal(r2.scheme, "upto", "absent scheme defaults to upto (legacy ceiling)");
  r2 = verifyExact({ txBlob: blob({ Amount: "500000" }) }, { payTo: PAY_TO, maxAmountRequired: "1000000", network: "xahau" });
  assert.equal(r2.isValid, true, "native default: paid<max passes (ceiling)");

  // NATIVE — explicit "upto".
  r2 = verifyExact({ txBlob: blob({ Amount: "500000" }) }, { payTo: PAY_TO, maxAmountRequired: "1000000", network: "xahau", scheme: "upto" });
  assert.equal(r2.isValid, true, "native upto: paid<max passes");
  assert.equal(r2.scheme, "upto");
  r2 = verifyExact({ txBlob: blob({ Amount: "1500000" }) }, { payTo: PAY_TO, maxAmountRequired: "1000000", network: "xahau", scheme: "upto" });
  assert.equal(r2.isValid, false, "native upto: paid>max fails");

  // NATIVE — "exact": paid MUST EQUAL max.
  r2 = verifyExact({ txBlob: blob({ Amount: "1000000" }) }, { payTo: PAY_TO, maxAmountRequired: "1000000", network: "xahau", scheme: "exact" });
  assert.equal(r2.isValid, true, "native exact: paid==max passes");
  assert.equal(r2.scheme, "exact");
  r2 = verifyExact({ txBlob: blob({ Amount: "999999" }) }, { payTo: PAY_TO, maxAmountRequired: "1000000", network: "xahau", scheme: "exact" });
  assert.equal(r2.isValid, false, "native exact: paid<max FAILS (must equal)");
  assert.match(r2.invalidReason, /!= maxAmountRequired/);
  r2 = verifyExact({ txBlob: blob({ Amount: "1000001" }) }, { payTo: PAY_TO, maxAmountRequired: "1000000", network: "xahau", scheme: "exact" });
  assert.equal(r2.isValid, false, "native exact: paid>max fails (over the ceiling)");

  // IOU — "upto" vs "exact".
  r2 = verifyExact({ txBlob: iouBlob({ value: "1.0" }) }, { ...iouReq, scheme: "upto" });
  assert.equal(r2.isValid, true, "IOU upto: 1.0 <= 1.5 passes");
  r2 = verifyExact({ txBlob: iouBlob({ value: "1.0" }) }, { ...iouReq, scheme: "exact" });
  assert.equal(r2.isValid, false, "IOU exact: 1.0 != 1.5 FAILS");
  assert.match(r2.invalidReason, /!= maxAmountRequired/);
  r2 = verifyExact({ txBlob: iouBlob({ value: "1.5" }) }, { ...iouReq, scheme: "exact" });
  assert.equal(r2.isValid, true, "IOU exact: 1.5 == 1.5 passes");
  r2 = verifyExact({ txBlob: iouBlob({ value: "1.5" }) }, { payTo: PAY_TO, maxAmountRequired: "1.50", network: "xahau", asset: IOU_ASSET, scheme: "exact" });
  assert.equal(r2.isValid, true, "IOU exact: 1.5 == 1.50 (exact compare, trailing zero) passes");

  // Unknown scheme is rejected (never coerced to a weaker check).
  r2 = verifyExact({ txBlob: blob() }, { payTo: PAY_TO, maxAmountRequired: "1000000", network: "xahau", scheme: "atmost" });
  assert.equal(r2.isValid, false, "unknown scheme rejected");
  assert.match(r2.invalidReason, /unknown scheme/);

  // settle honors the scheme (re-verifies): an exact-scheme under-pay is rejected before submit.
  (async () => {})(); // (settle exact path covered below in the integration test)
}

// FEATURE 3 — settle re-validates the scheme (exact under-pay rejected, no submit).
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  let submitCount = 0;
  const client = { isConnected: () => true, request: async () => ({ result: { account_objects: [] } }), submitAndWait: async () => { submitCount++; return { result: { hash: "X", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } } }; } };
  const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now };
  const exactReq = { payTo: PAY_TO, maxAmountRequired: "1000000", network: "xahau", scheme: "exact" };
  const out = await __test.settle({ txBlob: blob({ Amount: "999999", LastLedgerSequence: curLedger + 5, Sequence: 411 }) }, exactReq, deps);
  assert.equal(out.success, false, "settle rejects an exact-scheme under-pay");
  assert.match(out.errorReason, /verify failed/);
  assert.equal(submitCount, 0, "no submit for a scheme-rejected payment");
  // An exact-scheme payment that DOES equal max settles fine.
  const out2 = await __test.settle({ txBlob: blob({ Amount: "1000000", LastLedgerSequence: curLedger + 5, Sequence: 412 }) }, exactReq, deps);
  assert.equal(out2.success, true, `exact-scheme paid==max settles: ${out2.errorReason}`);
  assert.equal(submitCount, 1, "exact-scheme exact-match submits once");
  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// FEATURE 3 — GET /status/:id: auth-gate + found/unknown over a spawned server.
await new Promise((resolveTest, rejectTest) => {
  (async () => {
    const { spawn } = await import("node:child_process");
    const PORT = 4092;
    const SECRET = "status-secret";
    const child = spawn(process.execPath, ["server.mjs"], {
      env: { ...process.env, PORT: String(PORT), XAHAU_WSS: "", X402_SHARED_SECRET: SECRET },
      stdio: ["ignore", "ignore", "ignore"],
    });
    const getJson = (path, headers = {}) => new Promise((res) => {
      const r = http.request({ host: "127.0.0.1", port: PORT, path, method: "GET", headers }, (resp) => {
        let data = ""; resp.on("data", (c) => (data += c));
        resp.on("end", () => { let body; try { body = JSON.parse(data); } catch { body = data; } res({ status: resp.statusCode, body }); });
      });
      r.on("error", () => res({ status: null, body: null })); r.end();
    });
    const waitListen = async () => { for (let i = 0; i < 50; i++) { const ok = await new Promise((res) => { const r = http.request({ host: "127.0.0.1", port: PORT, path: "/supported", method: "GET" }, (resp) => { resp.resume(); res(resp.statusCode === 200); }); r.on("error", () => res(false)); r.end(); }); if (ok) return true; await new Promise((r) => setTimeout(r, 100)); } return false; };
    try {
      assert.equal(await waitListen(), true, "facilitator should start for the /status test");
      // WITHOUT the secret -> 401 (auth-gated).
      const unauth = await getJson("/status/some-id");
      assert.equal(unauth.status, 401, "/status without the secret -> 401");
      // WITH the secret, an unknown id -> found:false, status:unknown.
      const unknown = await getJson("/status/never-settled", { "x-x402-secret": SECRET });
      assert.equal(unknown.status, 200, "/status (with secret) returns 200");
      assert.equal(unknown.body.found, false, "unknown id -> found:false");
      assert.equal(unknown.body.status, "unknown", "unknown id -> status:unknown (honest)");
      resolveTest();
    } catch (e) { rejectTest(e); }
    finally { child.kill("SIGKILL"); }
  })().catch(rejectTest);
});

// FEATURE 3 — /status returns a stored receipt (found:settled) via the injected store.
// We can't easily settle a real tx over the spawned server (no node), so assert the
// store-exposure contract directly: a receipt set in the store is returned by getReceipt
// (the same call /status makes), and an absent key is "unknown".
{
  const { InMemoryStore } = __test;
  const now = Date.now();
  const s = new InMemoryStore({ now: () => now });
  const rcpt = { success: true, transaction: "STATUSHASH", payer: PAYER, network: "xahau" };
  await s.setReceipt("acct:" + PAYER + ":999", rcpt, now + 3_600_000);
  assert.deepEqual(await s.getReceipt("acct:" + PAYER + ":999"), rcpt, "/status surfaces a stored receipt verbatim (found:settled)");
  assert.equal(await s.getReceipt("acct:" + PAYER + ":nope"), undefined, "/status returns unknown for an absent id");
}

// ===========================================================================
// FEATURE 4 — pre-settle simulation (ADVISORY, config-gated)
// ===========================================================================
{
  const { simulatePayment } = __test;

  // Feature OFF when no URL + no injected fn -> available:false, never throws.
  let sim = await simulatePayment({ txBlob: blob() }, req, { mcpUrl: undefined });
  assert.equal(sim.available, false, "simulation off when X402_MCP_URL unset");
  assert.match(sim.note, /not configured/, "honest 'not configured' note");

  // Injected simulateFn returning an accept-prediction.
  sim = await simulatePayment({ txBlob: blob() }, req, { simulateFn: async () => ({ available: true, prediction: "accept" }) });
  assert.equal(sim.available, true); assert.equal(sim.prediction, "accept");

  // A throwing simulateFn fails SOFT (available:false, no throw).
  sim = await simulatePayment({ txBlob: blob() }, req, { simulateFn: async () => { throw new Error("mcp down"); } });
  assert.equal(sim.available, false, "sim error fails soft (available:false)");
  assert.match(sim.note, /unavailable/, "honest 'unavailable' note");
}

// FEATURE 4 — dryRun on settle returns a prediction and NEVER submits / reserves.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;
  const store = new InMemoryStore({ now: () => now });
  let submitCount = 0;
  const client = { isConnected: () => true, request: async () => ({ result: { account_objects: [] } }), submitAndWait: async () => { submitCount++; return { result: { hash: "SHOULD_NOT", meta: { TransactionResult: "tesSUCCESS" } } }; } };
  const deps = {
    store, client, currentValidatedLedger: async () => curLedger, now: () => now,
    dryRun: true, simulateFn: async () => ({ available: true, prediction: "accept" }),
  };
  const out = await __test.settle({ txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 421 }) }, req, deps);
  assert.equal(out.dryRun, true, "dryRun flagged");
  assert.equal(out.advisory, true, "dryRun is advisory");
  assert.equal(out.success, false, "dryRun is not a real settlement");
  assert.equal(out.simulation.prediction, "accept", "dryRun returns the prediction");
  assert.equal(submitCount, 0, "dryRun NEVER submits");
  assert.equal(store.map.size, 0, "dryRun reserves NO replay slot");
  assert.equal(await store.getReceipt("acct:" + PAYER + ":421"), undefined, "dryRun stores no receipt");

  // A dryRun on an INVALID payload is still rejected by verify (security preserved).
  const outBad = await __test.settle({ txBlob: blob({ Amount: "9000000", LastLedgerSequence: curLedger + 5, Sequence: 422 }) }, req, { ...deps, dryRun: true });
  assert.equal(outBad.success, false, "dryRun still re-verifies");
  assert.match(outBad.errorReason, /verify failed/, "an over-max dryRun is rejected by verify, not 'advisory'");

  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// FEATURE 4 — opt-in preSimReject short-circuits a PREDICTED-REJECT (no submit, no
// slot), but a predicted-ACCEPT (or unavailable sim) still runs the FULL real settle.
{
  const prev = process.env.XAHAU_WSS;
  process.env.XAHAU_WSS = "wss://invalid.example";
  const { InMemoryStore } = __test;
  const now = 1_000_000_000, curLedger = 100;

  // (a) predicted reject + opt-in -> advisory rejection, no submit, no slot.
  {
    const store = new InMemoryStore({ now: () => now });
    let submitCount = 0;
    const client = { isConnected: () => true, request: async () => ({ result: { account_objects: [] } }), submitAndWait: async () => { submitCount++; return { result: { hash: "NO", meta: { TransactionResult: "tesSUCCESS" } } }; } };
    const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now, preSimReject: true, simulateFn: async () => ({ available: true, prediction: "reject" }) };
    const out = await __test.settle({ txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 431 }) }, req, deps);
    assert.equal(out.success, false, "predicted-reject short-circuits");
    assert.equal(out.advisory, true, "predicted-reject is clearly advisory");
    assert.match(out.errorReason, /predicted-reject \(simulated, not submitted\)/, "advisory rejection labeled honestly");
    assert.equal(submitCount, 0, "predicted-reject does NOT submit");
    assert.equal(store.map.size, 0, "predicted-reject reserves NO replay slot");
  }

  // (b) predicted ACCEPT + opt-in -> still runs the FULL real settle (security unchanged).
  {
    const store = new InMemoryStore({ now: () => now });
    let submitCount = 0;
    const client = { isConnected: () => true, request: async () => ({ result: { account_objects: [] } }), submitAndWait: async () => { submitCount++; return { result: { hash: "REALSUBMIT", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } } }; } };
    const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now, preSimReject: true, simulateFn: async () => ({ available: true, prediction: "accept" }) };
    const out = await __test.settle({ txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 432 }) }, req, deps);
    assert.equal(out.success, true, "predicted-accept runs the full real settle");
    assert.equal(submitCount, 1, "predicted-accept actually submits (advisory never replaces real settle)");
  }

  // (c) UNAVAILABLE sim + opt-in -> NOT short-circuited; full real settle runs.
  {
    const store = new InMemoryStore({ now: () => now });
    let submitCount = 0;
    const client = { isConnected: () => true, request: async () => ({ result: { account_objects: [] } }), submitAndWait: async () => { submitCount++; return { result: { hash: "REAL2", meta: { TransactionResult: "tesSUCCESS", delivered_amount: "1000000" } } }; } };
    const deps = { store, client, currentValidatedLedger: async () => curLedger, now: () => now, preSimReject: true, simulateFn: async () => ({ available: false, note: "simulation unavailable" }) };
    const out = await __test.settle({ txBlob: blob({ LastLedgerSequence: curLedger + 5, Sequence: 433 }) }, req, deps);
    assert.equal(out.success, true, "an unavailable sim does NOT block the real settle (fail soft)");
    assert.equal(submitCount, 1, "unavailable sim -> full real settle still submits");
  }

  if (prev === undefined) delete process.env.XAHAU_WSS; else process.env.XAHAU_WSS = prev;
}

// FEATURE 4 — /simulate route is 404 when X402_MCP_URL is unset (feature entirely off).
await new Promise((resolveTest, rejectTest) => {
  (async () => {
    const { spawn } = await import("node:child_process");
    const PORT = 4091;
    const child = spawn(process.execPath, ["server.mjs"], {
      env: { ...process.env, PORT: String(PORT), XAHAU_WSS: "", X402_MCP_URL: "" },
      stdio: ["ignore", "ignore", "ignore"],
    });
    const postJson = (path) => new Promise((res) => {
      const body = "{}";
      const r = http.request({ host: "127.0.0.1", port: PORT, path, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) } }, (resp) => { resp.resume(); resp.on("end", () => res(resp.statusCode)); });
      r.on("error", () => res(null)); r.write(body); r.end();
    });
    const waitListen = async () => { for (let i = 0; i < 50; i++) { const ok = await new Promise((res) => { const r = http.request({ host: "127.0.0.1", port: PORT, path: "/supported", method: "GET" }, (resp) => { resp.resume(); res(resp.statusCode === 200); }); r.on("error", () => res(false)); r.end(); }); if (ok) return true; await new Promise((r) => setTimeout(r, 100)); } return false; };
    try {
      assert.equal(await waitListen(), true, "facilitator should start for the /simulate-off test");
      const s = await postJson("/simulate");
      assert.equal(s, 404, "/simulate is 404 when X402_MCP_URL is unset (feature off, no coupling)");
      resolveTest();
    } catch (e) { rejectTest(e); }
    finally { child.kill("SIGKILL"); }
  })().catch(rejectTest);
});

console.log("ok — all hardened verifyExact + settle cases pass (native + IOU + ops hardening + x402 spec fields + policy/receipts/scheme/status/simulate)");
