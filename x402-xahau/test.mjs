// Self-test for verifyExact — builds Payment tx blobs with the Xahau codec and
// asserts the facilitator's offline verification. Run: npm test (after npm i).
import assert from "node:assert";
import { encode } from "xrpl-binary-codec-prerelease";
import { verifyExact } from "./server.mjs";

const PAY_TO = "rJfeEF9Fh3gs7syURNy6daLJz68kyA65n1";
const PAYER = "rGZQKj1U9fy21xRjrAtYCniUarwxFRrzmi";

function blob(overrides = {}) {
  const tx = {
    TransactionType: "Payment",
    Account: PAYER,
    Destination: PAY_TO,
    Amount: "1000000", // 1 XAH in drops
    Fee: "10",
    Sequence: 1,
    LastLedgerSequence: 1000005,
    SigningPubKey: "",
    TxnSignature: "3045022100AB", // dummy presence; codec doesn't verify the curve
    ...overrides,
  };
  return encode(tx);
}

const req = { payTo: PAY_TO, maxAmountRequired: "1000000", network: "xahau" };

// 1. valid exact payment
let r = verifyExact({ txBlob: blob() }, req);
assert.equal(r.isValid, true, `valid payment should pass: ${r.invalidReason}`);
assert.equal(r.payer, PAYER);
assert.equal(r.amount, "1000000");

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
r = verifyExact({ txBlob: blob({ TxnSignature: undefined }) }, req);
assert.equal(r.isValid, false);
assert.match(r.invalidReason, /unsigned/);

// 6. garbage blob
r = verifyExact({ txBlob: "ZZZZ" }, req);
assert.equal(r.isValid, false);

console.log("ok — all verifyExact cases pass");
