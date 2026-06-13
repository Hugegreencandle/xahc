#!/usr/bin/env node
/**
 * exact-xahau — a reference x402 facilitator for Xahau.
 *
 * Implements the x402 facilitator surface for the proposed `exact-xahau` scheme
 * (see ../docs/X402-XAHAU.md):
 *   GET  /supported  -> advertise {scheme:"exact", network:"xahau"}
 *   POST /verify     -> offline checks on a signed Xahau Payment vs the requirements
 *   POST /settle     -> submit the signed tx to Xahau (needs XAHAU_WSS)
 *
 * Key design point: the facilitator does NOT enforce the agent's spending policy
 * itself — the payer's on-chain xahc **guardrail Hook** does, at settlement. A
 * payment that breaks policy `tecHOOK_REJECTED`s and no value moves, so the
 * facilitator cannot be tricked into settling an over-policy payment. /verify is
 * a fast offline pre-flight (field + signature shape); the Hook is the authority.
 */
import http from "node:http";
import { decode } from "xrpl-binary-codec-prerelease";

const PORT = process.env.PORT || 4021;
export const NETWORK = "xahau";

function send(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(b) });
  res.end(b);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let d = "";
    req.on("data", (c) => (d += c));
    req.on("end", () => { try { resolve(d ? JSON.parse(d) : {}); } catch (e) { reject(e); } });
    req.on("error", reject);
  });
}

/** native XAH amount -> bigint drops; issued (object) -> null */
function nativeDrops(amount) {
  return typeof amount === "string" ? BigInt(amount) : null;
}

/**
 * Offline verification of an `exact-xahau` payload.
 * payload: { txBlob }  — a signed Xahau Payment
 * req:     { payTo, maxAmountRequired, network, maxTimeoutSeconds }
 */
export function verifyExact(payload, req) {
  if (!payload || typeof payload.txBlob !== "string")
    return { isValid: false, invalidReason: "missing txBlob" };
  let tx;
  try { tx = decode(payload.txBlob); } catch { return { isValid: false, invalidReason: "undecodable txBlob" }; }

  if (tx.TransactionType !== "Payment")
    return { isValid: false, invalidReason: "not a Payment" };
  if (req?.payTo && tx.Destination !== req.payTo)
    return { isValid: false, invalidReason: "Destination != payTo" };

  const paid = nativeDrops(tx.Amount);
  if (paid === null)
    return { isValid: false, invalidReason: "issued-amount verify not implemented in this shim (native XAH only)" };
  if (req?.maxAmountRequired && paid > BigInt(req.maxAmountRequired))
    return { isValid: false, invalidReason: "Amount > maxAmountRequired" };

  if (tx.LastLedgerSequence == null)
    return { isValid: false, invalidReason: "missing LastLedgerSequence (no expiry window)" };
  if (!tx.TxnSignature && !(Array.isArray(tx.Signers) && tx.Signers.length))
    return { isValid: false, invalidReason: "unsigned (no TxnSignature/Signers)" };

  return { isValid: true, invalidReason: null, payer: tx.Account, amount: paid.toString() };
}

/** Submit the signed tx to Xahau. The on-chain guardrail Hook is the authority. */
async function settle(payload) {
  const wss = process.env.XAHAU_WSS;
  if (!wss) return { success: false, network: NETWORK, errorReason: "set XAHAU_WSS to settle" };
  if (!payload?.txBlob) return { success: false, network: NETWORK, errorReason: "missing txBlob" };
  let Client;
  try { ({ Client } = await import("xrpl")); }
  catch { return { success: false, network: NETWORK, errorReason: "install `xrpl` to settle" }; }
  const c = new Client(wss);
  await c.connect();
  try {
    const r = await c.submitAndWait(payload.txBlob);
    const code = r.result.meta?.TransactionResult;
    // tecHOOK_REJECTED here == the payer's guardrail Hook blocked an over-policy payment.
    return {
      success: code === "tesSUCCESS",
      transaction: r.result.hash,
      network: NETWORK,
      errorReason: code === "tesSUCCESS" ? null : code,
    };
  } finally {
    await c.disconnect();
  }
}

function serve() {
  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/supported")
        return send(res, 200, { kinds: [{ scheme: "exact", network: NETWORK }] });
      if (req.method === "POST" && req.url === "/verify") {
        const b = await readBody(req);
        return send(res, 200, verifyExact(b.paymentPayload, b.paymentRequirements));
      }
      if (req.method === "POST" && req.url === "/settle") {
        const b = await readBody(req);
        return send(res, 200, await settle(b.paymentPayload));
      }
      send(res, 404, { error: "not found" });
    } catch (e) {
      send(res, 500, { error: String(e?.message || e) });
    }
  });
  server.listen(PORT, () => console.error(`exact-xahau facilitator on :${PORT} (network=${NETWORK})`));
}

// run only when invoked directly (not when imported by test.mjs)
if (import.meta.url === `file://${process.argv[1]}`) serve();
