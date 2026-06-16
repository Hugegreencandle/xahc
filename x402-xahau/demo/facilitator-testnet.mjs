#!/usr/bin/env node
/**
 * facilitator-testnet.mjs — run the REAL x402-xahau facilitator surface against the
 * Xahau TESTNET (NetworkID 21338).
 *
 * WHY THIS THIN LAUNCHER EXISTS (and is not just `node server.mjs`):
 *   The production `server.mjs` is network-agnostic, but its internal xrpl client
 *   (`getClient()`) builds `new Client(wss)` with xrpl@4's DEFAULT api_version (2).
 *   Xahau's rippled ONLY speaks WS api_version 1 — a default-v2 client gets
 *   `invalid_API_version` and every /settle would fail. The facilitator anticipates
 *   exactly this: `settle()` takes an injectable `_deps.client` (+ a ledger fetcher)
 *   — the SAME seam the committed testnet proof harness uses. This launcher therefore
 *   imports the UNCHANGED production `verifyExact` and `settle` from `server.mjs` and
 *   serves the identical `/supported`, `/verify`, `/settle`, `/health` HTTP surface,
 *   injecting ONLY an api_version-1 xrpl client + ledger fetcher. The
 *   security-critical verify/settle logic (signature crypto, replay binding,
 *   delivered_amount check, guardrail-hook reporting) is the production code, byte for
 *   byte. The only thing replaced is the WS transport version + the HTTP boilerplate.
 *
 * AUTH: if X402_SHARED_SECRET is set, /settle requires header `x-x402-secret` (same
 * contract as production server.mjs). /verify stays public (x402 semantics).
 *
 * Env:  XAHAU_WSS (default wss://xahau-test.net), XAHAU_NETWORK_ID=21338,
 *       X402_SHARED_SECRET (optional), PORT (default 4021).
 *
 * No secrets are read or written here — this process never holds a seed.
 */
import http from "node:http";
import crypto from "node:crypto";
import { createRequire } from "node:module";

const require_ = createRequire(import.meta.url);

const PORT = Number(process.env.PORT) || 4021;
const WSS = process.env.XAHAU_WSS || "wss://xahau-test.net";
const NETWORK_ID = Number(process.env.XAHAU_NETWORK_ID) || 21338;
const SHARED_SECRET = process.env.X402_SHARED_SECRET || "";

// Pin env BEFORE importing the facilitator so EXPECTED_NETWORK_ID resolves to 21338
// and settle()'s XAHAU_WSS guard passes.
process.env.XAHAU_WSS = WSS;
process.env.XAHAU_NETWORK_ID = String(NETWORK_ID);

const { Client } = require_("xahau");
const { verifyExact, EXPECTED_NETWORK_ID, __test } = await import("../server.mjs");
const settle = __test.settle; // production settle(), exposed for the _deps seam

if (EXPECTED_NETWORK_ID !== NETWORK_ID) {
  console.error(`[facilitator] EXPECTED_NETWORK_ID=${EXPECTED_NETWORK_ID} != ${NETWORK_ID}`);
  process.exit(1);
}

// --- single shared api_version-1 client (Xahau requires v1) -----------------
let _client = null;
async function getClient() {
  if (_client && _client.isConnected()) return _client;
  const c = new Client(WSS);
  c.apiVersion = 1;
  await c.connect();
  c.apiVersion = 1;
  _client = c;
  return c;
}
async function currentValidatedLedger(c) {
  const cl = c || (await getClient());
  const r = await cl.request({ command: "ledger", ledger_index: "validated" });
  const idx = r?.result?.ledger_index ?? r?.result?.ledger?.ledger_index;
  const n = Number(idx);
  return Number.isFinite(n) && n > 0 ? n : null;
}

// --- auth (mirror server.mjs authOk: timing-safe shared-secret) -------------
function authOk(req) {
  if (!SHARED_SECRET) return true; // reference mode: open
  const provided = req.headers["x-x402-secret"];
  if (typeof provided !== "string" || provided.length === 0) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(SHARED_SECRET);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => { size += c.length; if (size > 64 * 1024) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { const d = Buffer.concat(chunks).toString("utf8"); resolve(d ? JSON.parse(d) : {}); } catch { reject(new Error("invalid JSON")); } });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health")
      return send(res, 200, { status: "ok", network: "xahau", networkID: EXPECTED_NETWORK_ID, wss: WSS, transport: "api_version 1" });

    if (req.method === "GET" && req.url === "/supported")
      return send(res, 200, { kinds: [{ x402Version: 2, scheme: "exact", network: "xahau" }] });

    if (req.method === "POST" && req.url === "/verify") {
      const b = await readBody(req);
      // production verifyExact, unchanged
      return send(res, 200, verifyExact(b.paymentPayload, b.paymentRequirements));
    }

    if (req.method === "POST" && req.url === "/settle") {
      if (!authOk(req)) return send(res, 401, { error: "unauthorized" });
      const b = await readBody(req);
      const client = await getClient();
      // production settle(), with the api_version-1 client + ledger fetcher injected
      // through the documented _deps seam. EVERYTHING else (verify re-run, replay
      // reservation, submit, delivered_amount check) is production code.
      const out = await settle(b.paymentPayload, b.paymentRequirements, {
        client,
        currentValidatedLedger,
      });
      const status = out && out.retryable === true ? 503 : 200;
      return send(res, status, out);
    }

    send(res, 404, { error: "not found" });
  } catch (e) {
    const status = /too large|invalid JSON/.test(String(e?.message)) ? 400 : 500;
    if (!res.headersSent) send(res, status, { error: status === 400 ? "bad request" : "internal error" });
  }
});

server.listen(PORT, () => {
  console.error(`[facilitator] listening on :${PORT}  network=xahau networkID=${EXPECTED_NETWORK_ID}  wss=${WSS}  auth=${SHARED_SECRET ? "shared-secret" : "open(reference)"}`);
});

async function shutdown() {
  try { if (_client) await _client.disconnect(); } catch { /* ignore */ }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
