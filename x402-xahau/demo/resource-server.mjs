#!/usr/bin/env node
/**
 * resource-server.mjs — a tiny x402 RESOURCE SERVER for the agent-pays-on-Xahau demo.
 *
 * It sells two paid resources and demonstrates the canonical x402 flow + the real
 * resource-server <-> FACILITATOR separation from the x402 spec:
 *
 *   GET /premium       -> price  1 XAH  (1_000_000 drops)   [UNDER the 5 XAH guardrail cap]
 *   GET /premium-plus  -> price 10 XAH  (10_000_000 drops)  [OVER  the 5 XAH guardrail cap]
 *
 * Flow per resource:
 *   1. No (or invalid) X-PAYMENT header -> HTTP 402 + the x402 `paymentRequirements`
 *      JSON: { scheme:"exact", network:"xahau", payTo:<MERCHANT>, maxAmountRequired:<drops>, ... }
 *      — the exact shape the facilitator's verifyExact expects (native XAH: no `asset`).
 *   2. Retry carrying X-PAYMENT: <base64 of {txBlob}> -> the resource server calls the
 *      FACILITATOR over HTTP: POST /verify (offline) then POST /settle (with the shared
 *      secret if configured). On settle success -> 200 + premium content. On failure ->
 *      402 + the reason (e.g. tecHOOK_REJECTED when the guardrail Hook blocks an
 *      over-budget payment at L1).
 *
 * The resource server holds NO seeds and signs NOTHING — it only relays a client-
 * supplied signed tx blob to the facilitator. The on-chain guardrail Hook on the
 * payer is the L1 spending authority; the facilitator surfaces its real verdict.
 *
 * Env:  PORT (default 4022), FACILITATOR_URL (default http://127.0.0.1:4021),
 *       MERCHANT_ADDRESS (required — the testnet payTo / allowlisted DST),
 *       X402_SHARED_SECRET (optional — forwarded to /settle as x-x402-secret).
 */
import http from "node:http";

const PORT = Number(process.env.PORT) || 4022;
const FACILITATOR_URL = (process.env.FACILITATOR_URL || "http://127.0.0.1:4021").replace(/\/$/, "");
const MERCHANT = process.env.MERCHANT_ADDRESS || "";
const SHARED_SECRET = process.env.X402_SHARED_SECRET || "";

if (!MERCHANT) { console.error("[resource] MERCHANT_ADDRESS is required"); process.exit(1); }

// Resource catalog: path -> { priceDrops, content }.
const CATALOG = {
  "/premium": {
    priceDrops: "1000000", // 1 XAH  (under the 5 XAH guardrail cap)
    label: "premium",
    content: { resource: "premium", data: "The agent autonomously paid 1 XAH and unlocked the premium feed.", secretInsight: "x402 + Xahau Hooks = budget-enforced agentic payments." },
  },
  "/premium-plus": {
    priceDrops: "10000000", // 10 XAH (OVER the 5 XAH guardrail cap -> Hook rejects)
    label: "premium-plus",
    content: { resource: "premium-plus", data: "If you can read this, the guardrail FAILED — the agent should never afford this." },
  },
};

// Build the x402 paymentRequirements for a resource (native XAH: no `asset`).
function paymentRequirements(resourcePath, priceDrops) {
  return {
    x402Version: 2,
    accepts: [
      {
        scheme: "exact",
        network: "xahau",
        payTo: MERCHANT,
        maxAmountRequired: priceDrops, // drops string (native XAH)
        resource: resourcePath,
        description: `Access to ${resourcePath}`,
        mimeType: "application/json",
        maxTimeoutSeconds: 120,
      },
    ],
  };
}

async function facilitatorPost(path, body) {
  const headers = { "content-type": "application/json" };
  if (SHARED_SECRET && path === "/settle") headers["x-x402-secret"] = SHARED_SECRET;
  const r = await fetch(`${FACILITATOR_URL}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
  const json = await r.json().catch(() => ({}));
  return { status: r.status, json };
}

function send(res, code, obj, extraHeaders = {}) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(b), ...extraHeaders });
  res.end(b);
}

// Decode an X-PAYMENT header: base64 of JSON { txBlob }.
function parsePaymentHeader(req) {
  const h = req.headers["x-payment"];
  if (typeof h !== "string" || h.length === 0) return null;
  try {
    const json = JSON.parse(Buffer.from(h, "base64").toString("utf8"));
    if (json && typeof json.txBlob === "string" && json.txBlob.length) return json;
  } catch { /* fall through */ }
  return null;
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health")
      return send(res, 200, { status: "ok", merchant: MERCHANT, facilitator: FACILITATOR_URL, resources: Object.keys(CATALOG) });

    const entry = req.method === "GET" ? CATALOG[req.url] : undefined;
    if (!entry) return send(res, 404, { error: "not found" });

    const reqs = paymentRequirements(req.url, entry.priceDrops);
    const accept = reqs.accepts[0];

    // No payment presented -> 402 challenge with paymentRequirements.
    const payment = parsePaymentHeader(req);
    if (!payment) {
      return send(res, 402, { error: "payment required", ...reqs }, { "x-accept-payment": "exact:xahau" });
    }

    // Payment presented -> verify (offline) then settle (on-ledger) via FACILITATOR.
    const payload = { txBlob: payment.txBlob };
    const requirements = {
      payTo: accept.payTo,
      maxAmountRequired: accept.maxAmountRequired,
      network: "xahau",
      maxTimeoutSeconds: accept.maxTimeoutSeconds,
    };

    const verify = await facilitatorPost("/verify", { paymentPayload: payload, paymentRequirements: requirements });
    if (verify.status !== 200 || !verify.json?.isValid) {
      return send(res, 402, { error: "payment verification failed", reason: verify.json?.invalidReason || `facilitator /verify HTTP ${verify.status}`, ...reqs });
    }

    const settle = await facilitatorPost("/settle", { paymentPayload: payload, paymentRequirements: requirements });
    if (settle.status !== 200 || !settle.json?.success) {
      // The on-chain guardrail Hook (or any settle failure) blocks access. Surface
      // the real reason + the on-ledger tx hash so the agent sees WHY it was denied.
      return send(res, 402, {
        error: "payment settlement failed",
        reason: settle.json?.errorReason || `facilitator /settle HTTP ${settle.status}`,
        transaction: settle.json?.transaction || null,
        guardrailHookPresent: settle.json?.guardrailHookPresent ?? null,
        explorer: settle.json?.transaction ? `https://explorer.xahau-test.net/tx/${settle.json.transaction}` : null,
        ...reqs,
      });
    }

    // Settled. Return the paid content + an x402 settlement receipt header.
    const receiptHeader = Buffer.from(JSON.stringify({ transaction: settle.json.transaction, network: "xahau", delivered: settle.json.delivered })).toString("base64");
    return send(res, 200, {
      ...entry.content,
      _payment: {
        settled: true,
        transaction: settle.json.transaction,
        delivered: settle.json.delivered,
        guardrailHookPresent: settle.json.guardrailHookPresent,
        explorer: `https://explorer.xahau-test.net/tx/${settle.json.transaction}`,
      },
    }, { "x-payment-response": receiptHeader });
  } catch (e) {
    if (!res.headersSent) send(res, 500, { error: "internal error", detail: String(e?.message || e) });
  }
});

server.listen(PORT, () => {
  console.error(`[resource] listening on :${PORT}  merchant=${MERCHANT}  facilitator=${FACILITATOR_URL}`);
  console.error(`[resource]   GET /premium       -> 1 XAH  (under guardrail cap)`);
  console.error(`[resource]   GET /premium-plus  -> 10 XAH (over guardrail cap)`);
});
process.on("SIGTERM", () => server.close(() => process.exit(0)));
process.on("SIGINT", () => server.close(() => process.exit(0)));
