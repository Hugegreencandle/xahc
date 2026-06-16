#!/usr/bin/env node
/**
 * agent.mjs — an AUTONOMOUS "AI agent" client that pays for resources over x402 on
 * Xahau, with its on-chain xahc `agent_guardrail` Hook enforcing the spend limit at L1.
 *
 * The agent has a guardrail-Hooked testnet account (PAYER) and a self-imposed budget.
 * For each resource it:
 *   1. GET <resource>                 -> receives HTTP 402 + x402 paymentRequirements
 *   2. parses the requirements, builds + SIGNS a Xahau Payment
 *      (NetworkID 21338, Fee 0.1 XAH to cover Hook execution, LastLedgerSequence ahead,
 *       Destination = merchant payTo, Amount = price)
 *   3. retries GET <resource> with header  X-PAYMENT: base64({txBlob})
 *   4. prints the outcome (200 + content, or 402 + the on-chain rejection reason)
 *
 * Scenario 1 (/premium, 1 XAH < 5 XAH cap):  the Hook ALLOWS it -> agent unlocks content.
 * Scenario 2 (/premium-plus, 10 XAH > 5 XAH cap): the Hook REJECTS it on-ledger
 *   (tecHOOK_REJECTED) -> the resource server denies access -> the agent is BLOCKED.
 *   THE MONEY SHOT: the agent could not overspend; the ledger enforced its budget at L1.
 *
 * SECRETS: the payer seed is loaded from the /tmp scratch file (mode 600, never tracked,
 * never printed). The agent process holds the seed only in memory to sign locally.
 *
 * Env:  RESOURCE_URL (default http://127.0.0.1:4022),
 *       XAHAU_WSS (default wss://xahau-test.net),
 *       SECRETS_FILE (default /tmp/x402-testnet-proof.secrets.json).
 */
import { createRequire } from "node:module";
import { readFileSync, existsSync } from "node:fs";

const require_ = createRequire(import.meta.url);
const kp = require_("xahau-keypairs");
const { Client } = require_("xahau");
const { encode, encodeForSigning } = require_("xahau-binary-codec");

const RESOURCE_URL = (process.env.RESOURCE_URL || "http://127.0.0.1:4022").replace(/\/$/, "");
const WSS = process.env.XAHAU_WSS || "wss://xahau-test.net";
const NETWORK_ID = 21338;
const SECRETS_FILE = process.env.SECRETS_FILE || "/tmp/x402-testnet-proof.secrets.json";
const EXPLORER = (h) => `https://explorer.xahau-test.net/tx/${h}`;

// ANSI helpers for a readable transcript.
const C = { dim: "\x1b[2m", b: "\x1b[1m", g: "\x1b[32m", r: "\x1b[31m", y: "\x1b[33m", c: "\x1b[36m", x: "\x1b[0m" };
const line = (s = "") => process.stdout.write(s + "\n");
const step = (n, s) => line(`\n${C.b}${C.c}[STEP ${n}]${C.x} ${s}`);

// --- load the agent's seed from /tmp (never tracked, never printed) ---------
function loadAgentKeys() {
  if (!existsSync(SECRETS_FILE)) {
    console.error(`agent secrets file not found: ${SECRETS_FILE}\nRun the testnet proof harness first to faucet + install the guardrail hook.`);
    process.exit(1);
  }
  const s = JSON.parse(readFileSync(SECRETS_FILE, "utf8"));
  if (!s.payer?.secret || !s.payer?.account) { console.error("secrets file missing payer.secret/account"); process.exit(1); }
  return { account: s.payer.account, secret: s.payer.secret };
}

// --- sign a Payment locally (ripple-keypairs over encodeForSigning) ---------
// A plain Payment uses only standard fields, so the stock prerelease codec is fine
// (no custom XrplDefinitions needed — unlike SetHook). The signed blob is exactly
// what the facilitator's default-codec decode expects.
function signPayment(tx, seed) {
  const { publicKey, privateKey } = kp.deriveKeypair(seed);
  const account = kp.deriveAddress(publicKey);
  if (account !== tx.Account) throw new Error(`seed derives ${account} != Account ${tx.Account}`);
  const t = { ...tx, SigningPubKey: publicKey };
  const signingData = encodeForSigning(t);
  t.TxnSignature = kp.sign(signingData, privateKey);
  return encode(t);
}

async function getJSON(url, headers = {}) {
  const r = await fetch(url, { headers });
  const json = await r.json().catch(() => ({}));
  return { status: r.status, json };
}

async function main() {
  const agent = loadAgentKeys();
  line(`${C.b}=== Autonomous x402 agent on Xahau testnet ===${C.x}`);
  line(`${C.dim}agent account (PAYER, guardrail-hooked): ${agent.account}${C.x}`);
  line(`${C.dim}resource server: ${RESOURCE_URL}   |   self-budget belief: spend per call must clear the on-chain guardrail${C.x}`);

  // Connect to Xahau (api_version 1) only to read Sequence + current ledger for signing.
  const client = new Client(WSS);
  client.apiVersion = 1;
  await client.connect();
  client.apiVersion = 1;
  line(`${C.dim}connected to ${WSS} (api_version 1) for sequence/ledger reads${C.x}`);

  const results = {};
  try {
    for (const [scenarioName, path, expect] of [
      ["SCENARIO 1", "/premium", "ALLOW"],
      ["SCENARIO 2", "/premium-plus", "BLOCK"],
    ]) {
      line(`\n${C.b}${"=".repeat(70)}${C.x}`);
      line(`${C.b}${scenarioName}: GET ${path}  (expect the guardrail to ${expect})${C.x}`);
      line(`${C.b}${"=".repeat(70)}${C.x}`);

      // 1) Hit the resource without payment -> expect 402 challenge.
      step(1, `agent requests ${path} with no payment`);
      const challenge = await getJSON(`${RESOURCE_URL}${path}`);
      if (challenge.status !== 402) throw new Error(`${path}: expected 402, got ${challenge.status}: ${JSON.stringify(challenge.json)}`);
      const accept = challenge.json.accepts?.[0];
      if (!accept) throw new Error(`${path}: 402 missing paymentRequirements.accepts`);
      const priceDrops = accept.maxAmountRequired;
      line(`  ${C.y}<- 402 Payment Required${C.x}  payTo=${accept.payTo}  price=${(Number(priceDrops) / 1e6)} XAH (${priceDrops} drops)  network=${accept.network}`);

      // 2) Build + sign the Payment. Fee 0.1 XAH covers Hook execution on the hooked
      //    payer (a too-low fee yields telINSUF_FEE_P). NetworkID 21338. LLS ahead.
      step(2, `agent builds + signs a Payment for ${(Number(priceDrops) / 1e6)} XAH`);
      const cur = (await client.request({ command: "ledger", ledger_index: "validated" })).result.ledger_index;
      const seq = (await client.request({ command: "account_info", account: agent.account, ledger_index: "validated" })).result.account_data.Sequence;
      const tx = {
        TransactionType: "Payment",
        Account: agent.account,
        Destination: accept.payTo,
        Amount: priceDrops,
        Fee: "100000", // 0.1 XAH — covers Hook execution on the hooked payer
        Sequence: seq,
        Flags: 0,
        NetworkID: NETWORK_ID,
        LastLedgerSequence: cur + 25,
      };
      const txBlob = signPayment(tx, agent.secret);
      line(`  ${C.dim}signed: seq=${seq} fee=0.1 XAH lastLedger=${cur + 25} networkId=${NETWORK_ID}${C.x}`);

      // 3) Retry WITH the X-PAYMENT header (base64 of {txBlob}).
      step(3, `agent retries ${path} carrying X-PAYMENT (the signed tx)`);
      const xpayment = Buffer.from(JSON.stringify({ txBlob })).toString("base64");
      const paid = await getJSON(`${RESOURCE_URL}${path}`, { "X-PAYMENT": xpayment });

      // 4) Outcome.
      if (paid.status === 200) {
        const txh = paid.json?._payment?.transaction;
        line(`  ${C.g}<- 200 OK — ACCESS GRANTED${C.x}`);
        line(`  ${C.g}tx: ${txh}${C.x}`);
        line(`  ${C.g}on-ledger: delivered ${paid.json?._payment?.delivered} drops, guardrailHookPresent=${paid.json?._payment?.guardrailHookPresent}${C.x}`);
        line(`  explorer: ${EXPLORER(txh)}`);
        line(`  ${C.dim}content: ${JSON.stringify(paid.json.data || paid.json.content || paid.json)}${C.x}`);
        results[path] = { status: 200, outcome: "GRANTED", transaction: txh, explorer: EXPLORER(txh), delivered: paid.json?._payment?.delivered };
      } else {
        const txh = paid.json?.transaction;
        line(`  ${C.r}<- ${paid.status} — ACCESS DENIED${C.x}`);
        line(`  ${C.r}reason: ${paid.json?.reason}${C.x}`);
        if (txh) {
          line(`  ${C.r}on-ledger tx (the rejected attempt): ${txh}${C.x}`);
          line(`  guardrailHookPresent=${paid.json?.guardrailHookPresent}`);
          line(`  explorer: ${EXPLORER(txh)}`);
        }
        line(`  ${C.b}${C.y}>> THE LEDGER ENFORCED THE AGENT'S BUDGET. The agent could not overspend. <<${C.x}`);
        results[path] = { status: paid.status, outcome: "DENIED", reason: paid.json?.reason, transaction: txh, explorer: txh ? EXPLORER(txh) : null, guardrailHookPresent: paid.json?.guardrailHookPresent };
      }
    }

    line(`\n${C.b}${"=".repeat(70)}${C.x}`);
    line(`${C.b}SUMMARY${C.x}`);
    line(`${C.b}${"=".repeat(70)}${C.x}`);
    line(JSON.stringify(results, null, 2));
  } finally {
    await client.disconnect();
  }
}

main().catch((e) => { console.error("FATAL:", e.stack || e.message); process.exit(1); });
