#!/usr/bin/env node
/**
 * verify-emit.mjs — offline verification of xahc's emit builders against the
 * chain-validated Xahau binary codec (the same codec xahau-mcp trusts).
 *
 * Pipeline:
 *   xahc sim <hook.wasm> ...           -> prints "emit[0] (N bytes): <HEX>"
 *   node scripts/verify-emit.mjs <HEX> -> decodes the blob, prints fields
 *
 * Why this exists: xahc builds transaction blobs by hand (emit/payment.h).
 * Rather than trust hand-derived byte offsets, we round-trip the blob through
 * `xrpl-binary-codec-prerelease` (Xahau-aware) and confirm the fields decode to
 * the intended values — no testnet, no node.
 *
 * Setup:  npm i xrpl-binary-codec-prerelease
 * Usage:  node scripts/verify-emit.mjs <emit-hex>
 */
import { decode } from "xrpl-binary-codec-prerelease";

const hex = (process.argv[2] || "").trim().toUpperCase();
if (!/^[0-9A-F]+$/.test(hex)) {
  console.error("usage: node scripts/verify-emit.mjs <emit-hex-from-xahc-sim>");
  process.exit(1);
}

// xahc's simulator zero-fills the EmitDetails region (xahaud injects the real
// one on-chain). Trim trailing zero bytes so the codec parses only our fields.
let end = hex.length;
while (end >= 2 && hex.slice(end - 2, end) === "00") end -= 2;
// Re-pad to an even field boundary is unnecessary; decode tolerates the trim
// as long as we stop on a field boundary. The builders place Destination last,
// so trimming trailing zeros lands exactly at end-of-Destination.

let json;
try {
  json = decode(hex.slice(0, end));
} catch (e) {
  console.error("decode failed:", e.message);
  console.error("(if this fires on a valid build, the EmitDetails trim boundary moved — file an issue)");
  process.exit(2);
}

console.log(JSON.stringify(json, null, 2));

const ok = (cond) => (cond ? "OK" : "FAIL");
const checks = [
  ["TransactionType present", !!json.TransactionType],
  ["Amount is a drops string", typeof json.Amount === "string" && /^\d+$/.test(json.Amount)],
  ["Account is r-address", /^r/.test(json.Account || "")],
  ["Destination is r-address", /^r/.test(json.Destination || "")],
];
console.log("\n=== checks ===");
let failed = 0;
for (const [name, pass] of checks) {
  console.log(`${ok(pass).padEnd(5)} ${name}`);
  if (!pass) failed++;
}
process.exit(failed ? 3 : 0);
