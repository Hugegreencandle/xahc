#!/usr/bin/env node
/**
 * verify-emit-vm.mjs — run a hook through xahau-mcp's VM (real XFL/float API)
 * and decode its emitted transaction(s). Use for emits xahc's own `sim` can't
 * execute (issued/IOU amounts need the float host fns).
 *
 * Requires a local xahau-mcp checkout (npm-installed + built: `npm run build`).
 *
 *   XAHAU_MCP=/path/to/xahau-mcp node scripts/verify-emit-vm.mjs <hook.wasm> [txType]
 *
 * Exit 0 if the run is non-degraded and every emit decodes; non-zero otherwise.
 */
import fs from "fs";

const mcp = process.env.XAHAU_MCP;
if (!mcp) {
  console.error("set XAHAU_MCP=/path/to/xahau-mcp (a built checkout: npm i && npm run build)");
  process.exit(1);
}
const wasmPath = process.argv[2];
const txType = process.argv[3] || "Payment";
if (!wasmPath) {
  console.error("usage: XAHAU_MCP=... node scripts/verify-emit-vm.mjs <hook.wasm> [txType]");
  process.exit(1);
}

const { runHook } = await import(`${mcp}/dist/sandbox.js`);
const pre = await import(`${mcp}/node_modules/xrpl-binary-codec-prerelease/dist/index.js`);
const { BinaryParser } = await import(
  `${mcp}/node_modules/xrpl-binary-codec-prerelease/dist/serdes/binary-parser.js`
);

const bytes = new Uint8Array(fs.readFileSync(wasmPath));
const r = runHook(bytes, { txType });

console.log(`exit=${r.exit} code=${r.returnCode} "${r.returnString ?? ""}" degraded=${r.degraded} emits=${r.emitted.length}`);
if (r.degraded) {
  console.error("DEGRADED — unsupported calls:", JSON.stringify(r.unsupportedCalls ?? []));
}

let failed = r.degraded ? 1 : 0;
for (const [i, blob] of r.emitted.entries()) {
  console.log(`\n=== emit[${i}] (${blob.length / 2} bytes) ===`);
  const p = new BinaryParser(blob.toUpperCase(), pre.DEFAULT_DEFINITIONS);
  let decodedAmount = false;
  try {
    let n = 0;
    while (!p.end() && n < 25) {
      const [field, value] = p.readFieldAndValue();
      const s = value?.toJSON ? JSON.stringify(value.toJSON()) : String(value);
      console.log(String(field.name).padEnd(20), "=", s.slice(0, 100));
      if (field.name === "Amount") decodedAmount = true;
      n++;
    }
  } catch {
    /* EmitDetails / synthetic tail — fields above are what we built */
  }
  if (!decodedAmount) { console.error("  no Amount field decoded"); failed = 1; }
}
process.exit(failed);
