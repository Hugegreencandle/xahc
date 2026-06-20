---
name: xahau-attest
description: Certify a Xahau Hook into a signed, independently re-checkable certification deliverable — the VaaS product artifact you hand a paying customer. Use when someone wants a Hook formally attested (proven safe for its claimed properties), or asks for a "safety certificate / audit attestation" for a Xahau Hook.
---

# xahau-attest — the signed certification deliverable

Turns a Hook into a customer-ready certification: runs the invariant battery, signs the PROVEN results
into the tamper-evident registry (bound to the on-chain HookHash), and renders a clean deliverable
(`CERTIFICATION.md` + `certification.json`). This is the **monetizable VaaS artifact** — the thing a
customer pays for and can re-verify themselves.

## The one rule that makes it honest (read first)
A certification certifies the Hook's **CLAIMED property set** — the specific invariants it's *supposed*
to satisfy. ALWAYS pass `--invariants <claimed set>`. A COUNTEREXAMPLE on a property the Hook never
claimed is NOT a defect (the Hook isn't designed for it), and presenting it as one is dishonest +
loses credibility. Full-battery mode (no `--invariants`) is a DISCOVERY sweep only, not a certification.

## Workflow
1. **Get the inputs:**
   - the Hook (`.wasm`, or `.c` to build).
   - the **claimed invariant set** — ask the customer/Dane what the Hook is supposed to guarantee
     (e.g. a yield Hook: `constant-product,conservation`; an admin Hook: `authz,overflow`). Map plain
     asks to invariant names (see the battery: `xahc prove --list` / xahau-hook-report).
   - the **attester key** (`--key`): Dane's stable Ed25519 key (registry keygen) so customers can pin
     his pubkey. Without it the cert is unsigned-but-tamper-evident (and says so).
2. **Run:**
   ```
   cd ~/Desktop/xahc-prover && ./.venv/bin/python tools/attest.py <hook> \
     --invariants <claimed,set> --key <attester.key> --customer "<Name>" --out <dir>
   ```
3. **Deliver:** hand the customer `CERTIFICATION.md` (the scorecard) + `certification.json`. Verdict is
   **CERTIFIED** only if every claimed property PROVEN; **NOT CERTIFIED** if any claimed one is
   COUNTEREXAMPLE/INCONCLUSIVE (report that honestly — it's a finding, not a failure of the tool).

## Honesty rules (carry these into how you present it)
- **PROVEN ≠ unqualified "safe."** It means: holds for every input, under that invariant's stated scope.
  Never tell a customer the Hook is "safe" — say which properties are proven, with the residual.
- **INCONCLUSIVE is not a pass** — it's fail-closed (the engine couldn't decide it soundly).
- **The cert binds to the exact bytecode (HookHash).** Modify the Hook → hash changes → cert void →
  re-certify. Say this to the customer.
- **Re-checkable by anyone:** the cert ships `reverify` / `recheck` / `checkproof` instructions. Lead
  with "trust the math, not us" — that's the differentiator.

## Related
xahau-audit (the lint→sim→prove→fuzz pass before attesting), the Proof Registry (where the signed
manifests land), xahc-prover `tools/attest.py` (the engine for this skill).
