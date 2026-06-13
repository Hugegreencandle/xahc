---
name: xahc-guardrail
description: >-
  Build and install an on-chain spending guardrail for an autonomous agent on
  Xahau. Use when a user wants to cap how much an AI agent / automated account
  can spend per transaction, lock it to specific destinations, or otherwise
  enforce agent payment policy at layer 1 (not just in app code). Produces a
  compiled Hook and an UNSIGNED SetHook transaction to install it. Triggers:
  "limit what my agent can spend", "agent spending cap", "guardrail hook",
  "restrict agent payments", "self-imposed on-chain budget".
---

# xahc-guardrail

Give an autonomous agent a **protocol-enforced** spending limit on Xahau. The
agent (or its operator) installs a Hook on its own account; from then on Xahau
itself rejects any outgoing payment that breaks the policy — even if the agent's
signing key is compromised or its off-chain logic misbehaves. This is the L1
control that app-layer agent frameworks and x402 flows lack.

## Prerequisites

- `xahc` on PATH and a wasm toolchain. Verify: `xahc doctor`.
  (Install: binary from xahc Releases + `brew install llvm lld` / `apt install clang lld`.)

## Procedure

1. **Scaffold** the guardrail project:
   ```sh
   xahc new agentguard --archetype agent_guardrail
   cd agentguard
   ```
   The Hook policies OUTGOING payments via two install-time parameters:
   - `LIM` — 8-byte big-endian drops, the max per-transaction spend (required).
   - `DST` — 20-byte account-id; if set, outgoing payments must go to it (optional).

2. **Build + test** (no testnet needed):
   ```sh
   xahc build agentguard.c -o agentguard.wasm   # compile -> clean -> lint
   xahc test agentguard.test.toml               # asserts the policy
   ```

3. **Compute `LIM`** = limit-in-drops as 16 hex chars (1 XAH = 1,000,000 drops).
   Example: 10 XAH = 10,000,000 = `0x989680` → `LIM=0000000000989680`.

4. **Emit the install transaction** (unsigned):
   ```sh
   xahc install-tx agentguard.wasm \
     --account <rAGENT_ACCOUNT> \
     --on Payment \
     --param 4C494D=0000000000989680     # 4C494D = "LIM"
   #  optional destination lock: --param 445354=<20-byte-dest-account-id-hex>  (445354 = "DST")
   ```
   This prints an UNSIGNED `SetHook`. **Never sign for the user.** Hand it back to
   be signed offline (xaman / xrpl-accountlib) and submitted.

5. **(Recommended) audit before install** — run `agentguard.wasm` through
   xahau-mcp's `analyze_hook` / `execute_hook` for full-fidelity verification.

## Notes

- Parameter NAMES are hex of the ASCII key: `LIM`=`4C494D`, `DST`=`445354`.
- `install-tx` refuses a wasm that fails lint and validates the r-address — it is
  not an escape hatch around the safety checks.
- To raise/lower the limit later, re-run `install-tx` with a new `LIM` (Flags=1
  overrides the existing hook in the slot).
