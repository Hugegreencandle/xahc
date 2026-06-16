# x402-xahau facilitator — live testnet proof

End-to-end proof that the **exact-xahau facilitator** (`server.mjs`) works against the
**real Xahau testnet** ledger (NetworkID **21338**) with a **real xahc `agent_guardrail`
Hook** installed on the payer — no stubs, no fakes. The facilitator's own `verifyExact`
and `settle` were called against a live xrpl client connected to `wss://xahau-test.net`;
`settle` submitted the signed Payments and read the ledger's `engine_result`.

Run **2026-06-16** with throwaway faucet accounts (no real value). Every hash below was
re-fetched from the node independently after the run.

Explorer: `https://explorer.xahau-test.net/tx/<hash>`

## What this validates

The facilitator's two security-critical entry points behave correctly against the live chain:

- **`verifyExact`** cryptographically verifies the signed Payment offline (signature bound to
  `Account`, NetworkID 21338, destination, amount ≤ max, expiry window present).
- **`settle`** submits to the real node, re-validates everything, reports the payer's guardrail
  Hook presence honestly (`guardrailHookPresent:true`), checks `delivered_amount ≥ required`,
  and is idempotent (a replay of the same payment returns the original receipt and never
  re-submits).
- The on-chain **`agent_guardrail` Hook is the L1 spending authority**: an in-limit payment is
  applied; an over-limit one is rolled back by the Hook (`tecHOOK_REJECTED`) on the ledger — the
  facilitator surfaces that real code, it does not enforce the limit itself.

## Accounts (ephemeral testnet faucet keys; no value, secrets NOT in this repo)

| role | address |
|---|---|
| **PAYER** — has `agent_guardrail` installed (`LIM=5 XAH`, `DST=PAYEE`) | `rMWaeQoWNZoKvuaiUh59z7eHWz6qsToPbg` |
| **PAYEE** — payment destination / allowlisted dst | `rPsf618mGxJgrvp5ubFYBTMEaJFY2KJWY3` |

> Secrets (faucet seeds) live only in a local `/tmp` scratch file, never committed, never in
> this doc. The proof script (`testnet-proof.mjs`) is gitignored.

## The installed Hook

- **Hook:** `agent_guardrail` (`examples/agent_guardrail.c`), prebuilt wasm at
  `~/Desktop/xahc-prover/hooks/agent_guardrail.wasm`.
- **Fires on:** `Payment` (outgoing only).
- **HookParameters** (set at install via `xahc install-tx --param`):
  - `LIM` (name hex `4C494D`) = `00000000004C4B40` = **5 000 000 drops (5 XAH)** per-tx spend cap.
  - `DST` (name hex `445354`) = `F1B9322DE209841AAE84BFBDA0118003D3A8B5F0` = the 20-byte account-id
    of **PAYEE** (destination allowlist).
- **SetHook install tx:** `9990977225948052B06A0EBD324052726F31189A97FC7FAA1D8BBE48E2848B4A`
  → `tesSUCCESS`, ledger 9719995, payer sequence 834898010.
  [explorer](https://explorer.xahau-test.net/tx/9990977225948052B06A0EBD324052726F31189A97FC7FAA1D8BBE48E2848B4A)
- Presence re-confirmed via `account_objects type=hook` → `confirmedInstalled: true`.

The SetHook was built with `xahc install-tx ... --json`, then signed with the payer seed and
submitted raw (the install: `2 XAH`-class fee, NetworkID 21338, `LastLedgerSequence` a few
ledgers ahead).

## The three scenarios

Spend cap `LIM = 5 XAH`. In-limit amount `A_ok = 3 XAH (3 000 000 drops)`; over-limit amount
`A_over = 10 XAH (10 000 000 drops)`. PAYEE is in the destination allowlist in all cases, so the
**only** thing distinguishing A from B is the spend limit.

### Scenario A — in-limit payment ACCEPTED (3 XAH < 5 XAH)

`verifyExact` returned `isValid:true`; `settle` submitted and the ledger applied it.

- **tx hash:** `29A3AF5C088C4B73CDF9B82B8ED9AA8288A937282EFD049140CC98FEAF9BB2B4`
  [explorer](https://explorer.xahau-test.net/tx/29A3AF5C088C4B73CDF9B82B8ED9AA8288A937282EFD049140CC98FEAF9BB2B4)
- **on-ledger:** `tesSUCCESS`, ledger 9720039, payer sequence 834898011.

```json
verifyExact(A) = {
  "isValid": true, "invalidReason": null,
  "payer": "rMWaeQoWNZoKvuaiUh59z7eHWz6qsToPbg",
  "amount": "3000000", "asset": null,
  "signatureVerified": true,
  "replayId": "acct:rMWaeQoWNZoKvuaiUh59z7eHWz6qsToPbg:834898011"
}

settle(A) = {
  "success": true,
  "transaction": "29A3AF5C088C4B73CDF9B82B8ED9AA8288A937282EFD049140CC98FEAF9BB2B4",
  "network": "xahau",
  "errorReason": null,
  "delivered": "3000000",
  "guardrailHookPresent": true,
  "payer": "rMWaeQoWNZoKvuaiUh59z7eHWz6qsToPbg"
}
```

### Scenario B — over-limit payment REJECTED by the guardrail Hook (10 XAH > 5 XAH)

`verifyExact` still returns `isValid:true` (the amount is ≤ `maxAmountRequired`, which was set to
10 XAH for this scenario — the facilitator's offline check is about the request, not the on-chain
spend limit). `settle` submitted it; the **on-chain Hook rolled it back** with `tecHOOK_REJECTED`,
and the facilitator surfaced exactly that.

- **tx hash:** `0F8EF9B90A086EDDDBB0C095443A33C6372382AD8FBCDC40D469119EE3583864`
  [explorer](https://explorer.xahau-test.net/tx/0F8EF9B90A086EDDDBB0C095443A33C6372382AD8FBCDC40D469119EE3583864)
- **on-ledger:** `tecHOOK_REJECTED`, ledger 9720042, payer sequence 834898012 (sequence consumed →
  the tx is on-ledger; the Hook rejected the *delivery*, not the inclusion).

```json
settle(B) = {
  "success": false,
  "transaction": "0F8EF9B90A086EDDDBB0C095443A33C6372382AD8FBCDC40D469119EE3583864",
  "network": "xahau",
  "errorReason": "tecHOOK_REJECTED",
  "guardrailHookPresent": true,
  "payer": "rMWaeQoWNZoKvuaiUh59z7eHWz6qsToPbg"
}
```

### Scenario C — replay idempotency (no second tx)

`settle` was called **again with Scenario A's exact payload**. It returned the **same receipt**
with `replayed:true` and the **same hash** — it did **not** submit a second transaction.

```json
settle(C) = {
  "success": true,
  "transaction": "29A3AF5C088C4B73CDF9B82B8ED9AA8288A937282EFD049140CC98FEAF9BB2B4",  // == A
  "network": "xahau",
  "errorReason": null,
  "delivered": "3000000",
  "guardrailHookPresent": true,
  "payer": "rMWaeQoWNZoKvuaiUh59z7eHWz6qsToPbg",
  "replayed": true
}
```

**On-ledger proof of no-duplicate:** after the run the PAYER's next sequence was **834898013** —
i.e. exactly two Payment transactions reached the ledger (A at 834898011, B at 834898012). The
replay produced **no** third transaction. The PAYEE balance was **1 003 000 000 drops** = 1000 XAH
(faucet) + 3 XAH (only A delivered; B was rejected and delivered nothing).

## Independent on-ledger re-verification

Re-fetched from `wss://xahau-test.net` (`tx` command) after the run:

| tx | type | engine_result | ledger | payer seq |
|---|---|---|---|---|
| `9990977…848B4A` (SetHook install) | SetHook | `tesSUCCESS` | 9719995 | 834898010 |
| `29A3AF5C…BB2B4` (A, in-limit) | Payment | `tesSUCCESS` | 9720039 | 834898011 |
| `0F8EF9B9…583864` (B, over-limit) | Payment | `tecHOOK_REJECTED` | 9720042 | 834898012 |

PAYER current Sequence = **834898013** (only A+B applied). PAYEE Balance = **1 003 000 000 drops**.

## Environment

- **Network:** Xahau testnet, NetworkID **21338**, WS `wss://xahau-test.net` (api_version **1** —
  Xahau's rippled does not accept api_version 2).
- **Facilitator env:** `XAHAU_NETWORK_ID=21338` (so `EXPECTED_NETWORK_ID === 21338`), `XAHAU_WSS=wss://xahau-test.net`.
- **Node deps:** `xrpl`, `ripple-keypairs`, `ripple-address-codec`, `xrpl-binary-codec-prerelease`
  (all already in `x402-xahau/node_modules`).
- **Signing:** Payments + SetHook signed with `ripple-keypairs` over `encodeForSigning`. The SetHook
  required an `XrplDefinitions` built from the node's `server_definitions` (the stock codec doesn't
  know the `SetHook` tx type / Hook fields). Payments are standard and need no custom definitions.
- **Toolchain:** `xahc install-tx` (release binary) produced the unsigned SetHook with the LIM/DST
  HookParameters; the prebuilt `agent_guardrail.wasm` was installed unchanged.

### Notes on the live run (honest caveats)

- The **first** attempt at Scenario A failed with `telINSUF_FEE_P`: a Payment from a hooked account
  must carry a fee high enough to cover Hook execution. The facilitator correctly **failed closed**
  (treated the LastLedgerSequence-passed/insufficient-fee outcome as ambiguous and retained the
  replay reservation rather than fabricating success). Raising the Payment `Fee` to `100000` drops
  (0.1 XAH) and widening `LastLedgerSequence` resolved it; the scenarios above are the clean run.
- The facilitator builds its own xrpl client by default; the proof script **injects** an
  api_version-1 client (and a ledger-index fetcher) via `settle`'s `_deps` seam so it talks to the
  Xahau node. The verify/settle logic exercised is the production code unchanged.

## How to re-run

From `x402-xahau/` (with `node_modules` installed):

```sh
# secrets stay in /tmp; the script is gitignored
node testnet-proof.mjs            # faucets/reuses PAYER+PAYEE, installs the hook if absent,
                                  # runs scenarios A/B/C, prints a JSON proof on stdout
```

- The script faucets two accounts (POST `https://xahau-test.net/accounts`, rate-limited ~60s, with
  retry/backoff) and caches their seeds in `/tmp/x402-testnet-proof.secrets.json` (mode 600, never
  committed) so reruns reuse them within the validity window.
- It sets `XAHAU_NETWORK_ID=21338` + `XAHAU_WSS=wss://xahau-test.net`, installs `agent_guardrail`
  with `LIM=5 XAH` / `DST=PAYEE` if not already present, then calls `verifyExact` + `settle`
  directly for each scenario and polls the ledger for validation.
- A fresh set of accounts will produce **different** tx hashes; the ones in this doc are from the
  2026-06-16 run and are permanent on the testnet ledger.

*The proof harness `testnet-proof.mjs` holds no secrets itself (seeds load from the `/tmp` scratch
file) and is gitignored. Only this doc is intended for commit.*
