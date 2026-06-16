# Live demo run — autonomous agent pays through x402 on Xahau, guardrail Hook enforces the budget at L1

**Real run on the Xahau testnet (NetworkID 21338), 2026-06-16.** Throwaway faucet accounts, no real
value. Every transaction hash below was **independently re-fetched from the node** (`tx` command on
`wss://xahau-test.net`) after the run — not just trusted from the app's own output.

Explorer: `https://explorer.xahau-test.net/tx/<hash>`

## What ran

Three processes, real HTTP between them, real WS to the testnet:

```
agent.mjs  --HTTP(402 + X-PAYMENT)-->  resource-server.mjs  --HTTP(/verify,/settle)-->  facilitator  --WS-->  Xahau testnet
 (signs a Payment,                       (sells /premium 1 XAH                            (the REAL x402-xahau         (agent_guardrail Hook
  holds the seed)                          and /premium-plus 10 XAH)                       verifyExact + settle)        is the L1 spend authority)
```

- **PAYER (the agent):** `rMWaeQoWNZoKvuaiUh59z7eHWz6qsToPbg` — has the xahc `agent_guardrail`
  Hook installed (`LIM = 5 XAH` per-payment cap, `DST = PAYEE` allowlisted). Same account + Hook
  installed by the facilitator's committed testnet proof (`docs/FACILITATOR-TESTNET-PROOF.md`).
- **PAYEE (the merchant / payTo):** `rPsf618mGxJgrvp5ubFYBTMEaJFY2KJWY3`.
- Facilitator launched with `XAHAU_WSS=wss://xahau-test.net`, `XAHAU_NETWORK_ID=21338`, a randomly
  generated `X402_SHARED_SECRET` (the resource server forwards it to `/settle`).

## The two scenarios

| scenario | resource | price | vs. 5 XAH cap | outcome | on-ledger result |
|---|---|---|---|---|---|
| 1 | `GET /premium` | 1 XAH | under | **200 — ACCESS GRANTED** | `tesSUCCESS` |
| 2 | `GET /premium-plus` | 10 XAH | over | **402 — ACCESS DENIED** | `tecHOOK_REJECTED` |

The only thing distinguishing the two is the spend amount. The destination is allowlisted in both.
The facilitator's offline `/verify` returns `isValid:true` for both (10 XAH ≤ the resource's own
`maxAmountRequired` of 10 XAH) — the **on-chain Hook**, not the facilitator, is what rejects the
over-budget one.

## Real transaction hashes

| scenario | tx hash | engine_result | ledger | delivered |
|---|---|---|---|---|
| 1 — `/premium` (1 XAH) | `4A887D365620CAEAE519A450C1C1420D10F568AF55BAABC7D489983604B400D7` | `tesSUCCESS` | 9721899 | 1 000 000 drops (1 XAH) |
| 2 — `/premium-plus` (10 XAH) | `4B13EBE1B74E83531A4E0EEE98CBD023515792CD63E487673854E7AADB799A32` | `tecHOOK_REJECTED` | 9721902 | nothing |

- [Scenario 1 on explorer](https://explorer.xahau-test.net/tx/4A887D365620CAEAE519A450C1C1420D10F568AF55BAABC7D489983604B400D7)
- [Scenario 2 on explorer](https://explorer.xahau-test.net/tx/4B13EBE1B74E83531A4E0EEE98CBD023515792CD63E487673854E7AADB799A32)

## Independent on-ledger re-verification

Re-fetched from `wss://xahau-test.net` (`tx` command) after the run:

```
SCENARIO 1 /premium (1 XAH)
  hash:      4A887D365620CAEAE519A450C1C1420D10F568AF55BAABC7D489983604B400D7
  type:      Payment  Amount=1 XAH
  validated: true  ledger=9721899
  result:    tesSUCCESS
  delivered: 1000000
  from->to:  rMWaeQoWNZoKvuaiUh59z7eHWz6qsToPbg -> rPsf618mGxJgrvp5ubFYBTMEaJFY2KJWY3
  networkId: 21338  seq=834898013

SCENARIO 2 /premium-plus (10 XAH)
  hash:      4B13EBE1B74E83531A4E0EEE98CBD023515792CD63E487673854E7AADB799A32
  type:      Payment  Amount=10 XAH
  validated: true  ledger=9721902
  result:    tecHOOK_REJECTED
  delivered: (none)
  from->to:  rMWaeQoWNZoKvuaiUh59z7eHWz6qsToPbg -> rPsf618mGxJgrvp5ubFYBTMEaJFY2KJWY3
  networkId: 21338  seq=834898014

PAYER after run: balance=994.6000 XAH  nextSeq=834898015
PAYEE after run: balance=1004.0000 XAH
```

**The balance is the proof.** The PAYEE (merchant) balance moved **+1 XAH** across the whole run
(1003 → 1004 XAH): only the in-limit `/premium` payment delivered. The over-budget `/premium-plus`
attempt is on-ledger (its sequence 834898014 was consumed, so it is a permanent record) but the
guardrail Hook **rolled back the delivery** — the merchant got nothing. The agent literally could
not overspend its on-chain budget. Both Payments carried `NetworkID: 21338` and a `0.1 XAH` fee
(a hooked account needs a higher fee to cover Hook execution — a lower fee yields `telINSUF_FEE_P`).

## Full agent console transcript (verbatim, ANSI stripped)

```
=== Autonomous x402 agent on Xahau testnet ===
agent account (PAYER, guardrail-hooked): rMWaeQoWNZoKvuaiUh59z7eHWz6qsToPbg
resource server: http://127.0.0.1:4022   |   self-budget belief: spend per call must clear the on-chain guardrail
connected to wss://xahau-test.net (api_version 1) for sequence/ledger reads

======================================================================
SCENARIO 1: GET /premium  (expect the guardrail to ALLOW)
======================================================================

[STEP 1] agent requests /premium with no payment
  <- 402 Payment Required  payTo=rPsf618mGxJgrvp5ubFYBTMEaJFY2KJWY3  price=1 XAH (1000000 drops)  network=xahau

[STEP 2] agent builds + signs a Payment for 1 XAH
  signed: seq=834898013 fee=0.1 XAH lastLedger=9721921 networkId=21338

[STEP 3] agent retries /premium carrying X-PAYMENT (the signed tx)
  <- 200 OK — ACCESS GRANTED
  tx: 4A887D365620CAEAE519A450C1C1420D10F568AF55BAABC7D489983604B400D7
  on-ledger: delivered 1000000 drops, guardrailHookPresent=true
  explorer: https://explorer.xahau-test.net/tx/4A887D365620CAEAE519A450C1C1420D10F568AF55BAABC7D489983604B400D7
  content: "The agent autonomously paid 1 XAH and unlocked the premium feed."

======================================================================
SCENARIO 2: GET /premium-plus  (expect the guardrail to BLOCK)
======================================================================

[STEP 1] agent requests /premium-plus with no payment
  <- 402 Payment Required  payTo=rPsf618mGxJgrvp5ubFYBTMEaJFY2KJWY3  price=10 XAH (10000000 drops)  network=xahau

[STEP 2] agent builds + signs a Payment for 10 XAH
  signed: seq=834898014 fee=0.1 XAH lastLedger=9721924 networkId=21338

[STEP 3] agent retries /premium-plus carrying X-PAYMENT (the signed tx)
  <- 402 — ACCESS DENIED
  reason: tecHOOK_REJECTED
  on-ledger tx (the rejected attempt): 4B13EBE1B74E83531A4E0EEE98CBD023515792CD63E487673854E7AADB799A32
  guardrailHookPresent=true
  explorer: https://explorer.xahau-test.net/tx/4B13EBE1B74E83531A4E0EEE98CBD023515792CD63E487673854E7AADB799A32
  >> THE LEDGER ENFORCED THE AGENT'S BUDGET. The agent could not overspend. <<

======================================================================
SUMMARY
======================================================================
{
  "/premium": {
    "status": 200,
    "outcome": "GRANTED",
    "transaction": "4A887D365620CAEAE519A450C1C1420D10F568AF55BAABC7D489983604B400D7",
    "explorer": "https://explorer.xahau-test.net/tx/4A887D365620CAEAE519A450C1C1420D10F568AF55BAABC7D489983604B400D7",
    "delivered": "1000000"
  },
  "/premium-plus": {
    "status": 402,
    "outcome": "DENIED",
    "reason": "tecHOOK_REJECTED",
    "transaction": "4B13EBE1B74E83531A4E0EEE98CBD023515792CD63E487673854E7AADB799A32",
    "explorer": "https://explorer.xahau-test.net/tx/4B13EBE1B74E83531A4E0EEE98CBD023515792CD63E487673854E7AADB799A32",
    "guardrailHookPresent": true
  }
}
```

## Honesty notes

- **Real ledger, real Hook, no stubs.** The facilitator's production `verifyExact` and `settle`
  (from `../server.mjs`) did the verification + submission; `settle` read the node's real
  `engine_result`. The on-chain `agent_guardrail` Hook produced the `tecHOOK_REJECTED`.
- **Why a launcher (`facilitator-testnet.mjs`) instead of `node server.mjs`:** the production
  facilitator's internal xrpl client uses xrpl@4's default WS `api_version` (2), which Xahau's
  rippled rejects with `invalid_API_version`. The launcher injects an `api_version:1` client + a
  ledger fetcher through the facilitator's documented `_deps` seam — the **same** seam the committed
  proof harness uses. The security-critical verify/settle logic is the production code, unchanged;
  only the WS transport version is pinned.
- **Secrets stay out of the repo.** The agent loads the payer seed from
  `/tmp/x402-testnet-proof.secrets.json` (mode 600, gitignored pattern `*.secrets.json`). No source
  file, this transcript, or the README contains a seed. A fresh set of accounts would produce
  different hashes; the hashes above are permanent on the testnet ledger from the 2026-06-16 run.
