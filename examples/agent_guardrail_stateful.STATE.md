# agent_guardrail_stateful — HookState & parameter contract

This is the binary contract the x402 facilitator (or any off-chain reader) uses
to decode an agent's remaining period budget and reset point straight from the
ledger. It is the authoritative spec for `agent_guardrail_stateful.c`.

Everything is **big-endian**. All amounts are XAH **drops** (1 XAH = 1,000,000 drops).

---

## HookParameters (install-time, on the SetHook `HookParameters` array)

| Name  | Bytes      | Encoding              | Required | Meaning                                  |
|-------|------------|-----------------------|----------|------------------------------------------|
| `LIM` | 8          | BE u64 drops          | yes      | Max spend per single payment             |
| `PLM` | 8          | BE u64 drops          | yes      | Max cumulative spend per period          |
| `PER` | 8 **or** 4 | BE u64 / BE u32       | yes      | Period length, measured in **ledgers**   |
| `DST` | 20         | account-id (raw 20B)  | no       | If present, the only allowed destination |

- Parameter *names* are the ASCII bytes `LIM`, `PLM`, `PER`, `DST` (no NUL).
- `PER` accepts a 4-byte or 8-byte big-endian integer; any other length → the
  hook rolls back (fail-closed). `PER` must be > 0.
- A missing `LIM`, `PLM`, or `PER` → rollback (fail-closed). `DST` is optional.

---

## HookState

### Key (fixed)

```
key = 0x01            (1 byte)
```

There is exactly **one** state entry, under this fixed 1-byte key, in the hook's
own namespace on the hooked account. (The facilitator reads it with the standard
`account_namespace` / state lookup against the agent account.)

### Value layout (16 bytes, big-endian)

| Offset  | Size | Field         | Type   | Meaning                                          |
|---------|------|---------------|--------|--------------------------------------------------|
| `0..8`  | 8    | `periodStart` | BE u64 | Ledger index at which the current period began   |
| `8..16` | 8    | `spent`       | BE u64 | Cumulative drops spent so far in this period     |

If the key is **absent**, no period has opened yet: treat as
`periodStart = (next outgoing payment's ledger)`, `spent = 0`.

A present value whose length is **not** 16 bytes is treated as corrupt by the
hook and causes a rollback (fail-closed). Readers should treat a non-16-byte
value the same way.

---

## On-chain decision logic (what the hook enforces, in order)

For each **outgoing native (XAH) Payment** from the hooked account (non-payments
and incoming payments are passed through untouched):

1. `amount` = this payment's drops. If `amount > LIM` → **rollback** (per-tx cap).
2. `now` = `ledger_seq()`. Read state.
3. Period rollover: if there is no state, **or** `now < periodStart`
   (stale/clock-skew guard), **or** `now - periodStart >= PER`, then a NEW
   period opens: `periodStart = now`, `spent = 0`.
4. `remaining = (spent <= PLM) ? PLM - spent : 0`.
   If `amount > remaining` → **rollback** (period budget exhausted).
5. If `DST` is set and the payment's destination ≠ `DST` → **rollback**.
6. Otherwise persist `periodStart` + `(spent + amount)` and **accept**.

Overflow safety: the budget test compares `amount` against `PLM - spent` (the
remaining headroom) rather than computing `spent + amount`, so no add can wrap.
Because the hook never persists a `spent` greater than `PLM`, `spent + amount` on
the accept path also cannot overflow.

---

## Facilitator formulas (read these straight off `value`)

Let `now` be the current ledger index the facilitator has (e.g. from
`ledger current` / `server_info`'s `validated_ledger.seq`), and let
`periodStart`, `spent` be decoded from `value`. Let `PLM`, `PER` be the install
parameters.

**Is the on-chain period still live?**
```
periodLive = (now >= periodStart) AND (now - periodStart < PER)
```

**Remaining budget (drops) the agent may still spend this period:**
```
if (NOT periodLive):
    remaining = PLM                 # a new payment now would open a fresh period
else:
    remaining = (spent <= PLM) ? (PLM - spent) : 0
```
(The `periodLive` branch matters: once `PER` ledgers have passed, the next
payment resets `spent` to 0 on-chain, so the *effective* remaining budget is the
full `PLM` again even though the stored `spent` is still the old value.)

**Ledgers until the period resets** (only meaningful while `periodLive`):
```
resetInLedgers = periodStart + PER - now        # > 0 while live; <= 0 means already resettable
```
Approximate wall-clock: Xahau closes a ledger roughly every ~3–4 seconds, so
`resetInSeconds ≈ resetInLedgers * 3.5` (use the network's actual close-time
rate for precision).

**Max this single next payment may be** (combining both caps):
```
maxNextPayment = min(LIM, remaining)
```

---

## Caveats (read before trusting any of the above)

- **Period anchor is sliding, not a fixed grid.** `periodStart` is set to the
  ledger of the payment that *opens* the period — not to a fixed calendar/ledger
  boundary. After a quiet stretch longer than `PER`, the period clock effectively
  restarts on the next payment. Budgets are therefore "rolling window from first
  spend", not "fixed N-ledger buckets". This is intentional and minimal; if you
  need fixed buckets, align `periodStart` to `now - (now % PER)` in the hook.
- **Local sim limits.** `xahc test` runs each case with empty state and a fixed
  `ledger_seq`, so it exercises the fresh-period decision path only. True
  multi-payment accumulation and the elapsed-period reset are proven exhaustively
  by `xahc-prover` and should be confirmed on testnet before production use.
- **Native XAH only.** Issued (IOU) amounts are not budgeted; `xahc_otxn_drops()`
  returns negative for issued amounts and the hook rolls back rather than letting
  an unbudgeted IOU payment through. If IOU support is needed, extend with the
  XFL path.
- **Spending authority — fail closed.** Any unexpected state size, missing
  required parameter, bad `PER` length, or non-native amount results in a
  rollback, never a silent accept.
