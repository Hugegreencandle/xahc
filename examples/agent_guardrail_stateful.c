#include "xahc/xahc.h"

/* Agent spending guardrail — STATEFUL period-budget edition.
 * Install on an autonomous agent's account.
 *
 * Extends agent_guardrail.c: keeps the per-tx cap (LIM) and the optional
 * destination lock (DST), and ADDS a cumulative spend budget enforced over a
 * rolling window of ledgers. Even when every individual payment is under LIM,
 * once the running total for the current period reaches PLM the hook rolls
 * back further outgoing payments until the period rolls over.
 *
 * HookParameters (install-time, HookParameters on the SetHook):
 *   "LIM" (8 bytes, big-endian drops)  REQUIRED — max per-tx spend
 *   "PLM" (8 bytes, big-endian drops)  REQUIRED — max cumulative spend per period
 *   "PER" (4 or 8 bytes, big-endian)   REQUIRED — period length, in LEDGERS
 *   "DST" (20-byte account-id)         OPTIONAL — lock outgoing to one destination
 *
 * HookState (one entry):
 *   key   = { 0x01 }                   (1 byte, fixed — the budget slot)
 *   value = 16 bytes, big-endian:
 *           [0..8)   periodStart : u64  ledger index the current period began at
 *           [8..16)  spent       : u64  drops spent so far this period
 *
 * Policies OUTGOING native (XAH) Payments from this account; passes everything
 * else (non-payments, incoming payments). Fails CLOSED on any unexpected
 * decode/state error (rollback), because this hook is a spending AUTHORITY.
 *
 * Period model: a NEW period anchors periodStart at the CURRENT ledger_seq of
 * the payment that opens it (a sliding anchor, not a fixed grid). See
 * agent_guardrail_stateful.STATE.md for the exact facilitator contract. */

int64_t cbak(uint32_t reserved) { return 0; }

/* Decode an 8-byte big-endian buffer to u64. */
static inline uint64_t be64(const uint8_t* b) {
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  | ((uint64_t)b[7]);
}

/* Encode u64 to an 8-byte big-endian buffer. */
static inline void wr64(uint8_t* b, uint64_t v) {
    b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40); b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);  b[7] = (uint8_t)(v);
}

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    if (otxn_type() != XAHC_ttPAYMENT)
        XAHC_ACCEPT("not a payment");

    /* Only police OUTGOING payments (origin == this hook's account). */
    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    int outgoing = 1;
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
        if (origin[i] != me[i]) outgoing = 0;
    if (!outgoing)
        XAHC_ACCEPT("incoming");

    /* --- Required parameters --- */

    /* Per-tx spend cap LIM (8-byte drops). */
    uint8_t lim_key[3] = { 'L', 'I', 'M' };
    uint8_t lim_b[8];
    XAHC_HOOK_PARAM_REQUIRE(lim_b, lim_key, 8);
    uint64_t lim = be64(lim_b);

    /* Period spend cap PLM (8-byte drops). */
    uint8_t plm_key[3] = { 'P', 'L', 'M' };
    uint8_t plm_b[8];
    XAHC_HOOK_PARAM_REQUIRE(plm_b, plm_key, 8);
    uint64_t plm = be64(plm_b);

    /* Period length PER, in LEDGERS. Accept 8-byte (BE u64) or 4-byte (BE u32). */
    uint8_t per_key[3] = { 'P', 'E', 'R' };
    uint8_t per_b[8];
    int64_t per_len = hook_param(XAHC_SBUF(per_b), XAHC_SBUF(per_key));
    uint64_t per;
    if (per_len == 8) {
        per = be64(per_b);
    } else if (per_len == 4) {
        per = ((uint64_t)per_b[0] << 24) | ((uint64_t)per_b[1] << 16) |
              ((uint64_t)per_b[2] << 8)  | ((uint64_t)per_b[3]);
    } else {
        rollback((uint32_t)"bad PER param", sizeof("bad PER param"), (int64_t)__LINE__);
        return 0; /* unreachable; fail-closed */
    }
    XAHC_REQUIRE(per > 0, "PER must be > 0");

    /* --- This payment's native amount (drops). --- */
    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native amount only");
    uint64_t amount = (uint64_t)drops;

    /* (1) Per-tx cap. */
    XAHC_REQUIRE(amount <= lim, "over per-tx spend limit");

    /* (2) Read current ledger and prior budget state. */
    uint64_t now = (uint64_t)ledger_seq();

    uint8_t skey[1] = { 0x01 };
    uint8_t sval[16];
    int64_t srd = state(XAHC_SBUF(sval), XAHC_SBUF(skey));

    uint64_t period_start;
    uint64_t spent;
    if (srd == 16) {
        period_start = be64(&sval[0]);
        spent        = be64(&sval[8]);
        /* Roll over to a new period if the window has elapsed. Guard against a
         * stale/future periodStart (now < period_start) by also resetting. */
        if (now < period_start || (now - period_start) >= per) {
            period_start = now;
            spent = 0;
        }
    } else if (srd < 0) {
        /* No prior state (absent key) -> open a fresh period. xahaud returns a
         * negative "doesn't exist" code for an absent key. Any OTHER negative is
         * also treated as fresh; a malformed non-16 positive read fails closed. */
        period_start = now;
        spent = 0;
    } else {
        /* Present but wrong size -> corrupt state. Fail closed. */
        rollback((uint32_t)"corrupt state", sizeof("corrupt state"), (int64_t)__LINE__);
        return 0; /* unreachable */
    }

    /* (3) Period budget check, overflow-safe: test amount against the REMAINING
     * headroom (plm - spent) rather than computing spent + amount, so no add can
     * wrap. spent <= plm is an invariant we maintain (we never store a value that
     * exceeds plm), but clamp defensively in case PLM was lowered between calls. */
    uint64_t remaining = (spent <= plm) ? (plm - spent) : 0;
    XAHC_REQUIRE(amount <= remaining, "over period budget");

    /* (4) Optional destination lock DST (20-byte account-id). */
    uint8_t dst_key[3] = { 'D', 'S', 'T' };
    uint8_t allowed[20];
    if (hook_param(XAHC_SBUF(allowed), XAHC_SBUF(dst_key)) == 20) {
        uint8_t dest[20];
        XAHC_OTXN_DESTINATION(dest);
        int ok = 1;
        for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
            if (dest[i] != allowed[i]) ok = 0;
        XAHC_REQUIRE(ok, "destination not in policy");
    }

    /* (5) Commit the new cumulative spend, then accept. amount <= remaining
     * guarantees spent + amount <= plm, so no overflow here either. */
    uint64_t new_spent = spent + amount;
    wr64(&sval[0], period_start);
    wr64(&sval[8], new_spent);
    XAHC_STATE_SET(skey, sval);

    XAHC_ACCEPT("within policy");
    return 0;
}
