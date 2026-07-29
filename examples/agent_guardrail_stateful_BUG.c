#include "xahc/xahc.h"

/* Agent spending guardrail — STATEFUL period-budget edition, WITH A PLANTED BUG.
 *
 * REFUTATION TWIN for prove_period_budget.py. Byte-for-byte identical to
 * agent_guardrail_stateful.c EXCEPT the period-budget check on line ~140:
 *
 *     REAL:  uint64_t remaining = (spent <= plm) ? (plm - spent) : 0;
 *            XAHC_REQUIRE(amount <= remaining, "over period budget");
 *     BUG:   XAHC_REQUIRE(amount <= plm, "over period budget");
 *
 * The bug is a realistic developer mistake: it caps each payment against the
 * FULL period budget PLM, ignoring how much was already spent this period.
 * Every individual payment <= PLM passes, and a fresh-state local sim (spent==0)
 * looks correct — so lint AND a single-tx sim both pass. But the hook still
 * persists  spent' = spent + amount  (line ~156), so with a prior spent up to PLM
 * and a new amount up to PLM, the persisted spent' reaches 2*PLM > PLM.
 *
 * That violates the exact obligation the inductive proof checks:
 *     (a) newly persisted spent' <= PLM.
 * The prover must return a COUNTEREXAMPLE (a prior in-budget state + an amount
 * that drives spent' past PLM). If it PROVES this hook, the proof is vacuous.
 * This twin is the non-vacuity control for Proven Agent Budget. */

int64_t cbak(uint32_t reserved) { return 0; }

static inline uint64_t be64(const uint8_t* b) {
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  | ((uint64_t)b[7]);
}

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

    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    int outgoing = 1;
    for (int i = 0; i < 20; ++i) {
        XAHC_GUARD(20);
        if (origin[i] != me[i]) outgoing = 0;
    }
    if (!outgoing)
        XAHC_ACCEPT("incoming");

    uint8_t lim_key[3] = { 'L', 'I', 'M' };
    uint8_t lim_b[8];
    XAHC_HOOK_PARAM_REQUIRE(lim_b, lim_key, 8);
    uint64_t lim = be64(lim_b);

    uint8_t plm_key[3] = { 'P', 'L', 'M' };
    uint8_t plm_b[8];
    XAHC_HOOK_PARAM_REQUIRE(plm_b, plm_key, 8);
    uint64_t plm = be64(plm_b);

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
        return 0;
    }
    XAHC_REQUIRE(per > 0, "PER must be > 0");

    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native amount only");
    uint64_t amount = (uint64_t)drops;

    XAHC_REQUIRE(amount <= lim, "over per-tx spend limit");

    uint64_t now = (uint64_t)ledger_seq();

    uint8_t skey[1] = { 0x01 };
    uint8_t sval[16];
    int64_t srd = state(XAHC_SBUF(sval), XAHC_SBUF(skey));

    uint64_t period_start;
    uint64_t spent;
    if (srd == 16) {
        period_start = be64(&sval[0]);
        spent        = be64(&sval[8]);
        if (now < period_start || (now - period_start) >= per) {
            period_start = now;
            spent = 0;
        }
    } else if (srd < 0) {
        period_start = now;
        spent = 0;
    } else {
        rollback((uint32_t)"corrupt state", sizeof("corrupt state"), (int64_t)__LINE__);
        return 0;
    }

    /* ---- PLANTED BUG: caps amount against the FULL period budget, ignoring
     * prior `spent`. The real hook uses `amount <= plm - spent`. ---- */
    XAHC_REQUIRE(amount <= plm, "over period budget");

    uint8_t dst_key[3] = { 'D', 'S', 'T' };
    uint8_t allowed[20];
    if (hook_param(XAHC_SBUF(allowed), XAHC_SBUF(dst_key)) == 20) {
        uint8_t dest[20];
        XAHC_OTXN_DESTINATION(dest);
        int ok = 1;
        for (int i = 0; i < 20; ++i) {
            XAHC_GUARD(20);
            if (dest[i] != allowed[i]) ok = 0;
        }
        XAHC_REQUIRE(ok, "destination not in policy");
    }

    uint64_t new_spent = spent + amount;
    wr64(&sval[0], period_start);
    wr64(&sval[8], new_spent);
    XAHC_STATE_SET(skey, sval);

    XAHC_ACCEPT("within policy");
    return 0;
}
