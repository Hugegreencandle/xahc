#include "xahc/xahc.h"

/* Agent spending guardrail (per-tx cap) — WITH A PLANTED BUG.
 *
 * REFUTATION TWIN for prove_guardrail.py. Identical to agent_guardrail.c EXCEPT
 * the per-tx cap comparison on line ~44:
 *
 *     REAL:  XAHC_REQUIRE((uint64_t)drops <= limit, "over per-tx spend limit");
 *     BUG:   XAHC_REQUIRE((uint32_t)drops <= (uint32_t)limit, "over per-tx spend limit");
 *
 * The bug truncates both sides to 32 bits — a realistic mistake (a dev casting an
 * int64 drop amount to int for the compare). A payment whose LOW 32 bits are under
 * the limit but whose HIGH 32 bits are set (a huge amount) passes the truncated
 * check. Small-value tests and a naive sim pass; the true amount is far over LIM.
 *
 * prove_guardrail.py checks: (accept AND outgoing Payment) => true drops <= LIM,
 * using the FULL 64-bit decode. So it must return a COUNTEREXAMPLE (a drops value
 * with high bits set that the truncated check let through). Non-vacuity control. */

int64_t cbak(uint32_t reserved) { return 0; }

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
    uint8_t lim[8];
    XAHC_HOOK_PARAM_REQUIRE(lim, lim_key, 8);
    uint64_t limit =
        ((uint64_t)lim[0] << 56) | ((uint64_t)lim[1] << 48) |
        ((uint64_t)lim[2] << 40) | ((uint64_t)lim[3] << 32) |
        ((uint64_t)lim[4] << 24) | ((uint64_t)lim[5] << 16) |
        ((uint64_t)lim[6] << 8)  | ((uint64_t)lim[7]);

    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native amount only");
    /* ---- PLANTED BUG: 32-bit truncated compare lets a high-bits-set amount through. ---- */
    XAHC_REQUIRE((uint32_t)drops <= (uint32_t)limit, "over per-tx spend limit");

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

    XAHC_ACCEPT("within policy");
    return 0;
}
