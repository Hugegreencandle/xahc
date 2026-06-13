#include "xahc/xahc.h"

/* Agent spending guardrail — install on an autonomous agent's account.
 *
 * Enforces, at layer 1, limits an off-chain agent must not exceed:
 *   HookParameter "LIM" (8 bytes, big-endian drops)  REQUIRED — max per-tx spend
 *   HookParameter "DST" (20-byte account-id)          OPTIONAL — lock outgoing to one dest
 *
 * Policies OUTGOING Payments from this account; passes everything else.
 * Pairs with x402/agentic payments: the agent signs payments off-chain, this
 * Hook bounds them on-chain (see docs/X402-XAHAU.md). */

int64_t cbak(uint32_t reserved) { return 0; }

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

    /* Per-tx spend cap from hook parameter LIM (8-byte drops). */
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
    XAHC_REQUIRE((uint64_t)drops <= limit, "over per-tx spend limit");

    /* Optional destination lock from hook parameter DST (20-byte account-id). */
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

    XAHC_ACCEPT("within policy");
    return 0;
}
