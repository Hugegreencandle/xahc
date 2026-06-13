/**
 * firewall.c — block incoming payments below a threshold, using xahc.
 *
 * Demonstrates: auto-guards, checked otxn reads, checked accept/rollback.
 * Build:  xahc build examples/firewall.c -o firewall.wasm
 */
#include "xahc/xahc.h"

#define MIN_DROPS 10000000ULL /* 10 XAH */

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY(); /* mandatory: imports _g, single guarded entry */

    /* Only police Payment transactions. */
    if (otxn_type() != XAHC_ttPAYMENT)
        XAHC_ACCEPT("not a payment");

    /* Native XAH amount in drops (helper handles the 8-byte STAmount decode). */
    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native amount read");
    XAHC_REQUIRE(drops >= (int64_t)MIN_DROPS, "below minimum");
    XAHC_ACCEPT("ok");
    return 0;
}
