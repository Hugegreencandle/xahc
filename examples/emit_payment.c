/* emit_payment.c — on any incoming Payment, emit a fixed 1 XAH payment to a
 * known destination, then accept. Exercises emit/payment.h end-to-end so the
 * serialized blob can be verified against xahau-mcp's chain-validated codec.
 *
 * Destination below is the all-0xBB test account (20 bytes). The hook account
 * (source) is mocked as all-0xAA by the simulator.
 */
#include "xahc/xahc.h"

#define EMIT_DROPS 1000000ULL  /* 1 XAH */

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    if (otxn_type() != XAHC_ttPAYMENT)
        XAHC_ACCEPT("not a payment");

    uint8_t dest[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
        dest[i] = 0xBB;

    XAHC_EMIT_PAYMENT(dest, EMIT_DROPS, 0, 0);

    XAHC_ACCEPT("emitted");
    return 0;
}
