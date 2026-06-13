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

    /* Read the amount field (native drops: 8-byte serialized amount). */
    uint8_t amt[8];
    XAHC_REQUIRE(otxn_field(XAHC_SBUF(amt), sfAmount) == 8, "amount read");

    /* Decode native drops (clear the sign/native flag bits in byte 0). */
    uint64_t drops = ((uint64_t)(amt[0] & 0x3F) << 56) |
                     ((uint64_t)amt[1] << 48) | ((uint64_t)amt[2] << 40) |
                     ((uint64_t)amt[3] << 32) | ((uint64_t)amt[4] << 24) |
                     ((uint64_t)amt[5] << 16) | ((uint64_t)amt[6] << 8) |
                     ((uint64_t)amt[7]);

    XAHC_REQUIRE(drops >= MIN_DROPS, "below minimum");
    XAHC_ACCEPT("ok");
    return 0;
}
