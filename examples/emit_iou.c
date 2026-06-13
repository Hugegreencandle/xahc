/* emit_iou.c — on any incoming Payment, emit 1.5 USD (issued amount) to a known
 * destination. Exercises emit/payment.h's IOU builder + the float_sto host fn.
 *
 * Currency : "USD" (standard 20-byte code, ASCII at bytes 12..14)
 * Issuer   : 0xCC * 20
 * Dest     : 0xBB * 20
 * Value    : 1.5  -> float_set(-1, 15)  (15 x 10^-1)
 *
 * Note: this hook CANNOT run in `xahc sim` (no XFL host fns there). Run it in
 * xahau-mcp's VM (execute_hook), which models the full float API.
 */
#include "xahc/xahc.h"

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    if (otxn_type() != XAHC_ttPAYMENT)
        XAHC_ACCEPT("not a payment");

    uint8_t cur[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) cur[i] = 0;
    cur[12] = 'U'; cur[13] = 'S'; cur[14] = 'D';

    uint8_t iss[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) iss[i] = 0xCC;

    uint8_t dst[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) dst[i] = 0xBB;

    int64_t xfl = float_set(-1, 15);   /* 1.5 */

    XAHC_EMIT_PAYMENT_IOU(dst, xfl, cur, iss, 0, 0);

    XAHC_ACCEPT("emitted iou");
    return 0;
}
