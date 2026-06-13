/* big_stack.c — intentionally allocates a 90 KB stack buffer (> the ~64 KB
 * wasm stack). Hooks have no heap; this overflows into data/heap at runtime.
 * Expect: lint warns "stack may overflow". Builds fine (the overflow is runtime).
 */
#include "xahc/xahc.h"

int64_t cbak(uint32_t r) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    int n = (int)(ledger_seq() & 0x7);
    volatile uint8_t buf[90000];              /* >64KB stack frame */
    for (int i = 0; XAHC_GUARD(90001), i < 90000; ++i)
        buf[i] = (uint8_t)i;
    accept(0, 0, buf[n]);
    return 0;
}
