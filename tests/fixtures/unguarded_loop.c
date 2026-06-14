/* unguarded_loop.c — a loop with NO guard. Expect: lint warns (on-chain reject).
 * Per-iteration trace_num() keeps the loop alive through -O2. */
#include "xahc/xahc.h"

extern int64_t trace_num(uint32_t read_ptr, uint32_t read_len, int64_t number);

int64_t cbak(uint32_t r) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    int n = (int)(ledger_seq() & 0x0F);   /* runtime bound */
    for (int i = 0; i < n; ++i)           /* <-- missing XAHC_GUARD */
        trace_num(0, 0, i);
    accept(0, 0, 0);
    return 0;
}
