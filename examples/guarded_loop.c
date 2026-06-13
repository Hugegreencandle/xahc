/* guarded_loop.c — a correctly guarded loop. Expect: lint clean.
 * The per-iteration trace_num() is a host side effect, so -O2 cannot fold the
 * loop away (unlike a pure accumulation). */
#include "xahc/xahc.h"

extern int64_t trace_num(uint32_t read_ptr, uint32_t read_len, int64_t number);

int64_t cbak(uint32_t r) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    int n = (int)(ledger_seq() & 0x0F);   /* runtime bound */
    for (int i = 0; XAHC_GUARD(16), i < n; ++i)
        trace_num(0, 0, i);
    accept(0, 0, 0);
    return 0;
}
