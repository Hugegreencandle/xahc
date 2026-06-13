/* over_budget.c — a loop guarded with too small a budget. Lint is clean (it HAS
 * a guard), but at runtime the guard is crossed more times than its maxiter, so
 * the on-chain validator (and now `xahc sim`/`xahc test`) reject it.
 * Expect: GUARD_VIOLATION. The per-iteration trace_num() is a host side effect so
 * the loop is not folded away. */
#include "xahc/xahc.h"

extern int64_t trace_num(uint32_t read_ptr, uint32_t read_len, int64_t number);

int64_t cbak(uint32_t r) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    /* XAHC_GUARD(3) allows 3 iterations; this loop wants 10 -> guard violation. */
    for (int i = 0; XAHC_GUARD(3), i < 10; ++i)
        trace_num(0, 0, i);
    accept(0, 0, 0);
    return 0;
}
