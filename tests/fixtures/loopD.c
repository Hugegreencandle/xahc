#include "xahc/xahc.h"
int64_t cbak(uint32_t r) { return 0; }
int64_t hook(uint32_t r) {
    XAHC_HOOK_ENTRY();
    uint8_t a[20], b[20];
    XAHC_OTXN_ACCOUNT(a); hook_account(XAHC_SBUF(b));
    int same = 1;
    /* loopA's condition-guard KEPT, plus a guard first in the body */
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i) {
        XAHC_GUARD(20);
        if (a[i] != b[i]) same = 0;
    }
    if (same) XAHC_ACCEPT("owner");
    XAHC_ACCEPT("other");
    return 0;
}
