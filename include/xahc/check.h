/**
 * xahc/check.h — checked return codes.
 *
 * The footgun this removes:
 *   Every Hook API returns a signed int; negative == error. Stock style lets
 *   you ignore that return and sail past a failed otxn_field / state read with
 *   garbage in your buffer. XAHC_TRY makes the failure stop the hook.
 */
#ifndef XAHC_CHECK_H
#define XAHC_CHECK_H 1

#include <stdint.h>

extern int64_t accept(uint32_t read_ptr, uint32_t read_len, int64_t error_code);
extern int64_t rollback(uint32_t read_ptr, uint32_t read_len, int64_t error_code);

/* (ptr,len) helper for a stack object/string literal. */
#define XAHC_SBUF(x) (uint32_t)(x), sizeof(x)

/* Evaluate expr; if it returns negative, rollback with the line number.
 * Returns the (non-negative) value otherwise. Statement-expression (GNU C / clang). */
#define XAHC_TRY(expr) ({                       \
    int64_t _xahc_rc = (int64_t)(expr);         \
    if (_xahc_rc < 0)                           \
        rollback(0, 0, (int64_t)__LINE__);      \
    _xahc_rc;                                    \
})

/* Require a condition or rollback with a message string. */
#define XAHC_REQUIRE(cond, msg)                            \
    do {                                                   \
        if (!(cond))                                       \
            rollback((uint32_t)(msg), sizeof(msg),         \
                     (int64_t)__LINE__);                   \
    } while (0)

/* Terminal helpers. */
#define XAHC_ACCEPT(msg)  accept((uint32_t)(msg), sizeof(msg), (int64_t)__LINE__)
#define XAHC_DONE()       accept(0, 0, (int64_t)__LINE__)

#endif /* XAHC_CHECK_H */
