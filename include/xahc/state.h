/**
 * xahc/state.h — typed hook-state get/set with checked returns.
 *
 * Hook state is a tiny key->value store on the account. Raw API hands you
 * bytes and unchecked lengths; these helpers do the (ptr,len) bookkeeping and
 * rollback on host error.
 */
#ifndef XAHC_STATE_H
#define XAHC_STATE_H 1

#include <stdint.h>
#include "check.h"

extern int64_t state(uint32_t write_ptr, uint32_t write_len, uint32_t kread_ptr, uint32_t kread_len);
extern int64_t state_set(uint32_t read_ptr, uint32_t read_len, uint32_t kread_ptr, uint32_t kread_len);

/* Set value buffer `v` under key buffer `k`, or rollback. */
#define XAHC_STATE_SET(k, v) \
    XAHC_TRY(state_set(XAHC_SBUF(v), XAHC_SBUF(k)))

/* Get into value buffer `v` under key buffer `k`. Returns bytes read (>=0),
 * or a negative host code if the key is absent (does NOT rollback — absence is
 * often expected). Use XAHC_STATE_GET_OR for a default. */
#define XAHC_STATE_GET(k, v) \
    state(XAHC_SBUF(v), XAHC_SBUF(k))

/* Get a uint64 under key `k`; if absent, yield `dflt`. */
static inline uint64_t xahc_state_u64(const uint8_t* k, uint32_t klen, uint64_t dflt) {
    uint8_t buf[8];
    int64_t rc = state((uint32_t)buf, sizeof(buf), (uint32_t)k, klen);
    if (rc != 8) return dflt;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | buf[i];
    return v;
}

#endif /* XAHC_STATE_H */
