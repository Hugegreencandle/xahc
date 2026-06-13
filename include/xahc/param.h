/**
 * xahc/param.h — typed access to hook parameters and otxn parameters.
 *
 * Hook parameters are install-time config baked into the SetHook (HookParameters).
 * otxn parameters ride on the triggering transaction. Both are key->blob lookups;
 * these wrappers do the (ptr,len) bookkeeping and return the byte count.
 */
#ifndef XAHC_PARAM_H
#define XAHC_PARAM_H 1

#include <stdint.h>
#include "check.h"

extern int64_t hook_param(uint32_t write_ptr, uint32_t write_len,
                          uint32_t read_ptr, uint32_t read_len);
extern int64_t otxn_param(uint32_t write_ptr, uint32_t write_len,
                          uint32_t read_ptr, uint32_t read_len);

/* Read install-time hook parameter `key` (buffer) into `out` (buffer).
 * Returns bytes read (>=0), or negative if absent. Does NOT rollback — a
 * missing optional parameter is often expected; check the return. */
#define XAHC_HOOK_PARAM(out, key) \
    hook_param(XAHC_SBUF(out), XAHC_SBUF(key))

/* Read transaction parameter `key` into `out`. Returns bytes read or negative. */
#define XAHC_OTXN_PARAM(out, key) \
    otxn_param(XAHC_SBUF(out), XAHC_SBUF(key))

/* Require a hook parameter of an exact expected length, or rollback. */
#define XAHC_HOOK_PARAM_REQUIRE(out, key, expect_len) \
    XAHC_REQUIRE(hook_param(XAHC_SBUF(out), XAHC_SBUF(key)) == (expect_len), "missing hook param")

#endif /* XAHC_PARAM_H */
