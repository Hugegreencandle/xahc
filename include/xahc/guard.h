/**
 * xahc/guard.h — auto-numbered guards.
 *
 * The footgun this removes:
 *   Stock hook-macros require GUARDM(maxiter, n) where `n` is a hand-assigned
 *   unique integer per guard site (to disambiguate guards that collapse to the
 *   same __LINE__). Assign two the same number -> guard violation -> hook
 *   rejected at runtime. Easy to get wrong, painful to debug.
 *
 * The fix:
 *   __COUNTER__ yields a globally-unique compile-time integer per expansion.
 *   You never assign IDs again. Just state the max iterations.
 *
 * Guard budget semantics (read this):
 *   _g's second argument is the maximum number of times that guard point may be
 *   crossed across the ENTIRE hook invocation — not per loop-entry. For nested
 *   loops the inner guard must budget outer*inner. XAHC_GUARD_NESTED makes that
 *   contract explicit and checked by the compiler.
 */
#ifndef XAHC_GUARD_H
#define XAHC_GUARD_H 1

#include <stdint.h>

/* Provided by xahaud. Must be imported by every hook. */
extern int32_t _g(uint32_t id, uint32_t maxiter);

/* Single loop. `maxiter` = max iterations of THIS loop per hook call. */
#define XAHC_GUARD(maxiter) \
    _g((1ULL << 31U) + ((uint32_t)__COUNTER__ + 1U), (uint32_t)(maxiter) + 1U)

/* Nested loop. Budget = outer_iters * inner_iters (total crossings). */
#define XAHC_GUARD_NESTED(inner_iters, outer_iters) \
    XAHC_GUARD((uint32_t)(inner_iters) * (uint32_t)(outer_iters))

/* Every hook MUST import `_g` or it is rejected on-chain — even a hook with no
 * loops. Put XAHC_HOOK_ENTRY() as the first statement of hook() to guarantee
 * the import and a single guarded entry. */
#define XAHC_HOOK_ENTRY() ((void)_g((1ULL << 31U) + ((uint32_t)__COUNTER__ + 1U), 1U))

#endif /* XAHC_GUARD_H */
