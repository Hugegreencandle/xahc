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
 * WHERE THE GUARD GOES (read this first):
 *   The guard must be the FIRST STATEMENT INSIDE the loop body. xahaud checks
 *   for the guard's literal BYTES immediately after the `loop` opcode
 *   (Guard.h:386); anything else is temMALFORMED at SetHook. Writing the guard
 *   in the `for` CONDITION lets clang hoist it out of the body, and whether it
 *   does depends on the body — so the condition form installs sometimes and is
 *   rejected other times, from source that looks identical.
 *
 *       for (int i = 0; i < N; ++i) { XAHC_GUARD(N); ... }   // correct
 *       for (int i = 0; XAHC_GUARD(N), i < N; ++i) ...       // may be REJECTED
 *
 *   `xahc build` verifies this on the emitted module and fails closed. Full
 *   write-up in docs/GUARD_PLACEMENT.md.
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

/* Single loop. `maxiter` = max iterations of THIS loop's body per hook call.
 * XAHC_GUARD(N) budgets a body that runs up to N times; the body running N+1 times
 * is a guard violation.
 *
 * The `+1` was written for a guard in the `for` CONDITION, which is crossed N+1
 * times (the final crossing being the check that ends the loop). A guard at the
 * head of the body — the only correct placement, see above — is crossed exactly
 * N times, so the `+1` is one spare crossing rather than a requirement. It is
 * kept: over-budgeting is safe, under-budgeting is a runtime GUARD_VIOLATION,
 * and this macro cannot see which form the caller wrote. */
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
