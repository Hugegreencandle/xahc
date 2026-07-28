# KNOWN ISSUE — a guard in the `for` condition ships a module the ledger rejects

**Found 2026-07-29 on Xahau testnet.** Severity: HIGH. A hook can pass `xahc build` completely
clean and be **uninstallable** — `SetHook` returns `temMALFORMED`.

## Reproducer

Two hooks, identical except for where the guard sits:

```c
/* loopA — REJECTED by SetHook (temMALFORMED) */
for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
    if (a[i] != b[i]) same = 0;

/* loopB — installs fine (tesSUCCESS) */
for (int i = 0; i < 20; ++i) {
    XAHC_GUARD(20);
    if (a[i] != b[i]) same = 0;
}
```

`xahc build` output is **byte-for-byte the same reassurance for both**:

```
clean stripped 1 stray export(s)
lint  no issues
built /tmp/lA.wasm
```

No `guard repositioned`, no `warn`, no error. Verified on testnet: loopA `temMALFORMED`, loopB
installs.

## Why this is a real defect, not a missing lint

`crates/xahc-cli/src/guardpass.rs` exists **precisely** to stop this. Its own doc comment says
clang's loop rotation moves the guard to the bottom of the loop, "violates the rule and gets the
hook rejected (temMALFORMED) even though it is guarded", and that mispositioned guards are
"surfaced so it isn't silent."

For the condition-placed guard it surfaces nothing. `build.rs:70-82` does wire
`repositioned` / `unguarded_loops` / `skipped` to output, so the pass is reporting **zero of each**
— it believes there is nothing to fix. The guard compiled into the loop's condition/continue block
rather than the body head, and the pass neither hoisted it nor counted it as skipped.

## Impact

Any hook with a guard written in the `for` condition ships broken and is only discovered at
deployment. Both dead-man fixtures in `xahc-prover` carried this form and **neither had ever been
deployed** — sibling hooks (`subscription_ok`, `rate_limit_ok`) install only because they contain
no loops at all, so nothing exercised the validator. It also means one of the "6 certified
primitives" was proved seven ways while being uninstallable.

## Fix direction (NOT yet implemented)

`reposition()` must recognise a guard block anywhere in the loop's instruction sequences — not only
the body head — and either hoist it or count it in `skipped`. Failing to find a guard in a loop that
has one must never report clean. **Fail closed: if the pass cannot prove the guard is at the loop
head, it must warn.** Today an unrecognised shape is indistinguishable from a correct one.

## Related

`xahc-prover/docs/DEADMAN_TESTNET_SMOKE_2026-07-29.md` (testnet bisect).
