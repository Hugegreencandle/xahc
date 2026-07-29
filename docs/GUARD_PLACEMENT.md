# Guard placement — why the guard must be the first statement inside the loop body

**Status: root-caused and enforced.** `xahc build` fails closed on this since 1.11.0. This file was
previously `KNOWN_ISSUE_guard_in_condition.md`, which described the symptom and explicitly withdrew
its explanation as unproven. The mechanism below replaced it on 2026-07-29 and is confirmed against
the ledger.

## The rule

Write the guard as the **first statement inside the loop body**:

```c
for (int i = 0; i < N; ++i) {
    XAHC_GUARD(N);          /* correct — installs */
    ...
}

for (int i = 0; XAHC_GUARD(N), i < N; ++i)  /* may be REJECTED by SetHook */
    ...
```

## Why — xahaud checks BYTES, not reachability

`xahaud include/xrpl/hook/Guard.h:386-390`, walking the emitted wasm:

```c
// first i32
REQUIRE(1);
if (wasm[i] != 0x41U)
    GUARD_ERROR("Missing first i32.const after loop instruction");
```

Immediately after every `loop` opcode and its blocktype byte, xahaud requires the literal sequence

```
0x41 <sleb guard id> 0x41 <uleb maxiter> 0x10 <uleb index of _g>
```

Anything else → `validateGuards` returns nullopt → `SetHook.cpp:586` → preflight fails →
**temMALFORMED**. The check is unconditional across hook rule versions. It is a **syntactic**
property of the emitted bytes, not a semantic property of the program.

A guard written in the `for` condition *is* reachable before anything else in the loop — only loads
precede it — so every reachability-based check passes. But clang is free to rotate the loop and
hoist the guard call out of the body, and when it does, the bytes after `loop` are `20 00 20 01 6a…`
(local.get) instead of the required `41 …`. The source says guarded; the module the ledger sees is
not.

Observed byte sequences after the `03 40` (`loop`, blocktype void):

```
rejected:  20 00 20 01 6a …                      local.get / local.get / i32.add
accepted:  41 82 80 80 80 78 41 15 10 00         i32.const / i32.const / call _g
```

## The condition form is a coin flip, not a consistent failure

It is not the case that the condition form always breaks. Across `examples/` before the fix, six
hooks using it were rejected and five using the **identical idiom** built to adjacent bytes and
installed. Whether clang hoists depends on the loop body, so no source-level rule can tell you which
one you have. That is the entire reason the check operates on the emitted module.

## Evidence — 4/4 predicted from the bytes, then confirmed on testnet

Predictions were recorded from the emitted bytes *before* submitting anything.

| fixture | guard position | predicted | `SetHook` |
|---------|----------------|-----------|-----------|
| `loopA` | in the `for` condition | reject | **temMALFORMED** |
| `loopB` | first inside the body | install | **tesSUCCESS** |
| `loopC` | last inside the body | reject | **temMALFORMED** |
| `loopD` | `loopA`'s condition guard **plus** a body-head guard | install | **tesSUCCESS** |

`loopD` is the decisive one. It is byte-identical to `loopA` in imports, exports, types and section
layout, and it still carries the hoisted condition guard — the only difference is that adjacent
bytes now exist after `loop`. It installs. So the discriminator is adjacency: not reachability, not
the presence of a condition-form guard, and nothing about the loop's semantics.

`loopC` rules out "reachable at all from the loop header": a guard at the bottom of the body is
crossed on every iteration and is still rejected.

Sources: `tests/fixtures/loop{A,B,C,D}.c`, also kept in `xahc-prover/hooks/`.

## What xahc does about it

`crates/xahc-cli/src/guardpass.rs::verify_byte_adjacency` decodes the **emitted** module with
wasmparser and, for every `loop`, requires the next three operators to be `i32.const`, `i32.const`,
`call <_g>`. It derives `_g`'s function index from the emitted import section rather than trusting
walrus's numbering, returns no findings when the module imports no guard at all, and **fails closed
if the module cannot be decoded** — an undecodable module is never "fine". `build.rs` turns any
finding into a build error naming the function, the byte offset, and the operator found instead.

The older `reposition` / `guard_already_first` passes reason about reachability and are kept as a
first line of reporting, but they are not what makes the build safe. Reachability was the wrong
property: `loopA` satisfies it and the ledger refuses the module anyway.

## Impact while this was silent

Every affected hook was uninstallable while every tool reported it clean. `escrow_ok` (1 loop) and
`multisig_ok` (4 loops) in `xahc-prover` used the condition form and had never been deployed; the
sibling hooks that did deploy (`subscription_ok`, `rate_limit_ok`) install only because they contain
no loops, so nothing exercised the validator. Both dead-man fixtures carried the same form. One of
the "6 certified primitives" had been proved seven ways while being impossible to install.

**PROVEN ≠ INSTALLABLE ≠ INVOKED ≠ RUNS.** A proof binds the semantics of the module; it says
nothing about whether the ledger will accept its bytes.

## Guard budget, with a body-head guard

`XAHC_GUARD(N)` passes `N + 1` to `_g`. The `+1` was written to absorb the trailing condition
crossing of an N-iteration `for` loop, which is what the condition form produces. A guard at the
head of the body is crossed exactly N times, so the `+1` is now one spare crossing rather than a
requirement. It is retained: over-budgeting a guard is safe, under-budgeting is a runtime
`GUARD_VIOLATION`, and the macro cannot know which form the caller used.

## Related

- `xahc-prover/docs/DEADMAN_TESTNET_SMOKE_2026-07-29.md` — the testnet bisect this came out of.
- `CHANGELOG.md` [1.11.0].
