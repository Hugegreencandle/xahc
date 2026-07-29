# Changelog

All notable changes to xahc are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

## [1.11.2] - 2026-07-29

Adds the check that would have caught the 1.11.1 defect before it reached a ledger.

### Added

- **`CALL_USER_FUNCTION` — lint and build now reject a hook that calls a function it defines
  itself.** xahaud allows a hook to call **only imported host functions**: `Guard.h:495-509`
  refuses any `call` whose callee index exceeds the last import, which fails `validateGuards` and
  returns `temMALFORMED` at `SetHook`. Until now nothing local caught it, so a module could pass
  every check here and be refused on-chain.

  This is an **optimiser-level** defect, which is what makes it worth a rule. `static inline` is a
  hint clang may decline for a large function once there is more than one call site, so the same C
  source compiles to an installable hook with one emit and an uninstallable one with two. Nothing
  in the source shows it; only the emitted module does. 1.11.1 fixed the shipped headers — this
  catches the same shape in anyone's own helpers.

  `CALL_CHECK_UNDECIDABLE` is reported if the module cannot be decoded. Fails closed: an
  undecodable module is never "fine".

- Five regression tests over `verify_no_user_calls`, in WAT so they test the pass rather than
  clang's inlining decisions: a call to a module-defined function is flagged; calls to imports are
  not; all offending calls are reported rather than the first; a helper that is defined but never
  *called* is legal, since only calls are rejected; and an undecodable module errors.

Verified against the real artifact: the pre-1.11.1 `revenue_split_ok`, which returned
`temMALFORMED` on testnet, is flagged with both of its calls at the right offsets; the fixed build
and the other primitives are clean; all eleven examples still build.

## [1.11.1] - 2026-07-29

**If your hook emits more than once, rebuild it — it could not be installed.** A hook that calls a
function it defines itself is rejected by `SetHook` with `temMALFORMED`, and the emit builders in
these headers were being compiled into exactly that.

### Fixed

- **Every hook emitting more than once was uninstallable (CRITICAL).** `xahc_build_payment` and
  `xahc_build_payment_iou` were declared `static inline`, which at `-Oz` is a hint clang is free to
  decline — and it does decline for a function this size once there is **more than one call site**.
  The helper was then emitted as a real function and the hook called it, which xahaud forbids:
  `Guard.h:495-509` rejects any `call` whose callee index exceeds the last import, because a hook
  may only call imported host functions. Now `__attribute__((always_inline))`, which is a
  requirement rather than a hint.

  Hooks with a single emit inlined the helper and installed normally, which is why this went
  unnoticed. Verified against two multi-emit hooks that were `temMALFORMED` before the change and
  install (`tesSUCCESS`) after, with no change to single-emit bytecode.

  `xahc_otxn_drops` and `xahc_state_u64` get the same treatment. They are small enough to have been
  inlined in practice, but "in practice" is what failed here.

### Note for anyone upgrading

The version bump matters. Headers are extracted to `~/.cache/xahc/v<version>/include` and only when
that directory does not already exist, so a fix to a header does not reach an existing install until
the version changes. `XAHC_INCLUDE` overrides the cache when developing against a working tree.

### Known gap

`xahc lint` does not yet flag a call to a user-defined function. It catches guard byte-adjacency
(1.11.0) but not this, so a module can still pass every local check and be refused on-chain. The
check is cheap and local: for each `0x10` call opcode, compare the callee index against the import
count.

## [1.11.0] - 2026-07-29

**If you have ever built a hook containing a loop, rebuild it and check it still builds.** A hook
could pass `xahc build` completely clean and be **impossible to install** — `SetHook` returns
`temMALFORMED`. Six of this repo's own eleven examples were in that state. If your hook builds
clean on 1.11.0 it was never affected; if it now fails, it could never have been deployed and the
error says exactly which loop to fix.

### Fixed

- **Guard placement is now verified on the emitted bytes (CRITICAL).** xahaud requires the guard's
  literal bytes — `0x41 <id> 0x41 <maxiter> 0x10 <_g>` — immediately after every `loop` opcode and
  its blocktype byte (`Guard.h:386-390`). Anything else fails `validateGuards`, then `SetHook.cpp`
  preflight, then **temMALFORMED**. Every check `guardpass` had reasoned about **reachability**
  instead, which is a strictly weaker and different property: a guard written in the `for` condition
  *is* reachable before anything else in the loop, so it passed, while clang hoisted it out of the
  body so the bytes were not adjacent and the ledger refused the module. `verify_byte_adjacency`
  decodes the module xahc is about to write and checks the property the ledger actually checks. It
  derives `_g`'s index from the emitted import section rather than trusting walrus's numbering, and
  **fails closed on a module it cannot decode**.

- **Six of eleven shipped examples were never installable.** `agent_guardrail`,
  `agent_guardrail_stateful`, `big_stack` and the three planted-bug twins all failed the new check.
  The other five used the **identical** source idiom and built to adjacent bytes. Same form,
  opposite verdict — whether clang hoists depends on the loop body, so the condition form cannot be
  judged from the source, which is why the check has to run on the emitted module. Every loop in
  `examples/` is now written with the guard first inside the body.

- **`xahc new` no longer teaches the fragile idiom.** Both scaffold templates used the condition
  form. The emitter archetype happened to build to adjacent bytes, so scaffolded hooks were not
  broken — but every new user was handed the form that broke six of ours.

- **The reported function index skipped no imports.** `verify_byte_adjacency` numbered code-section
  entries from 0, so every finding was reported as `func[0]` regardless of which function it was in.

### Added

- `docs/GUARD_PLACEMENT.md` — the rule, the mechanism with the xahaud source, the byte sequences,
  and the four-fixture evidence. Replaces `docs/KNOWN_ISSUE_guard_in_condition.md`.
- `tests/fixtures/loop{A,B,C,D}.c` — the four hooks that root-caused this, differing only in guard
  position, each with its testnet verdict predicted from the bytes beforehand (4/4 correct).
  `loopD` is the decisive one: it keeps loopA's hoisted guard, adds a body-head guard, and installs.
- Eleven regression tests over `verify_byte_adjacency`, written in WAT so they test this pass rather
  than clang's optimiser.

### Changed

- `include/xahc/guard.h` documents where the guard goes, ahead of the budget semantics. Its `+1`
  rationale is corrected: it described the trailing crossing of a **condition-placed** guard, i.e.
  it justified the macro by the placement this release rejects. A body-head guard is crossed exactly
  N times. The `+1` remains as spare headroom.

### Note on 1.10.0

1.10.0 was never tagged or released; its entry below stands as part of this release. Its "Known
issues" section described the guard defect as reproducible but unexplained, which was accurate when
written and is superseded by the root cause above.

## [1.10.0] - 2026-07-29

**If you emit from a hook, upgrade.** `XAHC_EMIT_PAYMENT` and `XAHC_EMIT_PAYMENT_IOU` could never
emit. Any hook built with them silently failed to send its payment on-ledger.

### Fixed

- **`XAHC_EMIT_PAYMENT` / `_IOU` could NEVER emit (CRITICAL).** Both macros called
  `emit(0, 0, ...)`. xahaud requires a **≥32-byte write buffer** for the emitted-transaction hash
  (`applyHook.cpp`: `if (write_len < 32) return TOO_SMALL;`), so every emit returned `TOO_SMALL` and
  the hook rolled back. `XAHC_TRY` reported a **line number** rather than the errno, so the failure
  looked like a fault in the payment builder — which is why it went unnoticed. The macros now pass a
  real `uint8_t _xahc_emithash[32]`; that hash is useful in its own right, since a `cbak` uses it to
  identify the transaction it is settling.

- **Emit buffers were 22 bytes too small for any hook exporting `cbak` (CRITICAL).**
  `etxn_details` requires `write_len >= 138` when the hook has a callback and 116 when it does not.
  `XAHC_PAYMENT_SIZE` was 248 and the builder writes a 132-byte prefix, leaving exactly 116 —
  correct for a no-callback hook with **zero margin**, and 22 short for a `cbak` one. Sized for the
  worst case: `XAHC_PAYMENT_SIZE` 248 → **270**, `XAHC_PAYMENT_IOU_SIZE` 288 → **310**. The
  constraint was already documented in the IOU variant's comment and nothing enforced it; the
  compiler cannot check a comment, so it is enforced by size now.

- **`etxn_reserve`'s return is now checked** in both macros. It was called bare, so a failed
  reservation was swallowed and resurfaced later as a rollback inside the builder, pointing at the
  wrong call entirely.

- **`guardpass` now fails closed.** `guard_already_first` descended into a leading `block` and
  blessed any guard found there, and `build.rs` never reported that path — so an unrecognised guard
  shape was indistinguishable from a correct one, in the one tool whose job is to stop you shipping
  a module the ledger rejects. Placement that cannot be **proved** is now a build error.

### Known issues

- A reproducible case where two hooks differing only in guard placement get opposite `SetHook`
  verdicts while `xahc build` calls both clean. The reproducer is real; the explanation for it was
  withdrawn as unproven. **Root-caused and fixed in 1.11.0 — see `docs/GUARD_PLACEMENT.md`.**

### Verified

All fixes confirmed on Xahau testnet, not just by inspection: an unmodified dead-man-switch hook
running its full lifecycle (arm → pending → release), emitting exactly one payment of the configured
amount, with the two-phase grace gate observed on-chain.

## [1.9.2] - 2026-06-14

### Added
- Expose the IOU spend-limit invariant via `xahc prove --invariant limit-iou`
  (driver `prove_limit_iou.py` in xahc-prover). Canonical kebab name; help text and
  CLAUDE.md invariant list updated to the full set (limit · guardrail · termination ·
  monotonic · nospend · conservation · limit-iou · authz · validate · overflow).

## [1.9.1] - 2026-06-14

`xahc prove` CLI integration fixes (residual audit LOW/MED items; the Rust glue
stays exit-code-only with no shell injection).

### Fixed
- **Temp `.wasm` leak + predictable name on `prove <file>.c` (LOW).** Building a
  `.c` input to a temp `.wasm` used a PID-based name (`xahc_prove_<pid>.wasm`,
  predictable/reused) and never deleted the file. The temp name now mixes PID, a
  nanosecond timestamp, and an atomic sequence counter, and an RAII drop-guard
  removes the file on every exit path — prover success, disprove, or an early
  `?`-error (build/spawn failure). No new dependency added.

### Added
- **`prove` honors `--json` (MEDIUM).** `xahc --json prove` previously emitted only
  the prover's human prose despite the global `--json` contract. It now also prints
  a stable `{invariant, input, verdict, exit_code}` envelope, with `verdict`
  derived from the prover exit code (`0`=proven, `2`=counterexample,
  `3`=inconclusive, else `error`). The human (non-`--json`) path is unchanged.

### Docs
- **`prove` prover discovery (informational).** `prover_dir()` now documents that
  the resolved checkout is executed as trusted code and that `XAHC_PROVER_DIR`
  should be set explicitly in CI / untrusted working directories so a stray
  sibling/cwd `xahc-prover` cannot be auto-discovered and run.

## [1.9.0] - 2026-06-14

Audit fixes — guard-lint false-positive, doc/severity-claim accuracy, and
verify/test hardening.

### Fixed
- **Positional guard no longer false-flags a nested-but-first `_g` (HIGH).** The
  loop guard check (`lint::loop_guard_pos`) and the guard-reposition pass
  (`guardpass::hoist_guard_in_seq`) only inspected a loop body's TOP-LEVEL
  instruction sequence, so a `_g` call inside a leading `block` — a shape clang
  `-O2` emits, e.g. `(loop (block (call _g) ...))` — was wrongly reported
  `UNGUARDED_LOOP` / `GUARD_NOT_FIRST`, blocking a VALID hook. lint now descends
  in **execution order** through any leading UNCONDITIONAL `block` (always
  entered) to find the genuinely-first guard-relevant instruction, mirroring
  xahaud's flattened-stream view. **Conservative by design:** it does NOT descend
  into `if`/`else` or a nested `loop` (execution can skip a conditional branch) —
  a `_g` reachable only inside one `if` branch is STILL flagged. This preserves
  the safety invariant that an unguarded loop is never accepted (a false-negative
  would ship a `temMALFORMED` hook on-chain). guardpass mirrors the same descent
  so it recognizes an already-correct nested guard instead of churning it. New
  WAT tests cover: nested-block guard (not flagged), truly-unguarded loop (still
  flagged), conditional-only guard (still flagged), branchless-block-then-guard
  (compliant).
- **`NO_EXIT_PATH` message/severity claims corrected (HIGH).** The rule stays a
  `warn`, but its message and the surrounding comments no longer assert as fact
  that "xahaud does not reject" a hook importing neither `accept` nor `rollback`
  — that on-chain behavior is **not** independently confirmed in this repo. The
  rule now reads as a strong-but-unverified warning. The README and the lint
  section header no longer claim xahc "mirrors the analyzer, so author and verify
  sides agree": the rule sets OVERLAP but differ in id and/or severity (xahc's
  `NO_EXIT_PATH` is `warn`; the MCP's `HOOK-001` is CRITICAL).
- **Rule-id crosswalk accuracy (MEDIUM).** The `~ HOOK-00X` crosswalk comments are
  now marked **approximate** (ids and/or semantics differ), `STATE_FOREIGN_WRITE`
  is documented as xahc-specific (no dedicated MCP foreign-write rule), and the
  `Finding` doc-comment now describes the ids as **xahc-stable** rather than an
  MCP-parity "compatibility contract".
- **`verify` and `test` resolve tx-types from the canonical table (MEDIUM).**
  `installtx::TX_TYPES` (the full 47-type table) is now `pub`, with a shared
  `resolve_tx_type`. `verify` resolves its local-sim number AND the canonical name
  it forwards to the remote VM from that one table (was a partial, divergent
  16-entry table that could send a name the local side couldn't map). `xahc test`
  now validates each case's `tt` against the same table (rejects unknown numerics),
  matching install-tx's `parse_types`.
- **`verify` requires an http(s) scheme on the remote URL (MEDIUM, SSRF surface).**
  `--remote` / `XAHC_SIM_URL` must start with `http://` or `https://`; otherwise
  it errors instead of attempting an ambiguous request.
- **`build` gives a wasm32-specific hint when clang fails (LOW).** A failed bare
  `clang` invocation now explains the likely cause (Apple's system clang lacks the
  wasm32 target) and how to install a wasm-capable clang (brew llvm), instead of a
  bare "clang failed".

### TODO
- **Confirm the no-exit on-chain behavior on testnet.** Whether xahaud rejects a
  hook importing neither `accept` nor `rollback` (temMALFORMED) or accepts the
  `RETURNED` outcome is not yet independently verified. Once confirmed, align the
  `NO_EXIT_PATH` severity here with xahau-mcp's `HOOK-001` and update both repos.

## [1.8.1] - 2026-06-14

Post-release audit fix.

### Changed
- **`NO_EXIT_PATH` downgraded from `error` to `warn`.** A hook importing neither
  `accept` nor `rollback` falls through to a plain return — unusual and almost
  always a bug, but xahaud does **not** reject it as `temMALFORMED` (the VM models
  it as a distinct `RETURNED` outcome). Blocking `build`/`install-tx` on it could
  refuse an odd-but-deployable hook, so it now warns instead of gating. Message no
  longer overclaims "will be rejected." (Aligns with the analyzer's finding-not-block
  semantics and the "don't hard-block valid hooks" rule.)

## [1.8.0] - 2026-06-14

Semantic safety lints — `xahc lint` now catches runtime/correctness footguns, not
just structural (`temMALFORMED`-class) rejections. These OVERLAP / are informed by
the wasm-tractable rules in xahau-mcp's analyzer.

> **Correction (see [1.9.0]):** this entry originally claimed the rules "mirror"
> the analyzer so the author and verify sides "agree." That overstated it — the
> rule sets are not 1:1 (ids and/or severities differ, e.g. `NO_EXIT_PATH` is a
> `warn` here vs CRITICAL `HOOK-001` in the MCP). Treat the crosswalk as
> informative, not a parity guarantee.

### Added
- **`NO_EXIT_PATH`** (error) — hook imports neither `accept` nor `rollback`; it
  cannot terminate a transaction decision (traps / rejected). Blocks `build` /
  `install-tx`. (~ xahau-mcp `HOOK-001-NO-EXIT`.)
- **`EMIT_WITHOUT_RESERVE`** (warn) — calls `emit` without importing `etxn_reserve`;
  every emit fails at runtime. The `XAHC_EMIT_*` macros reserve for you. (~ `HOOK-009`.)
- **`REENTRANCY_EMIT`** (warn) — `emit` + `hook_again` + a `cbak` export can form an
  unbounded emission / re-execution loop. (~ `HOOK-010`.)
- **`STATE_FOREIGN_WRITE`** (warn) — `state_foreign_set` modifies another account's
  state; confirm the HookGrant + bounds. (~ `HOOK-008` foreign.)
- Advisories (new **`info`** level): `EMIT_NO_CBAK`, `STATE_WRITE`, `FLOAT_USAGE`,
  `OVERSIZE_WASM`, `MEMORY_EXCESS`. (~ `HOOK-003/008/012/011/013`.)
- New `info` severity in the `--json` envelope and the human report (does not gate
  build/install — only errors do).
- 9 new lint unit tests (WAT-based); 22 tests total.

## [1.7.0] - 2026-06-14

Positional guard lint — `xahc lint` now matches xahaud's guard verifier exactly.

### Changed
- **The guard check is POSITIONAL, not presence-based.** xahaud requires `_g` to
  be the FIRST branch instruction in a loop (only const/local/arith may precede).
  lint now enforces exactly that:
  - `GUARD_NOT_FIRST` — a guard exists but a non-guard branch precedes it.
  - `UNGUARDED_LOOP` — a loop with no `_g`.
  Both are now **errors** (were warnings) — they cause `temMALFORMED` on-chain, so
  `xahc build` / `install-tx` block them. Built hooks are unaffected: the
  guard-reposition pass (v1.6.0) makes every built hook compliant.
- **Validated against Xahau testnet:** lint's verdict equals the ledger's
  `engine_result` across mispositioned / compliant / unguarded hooks (3/3).
- Moved `unguarded_loop.c` to `tests/fixtures/` + a CI negative test asserting
  `xahc build` fails on it.

## [1.6.1] - 2026-06-14

Post-audit hardening (5-reviewer audit of the money-touching + new-surface code).

### Fixed
- **Emit builders check host-fn returns.** `etxn_details` / `etxn_fee_base` /
  `float_sto` return a negative error code on failure; the builders now
  `rollback` on a negative instead of advancing the buffer pointer by a negative
  length (which would corrupt the emit / shift a negative). Native + IOU paths.
- **`clean` strips ALL custom sections** (not just name/producers/target_features)
  — also any `linking`/`reloc.*`/`.debug_*` — so no stray section reaches xahaud.
- **`install-tx` rejects an unknown numeric tx type** in `--on` (was silently
  ignored by the HookOn encoder, so the user thought it fired on that type).
- **`build` surfaces guard-reposition skips** — a loop guard with non-literal
  args is left in place and now warned, not silent.

### Known (documented, deferred)
- `xahc lint`'s guard check is **presence**, not **positional** — it can't catch a
  *mispositioned* guard the way xahaud does (built hooks are safe; the build pass
  fixes position). Positional lint is planned for v1.7.
- `check_stack` ignores `call_indirect` targets (underestimates depth).

## [1.6.0] - 2026-06-14

Guard-reposition pass — hooks build at `-O2` again, no `-Oz` dependency.

### Added / Changed
- **Guard-reposition pass** (`guardpass`): after compile, hoists each loop's
  guard — the developer's `const id; const maxiter; call _g; (drop)` block — to
  the loop head, satisfying xahaud's rule that `_g` be the **first branch
  instruction in a loop**. The optimizer's loop rotation moves the guard to the
  loop bottom; the pass moves it back. It repositions the *existing* guard and
  its literal bound — it never invents a `maxiter`. Loops with no `_g` at all are
  reported, not faked.
- **`build`: back to `-O2`** (from the v1.5.1 `-Oz` interim). `-O2` hooks now
  install; re-verified on Xahau testnet (guardrail installs, over-limit
  `tecHOOK_REJECTED`, under-limit `tesSUCCESS`).
- `build` prints the repositioned-guard count and warns on any unguarded loop.

## [1.5.1] - 2026-06-14

**Critical:** every prior xahc-built hook was rejected on-chain (`temMALFORMED`).
Found via the first real Xahau testnet deploy; the `agent_guardrail` hook now
installs and enforces a spending cap on-ledger (see [docs/TESTNET-PROOF.md](docs/TESTNET-PROOF.md)).

### Fixed — SetHook validator acceptance
- **`build`: `--gc-sections` + export only `hook`/`cbak`** (was `--export-all`).
  lld left dead functions (e.g. `__wasm_call_ctors`); xahaud validates every
  function and rejects an unguarded dead one.
- **`build`: `-Oz` instead of `-O2`.** `-O2` loop rotation moves the `_g` guard
  out of the position xahaud's guard verifier requires (our lint's presence check
  passed it; the chain's is position-sensitive). `-Oz` keeps guards in place and
  yields smaller hooks (lower SetHook fee). A wasm guard-injection pass is the
  robust long-term fix; `-Oz` is the validated interim.
- **`clean`: strip the `memory` export and compiler custom sections**
  (`name`/`producers`/`target_features`). xahaud rejects a hook that exports
  `memory`.
- **`sim`: re-add a `memory` export in-memory** before instantiating, since the
  deployable wasm no longer exports it (the on-disk artifact is untouched).
- CI: assert built hooks have the on-chain shape (no `memory` export / custom sections).

## [1.5.0] - 2026-06-13

Agentic payments — the layer-1 safety rail for autonomous agents on Xahau.

### Added
- **`agent_guardrail` archetype + `examples/agent_guardrail.c`** — a Hook that
  policies OUTGOING payments: per-tx spend cap (HookParameter `LIM`) and optional
  destination lock (`DST`). The protocol-enforced agent spending limit that
  x402/app-layer flows lack. Tested both sides of the cap (over-limit → rollback).
- **`xahc-guardrail` skill** (`skills/xahc-guardrail/SKILL.md`) — Claude-driven
  scaffold → build → test → `install-tx`, producing an UNSIGNED SetHook (no key
  custody) so an agent installs its own on-chain budget.
- **`hook_param` in the local sim**; test suites gain a `hook_params` table
  (ASCII name → hex value), so guardrail policy is unit-testable offline.
- **Docs:** `docs/AGENTIC.md` (why Hooks beat escrow/multisign for agent controls;
  how xahc / xahau-mcp / xrpl-mcp split the agent safety layer) and
  `docs/X402-XAHAU.md` (proposed `exact-xahau` x402 scheme with the guardrail Hook
  as the L1 spending authority at `/verify` and `/settle`).
- CI runs the guardrail test suite.

## [1.4.0] - 2026-06-13

`xahc sim`/`test` now enforce the guard budget — over-budget loops are caught locally.

### Added / Changed
- **`_g` guard-budget enforcement in the local sim.** A guard crossed more than its
  `maxiter` (`XAHC_GUARD(n)`) now produces a `GUARD_VIOLATION` outcome (exit 2 / test
  failure) instead of being silently accepted — the same loop bound the on-chain
  validator enforces. New `Outcome::GuardViolation`; `expect = "guardviolation"` is
  assertable in test suites. Adds `examples/over_budget.c` + a CI case.
- A local-sim trap (a host fn the sim doesn't model) now routes you to `xahc verify`
  for the full-fidelity xahau-mcp VM, instead of a bare trap message.

### Security
- Bumped **wasmtime 27 → 45**, clearing 15 RUSTSEC advisories (`cargo audit` now
  clean, exit 0). `sim.rs` migrated to wasmtime 45's forked `Error` type (kept the
  VM work in `run_inner`, converted to anyhow once at the boundary). VM behavior is
  unchanged — every example sim and test suite produces identical outcomes.

### Fixed
- `xahc verify` now forwards the SAME otxn fields the local sim synthesizes
  (`sfAmount` always, `sfAccount`/`sfDestination` as zero bytes) and treats a VM
  runtime-error `halted` (guard violation / trap) as a rollback — eliminating
  false `DISAGREE`s on hooks that read account/destination, zero-amount payments,
  and guard-violating hooks (incl. the bundled `over_budget.c`).

## [1.3.0] - 2026-06-13

The loop, wired — `xahc verify` runs the local sim AND the xahau-mcp VM and flags disagreement.

### Added
- **`xahc verify <wasm> [--tt --drops --remote]`** — differential gate: runs the
  built wasm through the fast local sim AND a hosted xahau-mcp `/execute` (the
  fidelity-locked VM), seeding **byte-identical inputs** to both, and flags any
  accept/rollback disagreement (nonzero exit). The local sim is the fast inner
  loop; the MCP VM is the authoritative gate; disagreement is itself a finding.
  Talks over HTTP (`XAHC_SIM_URL` / `--remote`) to an xahau-mcp `/execute` endpoint
  you supply — never a filesystem import of the private MCP, so any hosted shim works
  (vs the old bridge that needed a private-repo checkout).

## [1.2.0] - 2026-06-13

Machine-readable output — xahc can now be driven by CI, the web funnel, and xahau-mcp.

### Added
- **Global `--json` flag** on `build` / `lint` / `sim` / `test` / `clean`. Emits a
  stable result envelope on **stdout**; all human/diagnostic output goes to **stderr**,
  so `xahc build --json | jq` is clean. Exit codes are unchanged (lint error = 1,
  rollback = 2), so structured and exit-code consumers both work.
  - `BuildResult{wasm_path, wasm_hex, bytes, lint}` — `wasm_hex` removes the manual
    file→hex bridge when handing a build to xahau-mcp.
  - `LintResult{ok, error_count, findings:[{level, rule_id, msg}]}`.
  - `SimResult{outcome, return_code, emitted:[{bytes, hex}], state_keys}`.
  - `TestResult{wasm, passed, failed, cases:[{name, ok, detail}]}`.
- **Stable `rule_id`s on lint findings** (ILLEGAL_EXPORT, NO_HOOK_EXPORT, NO_G_IMPORT,
  UNGUARDED_LOOP, STACK_OVERFLOW, …) — a compatibility contract for machine consumers,
  independent of the human message wording.

## [1.1.0] - 2026-06-13

Safety hardening of `install-tx` (pre-launch audit).

### Changed
- **`install-tx --on` is now required** — no implicit fire-on-all-types default,
  which was a footgun (a hook firing on every transaction type, incl. SetHook).

### Added / Fixed
- `install-tx` **refuses a wasm that fails lint** (errors) and **surfaces lint
  warnings** (unguarded loop, stack budget) instead of packaging them silently —
  it's no longer an escape hatch around the safety checks.
- `install-tx` **validates the `--account` r-address** (base58 classic-address
  shape) before emitting.
- `install-tx` **caps HookParameter name/value lengths** (32 B / 256 B).

## [1.0.0] - 2026-06-13

First stable release. xahc is the authoring/compile companion to
[xahau-mcp](https://github.com/Hugegreencandle/xahau-mcp): write a C Hook safely,
compile it, and emit a ready-to-sign install transaction.

### Added
- **Self-contained binary** — the safe-header library is embedded and materialized
  at build time, so an installed `xahc` needs no repo checkout.
- **`xahc doctor`** — verifies clang + wasm-ld and compiles a hook end-to-end.
- **`xahc new <name>`** — scaffolds a buildable project (firewall / accept_all /
  emitter archetypes) with a test suite, justfile, and README.
- **`xahc install-tx`** — emits an UNSIGNED SetHook: CreateCode, HookOn
  (computed from Xahau's active-low mask, regression-tested against golden values),
  HookNamespace
  (`--namespace` or `--namespace-label` = sha256), HookParameters (`--param`),
  NetworkID, Flags.
- **`xahc test`** — declarative TOML test suites over the simulator (outcome +
  emit/state-count assertions), nonzero exit on failure.
- **`xahc sim`** — local wasmtime preflight (accept/rollback, emitted txns, state).
- **`xahc lint`** — export allowlist, Hook API import allowlist, per-loop `_g`
  guard presence, and a stack-budget overflow check.
- **`xahc build` / `clean`** — clang→wasm pipeline with a Rust hook-cleaner.
- **Safe headers** — `guard.h` (auto-numbered guards), `check.h` (checked
  returns), `otxn.h` (+ native-drops decode), `param.h`, `state.h`, `sfcodes.h`,
  and verified emit builders: native `XAHC_EMIT_PAYMENT` (codec-verified) and
  issued `XAHC_EMIT_PAYMENT_IOU` (VM-verified, 1.5 USD).

### Notes
- Pre-1.0 work shipped under 0.0.1 / 0.1.0 tags.
- Not audited. Always confirm financial hooks on testnet before mainnet.
