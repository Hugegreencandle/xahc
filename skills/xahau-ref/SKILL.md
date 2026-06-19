---
name: xahau-ref
description: Authoritative lookup of Xahau protocol facts — Hook host functions, return/error codes, sfcodes & field IDs, guard/XFL/emit semantics, SetHook fields, TSH (weak/strong), keylets, and amendments — from the user's live-scraped reference instead of guessing from training data. Use when the user (or another skill) asks "what does host fn X return", "what's the sfcode for Y", "how does guard/XFL/emit/TSH work", "is amendment Z active", "how is HookOn/HookNamespace/HookParameter encoded", or any Xahau protocol detail. ALWAYS prefer this over memory for Xahau internals.
---

# xahau-ref — cite Xahau protocol facts, don't guess

Xahau internals (host-fn signatures, return codes, field IDs, XFL flag maps, guard/emit rules)
are easy to get subtly wrong from memory — and a wrong constant in a hook or a proof is a real
bug. This skill answers from the curated, live-scraped reference, with the source line cited.

## THE ONE RULE — never answer Xahau internals from training data
If it's a protocol fact (a code, a signature, a flag, an encoding, an amendment's existence),
look it up here and CITE it. If the reference doesn't cover it, say so and point to the upstream
source — never fabricate a code or a signature.

## Sources (in priority order)
1. `~/Desktop/xahc-prover/docs/XAHAU-DEV-REFERENCE.md` — host fns, return codes, sfcodes,
   guard/XFL/emit semantics, SetHook, TSH, amendments (the mirror; quote it).
2. `~/Desktop/xahc-prover/docs/XAHAU-RESOURCES.md` — curated upstream repos/tools/standards.
3. Ground truth (when the mirror is silent or possibly stale):
   - `hookapi.h` / macros: https://github.com/XRPLF/hook-macros (sfcodes, keylets, field-id scheme)
   - host-fn behaviour + VM: https://github.com/Xahau/xahaud
   - Rust signatures + XFL maps: https://github.com/Xahau/hooks-rs
   - Live amendments: https://xahau.network/docs/features/amendments

## Sequence
1. **Grep the reference first:**
   `grep -in "<term>" ~/Desktop/xahc-prover/docs/XAHAU-DEV-REFERENCE.md` (try host-fn name,
   sfcode label, error code, amendment name). Read the matched section.
2. **Answer with the cite:** quote the exact line + `file:line`. For a code/signature, give it
   verbatim (e.g. `state(write_ptr,write_len,kread_ptr,kread_len)`, `-34 NOT_AUTHORIZED`).
3. **Stale/missing → escalate honestly:** if it's not in the mirror or might be out of date
   (the file notes "current as of compile date"), say so and point to the upstream source above
   — for "is amendment X active" the only authority is a live node / the amendments page.
4. **Cross-check constants** the prover/headers depend on against `hook-macros`/`hooks-rs` when
   the question is about a field ID, XFL flag, or FCMP constant (a wrong one = a false PROVEN).

## Common lookups
- Host fns + return codes · sfcodes/field IDs · guard `_g` semantics · XFL (issued-amount float)
- `emit`/`etxn_reserve`/`etxn_details` rules · SetHook fields (HookOn/HookNamespace/HookParameter/
  HookGrant/HookCanEmit) · TSH weak vs strong (who can rollback) · keylets · state namespacing.

## Notes
- This skill is read-only knowledge — no builds. It backs the other skills (audit/prove/hook).
- When citing to the user, prefer the exact reference line over paraphrase; the user builds on these.
