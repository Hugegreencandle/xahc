---
name: xahau-amendment
description: Track Xahau amendments and assess their impact on a deployed Hook — does an activated or pending amendment change host-function / transactor / state semantics a hook relies on, and should it be re-proven? Use when the user says "/xahau-amendment", "is amendment X active", "what amendments are live/voting", "will this amendment break my hook", "did the ledger change under my hook", or wants to check whether a Xahau protocol change affects a deployed Hook's proof.
---

# xahau-amendment — is the ledger a moving target under your hook?

Xahau improves fast (amendments activate on a 5-day majority window). A Hook proven against
today's semantics can behave differently if an amendment changes a host-fn, transactor, or
state rule it relies on. (Caveat the kernel devs make, rightly: they work hard NOT to break
user space — but a hook author should still check, and re-prove if a relied-on semantic moved.)
This skill checks amendment status and re-establishes the proof.

## THE ONE RULE — live status comes from a node, not from memory or the mirror
The reference notes amendments are "current as of compile date." NEVER claim an amendment is
active/inactive from training data or a possibly-stale doc. The only authority for *live* status
is a node query or the amendments page. State the source + as-of time.

## Sources
- Live status (authoritative): query a node `feature` / the amendments page
  https://xahau.network/docs/features/amendments
- Semantics of a named amendment + what it touches:
  `grep -in "<amendment>" ~/Desktop/xahc-prover/docs/XAHAU-DEV-REFERENCE.md`, then xahaud
  (https://github.com/Xahau/xahaud) for the actual behavioural change.
- Hook proofs to re-run: `~/Desktop/xahc-prover` (the prover) + `xahau-prove` / `xahau-audit`.

## Sequence
1. **Identify the amendment(s).** Name + what subsystem they change (host fn, transactor, field,
   reserve, emit/TSH rule). Use `xahau-ref` to pull the reference section; cite it.
2. **Get LIVE status** (don't guess): node `feature` RPC or the amendments page. Report:
   `<amendment>: ENABLED | VOTING (n%) | OBSOLETE`, with source + as-of timestamp.
3. **Map the change → the hook's dependencies.** Does the hook read a field / call a host fn /
   rely on a transactor or reserve rule the amendment alters? If NO overlap → no impact (state it).
   If overlap → the existing proof's assumptions may have moved.
4. **Re-prove the affected invariants** against current semantics (`xahau-prove` / `xahau-audit`).
   If the prover models the changed behaviour, you get a fresh verdict; if not, it fails closed to
   INCONCLUSIVE — say so (not a pass). A changed-and-still-PROVEN result is the all-clear.
5. **Registry tie-in:** a deployed hook's proof in the registry was made under a prover_commit at
   a point in time. After a relevant amendment, the honest state is "proof predates amendment X —
   re-verify." (`xahc-watch`'s PROOF_VOID is about bytecode change, NOT amendment drift — different
   axis; flag amendment drift explicitly.)

## Report
"Amendment X (touches: <subsystem>) is <LIVE status, source, as-of>. Hook depends on it: yes/no.
If yes: re-proof verdict = <…>; residual = <…>." Never imply 'fine' without the live check + the
re-proof.

## Notes
- "we don't break user space" is the protocol ethos, not a guarantee your hook's *own*
  assumptions survived — check the ones it relies on.
- Pair with `xahau-ref` (semantics) and `xahau-audit` (re-proof). This skill is the "living
  target" guard.
