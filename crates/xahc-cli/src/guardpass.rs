//! Guard-reposition pass.
//!
//! xahaud's guard rule: "a call to `_g` must be the first branch instruction
//! after a loop instruction" (only non-branch instructions — const/local/arith —
//! may precede it). Optimizing compilers (clang -O2 loop rotation) move the
//! guard call + its literal args to the BOTTOM of the loop, which violates the
//! rule and gets the hook rejected (temMALFORMED) even though it is guarded.
//!
//! This pass HOISTS the developer's existing guard — the contiguous
//! `i32.const <id>; i32.const <maxiter>; call _g; (drop)` block — to the head of
//! each loop body. It never invents a guard or a bound: it only moves what the
//! developer already wrote, so the iteration promise is preserved. A loop with
//! no `_g` at all is reported (the developer must guard it).

use anyhow::{Context, Result};
use walrus::ir::{Instr, InstrSeqId};
use walrus::{FunctionId, FunctionKind, Module};

pub struct Report {
    pub repositioned: usize,
    pub already_ok: usize,
    pub unguarded_loops: usize,
    /// loops whose guard args weren't plain literals → left in place (may be
    /// mispositioned; surfaced so it isn't silent).
    pub skipped: usize,
    /// FAIL-CLOSED (2026-07-29): loops that DO contain a `_g` somewhere, but where this pass could
    /// not PROVE it is the first branch at the loop head — e.g. a guard written in the `for`
    /// CONDITION, which clang compiles into a nested block. These previously counted as
    /// `already_ok` and were reported as nothing at all, so `xahc build` said "lint no issues" for a
    /// module SetHook then rejected with temMALFORMED. An unrecognised guard shape must never be
    /// indistinguishable from a correct one. See docs/GUARD_PLACEMENT.md.
    pub unverified: usize,
}

pub fn reposition(wasm: &[u8]) -> Result<(Vec<u8>, Report)> {
    let mut m = Module::from_buffer(wasm).context("parse wasm")?;
    let g = match find_g(&m) {
        Some(g) => g,
        None => {
            // No guard import at all → no loops to guard (or an unguarded hook,
            // which lint catches separately). Pass through unchanged.
            return Ok((m.emit_wasm(), Report { repositioned: 0, already_ok: 0, unguarded_loops: 0, skipped: 0, unverified: 0 }));
        }
    };

    let mut rep = Report { repositioned: 0, already_ok: 0, unguarded_loops: 0, skipped: 0, unverified: 0 };

    let func_ids: Vec<FunctionId> = m
        .funcs
        .iter()
        .filter(|f| matches!(f.kind, FunctionKind::Local(_)))
        .map(|f| f.id())
        .collect();

    for fid in func_ids {
        // Collect this function's loop body sequences.
        let loops = {
            let lf = match &m.funcs.get(fid).kind {
                FunctionKind::Local(lf) => lf,
                _ => continue,
            };
            let mut acc = Vec::new();
            collect_loops(lf, lf.entry_block(), &mut acc);
            acc
        };
        for seq in loops {
            let lf = match &mut m.funcs.get_mut(fid).kind {
                FunctionKind::Local(lf) => lf,
                _ => continue,
            };
            match hoist_guard_in_seq(lf, seq, g) {
                Hoist::AlreadyHead => rep.already_ok += 1,
                Hoist::Moved => rep.repositioned += 1,
                Hoist::NoGuard => rep.unguarded_loops += 1,
                Hoist::Skip => rep.skipped += 1, // non-literal args: left in place, surfaced by build
                Hoist::Unverified => rep.unverified += 1,
            }
        }
    }

    Ok((m.emit_wasm(), rep))
}

fn find_g(m: &Module) -> Option<FunctionId> {
    m.imports.iter().find_map(|imp| {
        if imp.module == "env" && imp.name == "_g" {
            if let walrus::ImportKind::Function(fid) = imp.kind {
                return Some(fid);
            }
        }
        None
    })
}

fn collect_loops(lf: &walrus::LocalFunction, seq: InstrSeqId, out: &mut Vec<InstrSeqId>) {
    for (instr, _) in lf.block(seq).instrs.iter() {
        match instr {
            Instr::Loop(l) => {
                out.push(l.seq);
                collect_loops(lf, l.seq, out);
            }
            Instr::Block(b) => collect_loops(lf, b.seq, out),
            Instr::IfElse(ie) => {
                collect_loops(lf, ie.consequent, out);
                collect_loops(lf, ie.alternative, out);
            }
            _ => {}
        }
    }
}

enum Hoist {
    AlreadyHead,
    Moved,
    NoGuard,
    Skip,
    /// A `_g` exists somewhere in this loop, but not at the top level where we can prove it runs
    /// first. We will NOT silently bless it.
    Unverified,
}

/// True if a `_g` call is ALREADY provably the first branch on entry to `seq`,
/// descending in execution order through any leading unconditional `block`
/// (the shape clang -O2 can emit). Mirrors lint::first_branch_is_guard so the
/// hoist does not "fix" a guard that is already correct (e.g. one nested inside
/// a leading block) — which would either double-hoist or churn a valid hook.
///
/// Conservative on purpose: a `block` body is always entered, so a guard first
/// inside a leading block is genuinely first; an `if`/`else` or any other branch
/// reached before the guard is NOT treated as guard-first.
fn guard_already_first(lf: &walrus::LocalFunction, seq: InstrSeqId, g: FunctionId) -> bool {
    for (instr, _) in lf.block(seq).instrs.iter() {
        match instr {
            Instr::Call(c) if c.func == g => return true,
            Instr::Block(b) => {
                // A leading block is always entered. If it contains a branch we
                // can decide here; if it has no branch, continue scanning after it.
                if seq_has_branch(lf, b.seq) {
                    return guard_already_first(lf, b.seq, g);
                }
            }
            _ if is_branch(instr) => return false,
            _ => {}
        }
    }
    false
}

/// Guard is provably first ONLY if it appears at this sequence's own top level before any other
/// branch. Deliberately does NOT descend into a leading `block`: xahaud requires `_g` to be the
/// first branch after the loop instruction, and a guard buried in a nested block is exactly the
/// shape the ledger rejected while this pass called it fine.
fn guard_first_at_top_level(lf: &walrus::LocalFunction, seq: InstrSeqId, g: FunctionId) -> bool {
    for (instr, _) in lf.block(seq).instrs.iter() {
        match instr {
            Instr::Call(c) if c.func == g => return true,
            _ if is_branch(instr) => return false,
            _ => {}
        }
    }
    false
}

/// Does a `_g` call appear anywhere inside this sequence's NESTED blocks?
fn seq_contains_guard_nested(lf: &walrus::LocalFunction, seq: InstrSeqId, g: FunctionId) -> bool {
    for (instr, _) in lf.block(seq).instrs.iter() {
        match instr {
            Instr::Call(c) if c.func == g => return true,
            Instr::Block(b) => {
                if seq_contains_guard_nested(lf, b.seq, g) { return true; }
            }
            Instr::Loop(l) => {
                if seq_contains_guard_nested(lf, l.seq, g) { return true; }
            }
            Instr::IfElse(ie) => {
                if seq_contains_guard_nested(lf, ie.consequent, g)
                    || seq_contains_guard_nested(lf, ie.alternative, g) { return true; }
            }
            _ => {}
        }
    }
    false
}

/// Whether a sequence contains any branch instruction at its top level (used to
/// decide if a leading `block` is "decisive" for the guard-first check).
fn seq_has_branch(lf: &walrus::LocalFunction, seq: InstrSeqId) -> bool {
    lf.block(seq).instrs.iter().any(|(i, _)| is_branch(i))
}

/// A control-transfer / call instruction (kept in sync with lint::is_branch).
fn is_branch(instr: &Instr) -> bool {
    matches!(
        instr,
        Instr::Call(_)
            | Instr::CallIndirect(_)
            | Instr::Br(_)
            | Instr::BrIf(_)
            | Instr::BrTable(_)
            | Instr::IfElse(_)
            | Instr::Loop(_)
            | Instr::Block(_)
            | Instr::Return(_)
            | Instr::Unreachable(_)
    )
}

/// Within one loop body sequence, hoist the `_g` guard block to the front.
fn hoist_guard_in_seq(lf: &mut walrus::LocalFunction, seq: InstrSeqId, g: FunctionId) -> Hoist {
    // If the guard is already provably first on entry — including the case where
    // it lives inside a leading unconditional `block` — there is nothing to move.
    // Skipping here prevents churning (or double-hoisting) an already-correct hook.
    // PROOF, not assumption: the guard must be reachable-first at THIS sequence's top level.
    // The old check descended into a leading `block`, which is how a for-condition guard was
    // blessed as AlreadyHead and then rejected by the ledger.
    if guard_first_at_top_level(lf, seq, g) {
        return Hoist::AlreadyHead;
    }

    let instrs = &mut lf.block_mut(seq).instrs;

    let ci = match instrs
        .iter()
        .position(|(i, _)| matches!(i, Instr::Call(c) if c.func == g))
    {
        Some(ci) => ci,
        None => {
            // No `_g` at this sequence's top level. Distinguish "there is no guard at all" from
            // "there IS one, nested where we cannot hoist or prove it" — the latter is the
            // for-condition shape and must be surfaced, not passed through as unguarded-or-fine.
            return if seq_contains_guard_nested(lf, seq, g) {
                Hoist::Unverified
            } else {
                Hoist::NoGuard
            };
        }
    };

    // The guard takes two literal args (id, maxiter): two i32.const immediately
    // before the call. Bound the grab to exactly those two.
    let mut start = ci;
    let mut consts = 0;
    while start > 0 && consts < 2 && matches!(instrs[start - 1].0, Instr::Const(_)) {
        start -= 1;
        consts += 1;
    }
    if consts < 2 {
        // Args aren't plain literals (unexpected post-compile). Don't risk a
        // bad move; leave it for lint to evaluate.
        return Hoist::Skip;
    }

    // Include a trailing `drop` of the guard's return value if present.
    let mut end = ci + 1;
    if end < instrs.len() && matches!(instrs[end].0, Instr::Drop(_)) {
        end += 1;
    }

    if start == 0 {
        return Hoist::AlreadyHead;
    }

    let block: Vec<_> = instrs.drain(start..end).collect();
    for (k, item) in block.into_iter().enumerate() {
        instrs.insert(k, item);
    }
    Hoist::Moved
}

// ---------------------------------------------------------------------------
// BYTE-ADJACENCY VERIFICATION (2026-07-29)
// ---------------------------------------------------------------------------
// xahaud does NOT check that the guard is reachable-first. It checks that the
// guard's BYTES sit immediately after the `loop` opcode + blocktype byte
// (include/xrpl/hook/Guard.h:386):
//
//     if (wasm[i] != 0x41U)
//         GUARD_ERROR("Missing first i32.const after loop instruction");
//
// i.e. exactly `0x41 <sleb id> 0x41 <uleb maxiter> 0x10 <uleb guard_idx>`.
// Failing that, SetHook rejects the module with temMALFORMED.
//
// The walrus-IR checks above reason about REACHABILITY, which is a different
// and weaker property: a guard written in a `for` condition is reachable-first
// (only loads precede it) yet clang hoists it out of the loop body, so the
// bytes are not adjacent and the ledger refuses the hook. That gap is why
// escrow_ok and multisig_ok were never installable while `xahc lint` reported
// "no issues". This verifies the ACTUAL property, on the ACTUAL emitted bytes.
//
// Fixtures: xahc-prover hooks/loopA.c + loopC.c (must FAIL), loopB.c + loopD.c
// (must PASS).

/// One loop whose guard bytes are not adjacent to its `loop` opcode.
pub struct Misplaced {
    pub func: u32,
    pub offset: usize,
    pub found: String,
}

/// Verify every `loop` in the emitted module is immediately followed by the
/// guard byte sequence. Returns the offending loops, or an Err if the module
/// cannot be decoded (FAIL CLOSED: an undecodable module is never "fine").
pub fn verify_byte_adjacency(wasm: &[u8]) -> Result<Vec<Misplaced>> {
    use wasmparser::{Parser, Payload, Operator};
    // Derive the guard's function index from the emitted module itself: `env._g` is an import, and
    // imported functions occupy the low indices in order. Taking it from the bytes we are about to
    // ship avoids any mismatch with walrus's own numbering.
    let mut guard_idx: Option<u32> = None;
    // Imported functions occupy the low indices, so the code section's first entry is function
    // number `imported_funcs` — not 0. Getting this wrong misnames the function in the error.
    let mut imported_funcs: u32 = 0;
    {
        for payload in Parser::new(0).parse_all(wasm) {
            if let Payload::ImportSection(r) = payload.context("decode imports")? {
                for imp in r {
                    let imp = imp.context("import")?;
                    if let wasmparser::TypeRef::Func(_) = imp.ty {
                        if imp.module == "env" && imp.name == "_g" { guard_idx = Some(imported_funcs); }
                        imported_funcs += 1;
                    }
                }
            }
        }
    }
    // No guard import at all -> no loops to check against it; nothing to verify.
    let guard_idx = match guard_idx { Some(g) => g, None => return Ok(Vec::new()) };
    let mut bad = Vec::new();
    let mut fidx: u32 = imported_funcs;
    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload.context("decode wasm")?;
        if let Payload::CodeSectionEntry(body) = payload {
            let mut ops = body.get_operators_reader().context("operators")?;
            // Walk (operator, byte-offset) pairs; when we see `Loop`, the next
            // three operators must be i32.const / i32.const / call guard_idx.
            let mut pending: Option<usize> = None;
            let mut want: u8 = 0;
            while !ops.eof() {
                let (op, off) = ops.read_with_offset().context("read op")?;
                if let Some(loop_off) = pending {
                    let ok = match (want, &op) {
                        (0, Operator::I32Const { .. }) => { want = 1; true }
                        (1, Operator::I32Const { .. }) => { want = 2; true }
                        (2, Operator::Call { function_index }) => {
                            if *function_index == guard_idx { pending = None; true } else { false }
                        }
                        _ => false,
                    };
                    if !ok {
                        bad.push(Misplaced {
                            func: fidx,
                            offset: loop_off,
                            found: format!("{:?}", op),
                        });
                        pending = None;
                    }
                }
                if matches!(op, Operator::Loop { .. }) {
                    pending = Some(off);
                    want = 0;
                }
            }
            if pending.is_some() {
                bad.push(Misplaced { func: fidx, offset: pending.unwrap(), found: "end-of-body".into() });
            }
            fidx += 1;
        }
    }
    Ok(bad)
}

// ---------------------------------------------------------------------------
// Tests for the byte-adjacency gate.
//
// These are written in WAT rather than compiled from C on purpose: the property
// under test is a property of the EMITTED BYTES, and clang's decision to hoist a
// guard out of a loop body depends on the body and on the optimiser's mood. A C
// fixture would therefore be testing clang, not this pass. The WAT below encodes
// the exact shapes observed on-chain — see docs/GUARD_PLACEMENT.md and the C
// originals in tests/fixtures/loop{A,B,C,D}.c.
/// One `call` to a function the module defines itself.
pub struct IllegalCall {
    pub func: u32,
    pub offset: usize,
    pub callee: u32,
}

// A hook may call ONLY imported host functions. xahaud `Guard.h:495-509`:
//
//     if (callee_idx > last_import_idx)
//         GUARDLOG(hook::log::CALL_ILLEGAL)
//             << "Hook calls a function outside of the whitelisted imports ";
//         return {};
//
// which fails validateGuards -> SetHook preflight -> temMALFORMED.
//
// This bites through the OPTIMISER, not the source. A `static inline` helper is a hint clang may
// decline for a large function once there is more than one call site, so the same source installs
// with one emit and is refused with two. Nothing at the C level shows it; only the emitted module
// does. (Fixed in the shipped headers in 1.11.1 by forcing always_inline — this rule catches the
// same shape in any hook, including hand-written helpers.)

/// Verify the module calls only imported functions. Returns the offending calls, or an Err if the
/// module cannot be decoded (FAIL CLOSED: an undecodable module is never "fine").
pub fn verify_no_user_calls(wasm: &[u8]) -> Result<Vec<IllegalCall>> {
    use wasmparser::{Parser, Payload, Operator};
    // Imported functions occupy the low indices; anything at or above this count is defined by
    // the module itself.
    let mut imported_funcs: u32 = 0;
    for payload in Parser::new(0).parse_all(wasm) {
        if let Payload::ImportSection(r) = payload.context("decode imports")? {
            for imp in r {
                let imp = imp.context("import")?;
                if let wasmparser::TypeRef::Func(_) = imp.ty {
                    imported_funcs += 1;
                }
            }
        }
    }
    let mut bad = Vec::new();
    let mut fidx: u32 = imported_funcs;
    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload.context("decode wasm")?;
        if let Payload::CodeSectionEntry(body) = payload {
            let mut ops = body.get_operators_reader().context("operators")?;
            while !ops.eof() {
                let (op, off) = ops.read_with_offset().context("read op")?;
                if let Operator::Call { function_index } = op {
                    if function_index >= imported_funcs {
                        bad.push(IllegalCall { func: fidx, offset: off, callee: function_index });
                    }
                }
            }
            fidx += 1;
        }
    }
    Ok(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap a function body in a module importing `env._g` (function index 0).
    fn module(body: &str) -> Vec<u8> {
        let wat = format!(
            r#"(module
                 (import "env" "_g" (func $g (param i32 i32) (result i32)))
                 (func (export "hook") (param i32) (result i64)
                   {body}
                   (i64.const 0)))"#
        );
        wat::parse_str(wat).expect("valid wat")
    }

    /// The guard's three operators, byte-adjacent to the loop opcode.
    const GUARD: &str = "(drop (call $g (i32.const 1) (i32.const 21)))";

    /// loopB: guard first inside the body. This is the only correct form.
    #[test]
    fn guard_first_in_body_is_accepted() {
        let m = module(&format!("(loop {GUARD})"));
        assert!(verify_byte_adjacency(&m).unwrap().is_empty());
    }

    /// loopA: clang hoisted the guard, so the loop opens with a load. Rejected
    /// on-chain with temMALFORMED; must be caught here.
    #[test]
    fn guard_hoisted_out_of_body_is_caught() {
        let m = module("(loop (drop (local.get 0)))");
        let bad = verify_byte_adjacency(&m).unwrap();
        assert_eq!(bad.len(), 1);
        assert!(bad[0].found.contains("LocalGet"), "found: {}", bad[0].found);
    }

    /// loopC: a guard at the BOTTOM of the body is crossed every iteration and is
    /// still rejected — adjacency is syntactic, not semantic.
    #[test]
    fn guard_last_in_body_is_caught() {
        let m = module(&format!("(loop (drop (local.get 0)) {GUARD})"));
        assert_eq!(verify_byte_adjacency(&m).unwrap().len(), 1);
    }

    /// loopD: the hoisted guard is still there AND a body-head guard was added.
    /// Installs on-chain, so this pass must not flag it.
    #[test]
    fn hoisted_guard_plus_body_head_guard_is_accepted() {
        let m = module(&format!("{GUARD} (loop {GUARD})"));
        assert!(verify_byte_adjacency(&m).unwrap().is_empty());
    }

    /// The two i32.consts must be followed by a call to `_g` specifically, not to
    /// whatever function happens to sit at that index.
    #[test]
    fn call_to_a_different_function_is_caught() {
        let wat = r#"(module
             (import "env" "_g" (func $g (param i32 i32) (result i32)))
             (func $other (param i32 i32) (result i32) (i32.const 0))
             (func (export "hook") (param i32) (result i64)
               (loop (drop (call $other (i32.const 1) (i32.const 21))))
               (i64.const 0)))"#;
        let m = wat::parse_str(wat).unwrap();
        let bad = verify_byte_adjacency(&m).unwrap();
        assert_eq!(bad.len(), 1);
        assert!(bad[0].found.contains("Call"), "found: {}", bad[0].found);
    }

    /// A loop whose body ends before the guard sequence completes.
    #[test]
    fn loop_that_ends_before_the_guard_completes_is_caught() {
        let m = module("(loop (i32.const 1) (drop))");
        let bad = verify_byte_adjacency(&m).unwrap();
        assert_eq!(bad.len(), 1);
    }

    /// Every loop is reported, not just the first — multisig_ok had four.
    #[test]
    fn every_bad_loop_is_reported() {
        let m = module("(loop (drop (local.get 0))) (loop (drop (local.get 0)))");
        assert_eq!(verify_byte_adjacency(&m).unwrap().len(), 2);
    }

    /// The reported function index must account for imported functions, which
    /// occupy the low indices. With one import, the first defined function is 1.
    #[test]
    fn reported_function_index_skips_imports() {
        let m = module("(loop (drop (local.get 0)))");
        assert_eq!(verify_byte_adjacency(&m).unwrap()[0].func, 1);
    }

    /// A module that imports no guard has no adjacency obligation.
    #[test]
    fn module_without_a_guard_import_has_nothing_to_verify() {
        let wat = r#"(module
             (func (export "hook") (param i32) (result i64)
               (loop (drop (local.get 0)))
               (i64.const 0)))"#;
        let m = wat::parse_str(wat).unwrap();
        assert!(verify_byte_adjacency(&m).unwrap().is_empty());
    }

    /// A loop-free module is fine.
    #[test]
    fn module_without_loops_is_accepted() {
        let m = module(GUARD);
        assert!(verify_byte_adjacency(&m).unwrap().is_empty());
    }

    /// A hook may call ONLY imported host functions. This is the shape that made every
    /// multi-emit hook uninstallable before 1.11.1: the helper exists because clang declined
    /// an `inline` hint, and nothing in the C source shows it.
    #[test]
    fn a_call_to_a_module_defined_function_is_caught() {
        let wat = r#"(module
             (import "env" "_g" (func $g (param i32 i32) (result i32)))
             (func $helper (result i32) (i32.const 7))
             (func (export "hook") (param i32) (result i64)
               (drop (call $helper))
               (i64.const 0)))"#;
        let m = wat::parse_str(wat).unwrap();
        let bad = verify_no_user_calls(&m).unwrap();
        assert_eq!(bad.len(), 1, "expected the call to $helper to be flagged");
        assert_eq!(bad[0].callee, 1, "callee should be the first module-defined function");
    }

    /// Calls to imported host functions are the whole point and must never be flagged.
    #[test]
    fn calls_to_imports_are_not_flagged() {
        let wat = r#"(module
             (import "env" "_g" (func $g (param i32 i32) (result i32)))
             (import "env" "accept" (func $a (param i32 i32 i64) (result i64)))
             (func (export "hook") (param i32) (result i64)
               (drop (call $g (i32.const 1) (i32.const 2)))
               (drop (call $a (i32.const 0) (i32.const 0) (i64.const 0)))
               (i64.const 0)))"#;
        let m = wat::parse_str(wat).unwrap();
        assert!(verify_no_user_calls(&m).unwrap().is_empty());
    }

    /// Every offending call is reported, not just the first — the real case had two and three.
    #[test]
    fn every_illegal_call_is_reported() {
        let wat = r#"(module
             (import "env" "_g" (func $g (param i32 i32) (result i32)))
             (func $helper (result i32) (i32.const 7))
             (func (export "hook") (param i32) (result i64)
               (drop (call $helper))
               (drop (call $helper))
               (drop (call $helper))
               (i64.const 0)))"#;
        let m = wat::parse_str(wat).unwrap();
        assert_eq!(verify_no_user_calls(&m).unwrap().len(), 3);
    }

    /// A module that defines a helper but never CALLS it is legal — only calls are rejected.
    #[test]
    fn an_uncalled_module_defined_function_is_fine() {
        let wat = r#"(module
             (import "env" "_g" (func $g (param i32 i32) (result i32)))
             (func $unused (result i32) (i32.const 7))
             (func (export "hook") (param i32) (result i64) (i64.const 0)))"#;
        let m = wat::parse_str(wat).unwrap();
        assert!(verify_no_user_calls(&m).unwrap().is_empty());
    }

    #[test]
    fn undecodable_module_is_an_error_for_the_call_check_too() {
        assert!(verify_no_user_calls(b"not wasm at all").is_err());
        assert!(verify_no_user_calls(b"\0asm\x01\x00\x00\x00\xff\xff\xff").is_err());
    }

    /// FAIL CLOSED: an undecodable module is never "fine". Returning Ok(vec![])
    /// here would let a corrupt module through the one gate meant to stop it.
    #[test]
    fn undecodable_module_is_an_error_not_a_pass() {
        assert!(verify_byte_adjacency(b"\0asm\x01\x00\x00\x00\xff\xff\xff").is_err());
        assert!(verify_byte_adjacency(b"not wasm at all").is_err());
    }
}
