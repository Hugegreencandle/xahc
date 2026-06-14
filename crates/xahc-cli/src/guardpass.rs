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
}

pub fn reposition(wasm: &[u8]) -> Result<(Vec<u8>, Report)> {
    let mut m = Module::from_buffer(wasm).context("parse wasm")?;
    let g = match find_g(&m) {
        Some(g) => g,
        None => {
            // No guard import at all → no loops to guard (or an unguarded hook,
            // which lint catches separately). Pass through unchanged.
            return Ok((m.emit_wasm(), Report { repositioned: 0, already_ok: 0, unguarded_loops: 0, skipped: 0 }));
        }
    };

    let mut rep = Report { repositioned: 0, already_ok: 0, unguarded_loops: 0, skipped: 0 };

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
}

/// Within one loop body sequence, hoist the `_g` guard block to the front.
fn hoist_guard_in_seq(lf: &mut walrus::LocalFunction, seq: InstrSeqId, g: FunctionId) -> Hoist {
    let instrs = &mut lf.block_mut(seq).instrs;

    let ci = match instrs
        .iter()
        .position(|(i, _)| matches!(i, Instr::Call(c) if c.func == g))
    {
        Some(ci) => ci,
        None => return Hoist::NoGuard,
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
