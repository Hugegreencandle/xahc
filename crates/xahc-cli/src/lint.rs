//! Static checks the on-chain validator would otherwise reject your hook for —
//! caught locally, before deploy.

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use serde::Serialize;
use std::path::Path;
use walrus::ir::{Instr, InstrSeqId};
use walrus::{ExportItem, FunctionId, FunctionKind, ImportKind, LocalFunction, Module};

/// Functions a hook is allowed to export. Anything else => on-chain rejection.
pub const ALLOWED_EXPORT_FNS: &[&str] = &["hook", "cbak"];

/// The Hook API host-function surface. Every `env` import must be one of these.
/// Source of truth: Xahau `extern.h`. Keep in sync as the API grows.
pub const HOOK_API: &[&str] = &[
    "_g", "accept", "emit", "etxn_burden", "etxn_details", "etxn_fee_base",
    "etxn_generation", "etxn_nonce", "etxn_reserve", "fee_base",
    "float_compare", "float_divide", "float_exponent", "float_exponent_set",
    "float_int", "float_invert", "float_log", "float_mantissa",
    "float_mantissa_set", "float_mulratio", "float_multiply", "float_negate",
    "float_one", "float_root", "float_set", "float_sign", "float_sign_set",
    "float_sto", "float_sto_set", "float_sum",
    "hook_account", "hook_again", "hook_hash", "hook_param", "hook_param_set",
    "hook_pos", "hook_skip",
    "ledger_keylet", "ledger_last_hash", "ledger_last_time", "ledger_nonce",
    "ledger_seq", "meta_slot",
    "otxn_burden", "otxn_field", "otxn_field_txt", "otxn_generation", "otxn_id",
    "otxn_param", "otxn_slot", "otxn_type",
    "rollback",
    "slot", "slot_clear", "slot_count", "slot_float", "slot_id", "slot_set",
    "slot_size", "slot_subarray", "slot_subfield", "slot_type",
    "state", "state_foreign", "state_foreign_set", "state_set",
    "sto_emplace", "sto_erase", "sto_subarray", "sto_subfield", "sto_validate",
    "trace", "trace_float", "trace_num", "trace_slot",
    "util_accid", "util_keylet", "util_raddr", "util_sha512h", "util_verify",
];

#[derive(PartialEq, Eq, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level { Error, Warn }

/// Stable machine-routable rule identifiers. Treat these as a COMPATIBILITY
/// CONTRACT — xahau-mcp, CI gates, and any `--json` consumer key on them, so do
/// not rename casually. The human `msg` may change freely; the `rule_id` is fixed.
#[derive(Serialize)]
pub struct Finding {
    pub level: Level,
    pub rule_id: &'static str,
    pub msg: String,
}

impl Finding {
    pub fn error(rule_id: &'static str, msg: impl Into<String>) -> Self {
        Finding { level: Level::Error, rule_id, msg: msg.into() }
    }
    pub fn warn(rule_id: &'static str, msg: impl Into<String>) -> Self {
        Finding { level: Level::Warn, rule_id, msg: msg.into() }
    }
}

pub fn lint_file(path: &Path) -> Result<Vec<Finding>> {
    let wasm = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    lint(&wasm)
}

pub fn lint(wasm: &[u8]) -> Result<Vec<Finding>> {
    let m = Module::from_buffer(wasm).context("parse wasm")?;
    let mut f = Vec::new();

    // 1. Exactly the allowed exports — stray exports are the classic silent reject.
    let mut has_hook = false;
    for e in m.exports.iter() {
        match &e.item {
            ExportItem::Function(_) => {
                if e.name == "hook" { has_hook = true; }
                if !ALLOWED_EXPORT_FNS.contains(&e.name.as_str()) {
                    f.push(Finding::error("ILLEGAL_EXPORT", format!(
                        "illegal export `{}` — run `xahc clean` or it will be rejected on-chain", e.name)));
                }
            }
            ExportItem::Memory(_) => { /* `memory` export is fine */ }
            _ => f.push(Finding::error("ILLEGAL_NONFN_EXPORT", format!(
                "illegal export `{}` (non-function/memory) — will be rejected", e.name))),
        }
    }
    if !has_hook {
        f.push(Finding::error("NO_HOOK_EXPORT", "no `hook` export — every hook must export `hook`"));
    }

    // 2. Every host import must be a real Hook API function.
    let mut imports_g = false;
    for imp in m.imports.iter() {
        if imp.module != "env" {
            f.push(Finding::error("NON_ENV_IMPORT", format!(
                "import from `{}` — only `env` (Hook API) imports allowed", imp.module)));
            continue;
        }
        if imp.name == "_g" { imports_g = true; }
        if !HOOK_API.contains(&imp.name.as_str()) {
            f.push(Finding::error("UNKNOWN_HOST_IMPORT", format!(
                "unknown host import `env.{}` — not in the Hook API", imp.name)));
        }
    }

    // 3. Guard function must be imported. No `_g` => no guards => rejected.
    if !imports_g {
        f.push(Finding::error("NO_G_IMPORT", "no `_g` import — hook declares no guards, will be rejected"));
    }

    // 4. Guard-presence per loop: every wasm `loop` must call `_g` directly in
    //    its body, or the on-chain validator rejects the hook.
    if let Some(g) = find_g(&m) {
        f.extend(check_guards(&m, g));
    }

    // 5. Stack budget: hooks have no heap; deep/large stack frames overflow.
    f.extend(check_stack(&m));

    Ok(f)
}

/// FunctionId of the imported guard function `env._g`, if present.
fn find_g(m: &Module) -> Option<FunctionId> {
    m.imports.iter().find_map(|imp| {
        if imp.module == "env" && imp.name == "_g" {
            if let ImportKind::Function(fid) = imp.kind {
                return Some(fid);
            }
        }
        None
    })
}

/// Walk every local function; flag any `loop` whose body has no direct call to `_g`.
fn check_guards(m: &Module, g: FunctionId) -> Vec<Finding> {
    let mut out = Vec::new();
    for func in m.funcs.iter() {
        if let FunctionKind::Local(lf) = &func.kind {
            let label = func.name.clone().unwrap_or_else(|| format!("#{:?}", func.id()));
            walk_seq(lf, lf.entry_block(), g, &label, &mut out);
        }
    }
    out
}

enum GuardPos {
    /// the first branch in the loop body is `call _g` — xahaud-compliant
    Compliant,
    /// a `_g` exists in the loop but a non-guard branch comes first
    Mispositioned,
    /// no `_g` call in the loop body at all
    NoGuard,
}

/// A control-transfer / call instruction. xahaud's rule: only NON-branch
/// instructions (const, local.*, arithmetic) may precede the guard `_g` in a loop.
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

/// xahaud requires the FIRST branch instruction in a loop body to be `call _g`.
fn loop_guard_pos(lf: &LocalFunction, seq: InstrSeqId, g: FunctionId) -> GuardPos {
    let instrs = &lf.block(seq).instrs;
    for (instr, _) in instrs.iter() {
        if matches!(instr, Instr::Call(c) if c.func == g) {
            return GuardPos::Compliant; // guard is the first branch reached
        }
        if is_branch(instr) {
            // a non-guard branch came first — is the guard present (just late) or missing?
            let has_g = instrs
                .iter()
                .any(|(i, _)| matches!(i, Instr::Call(c) if c.func == g));
            return if has_g { GuardPos::Mispositioned } else { GuardPos::NoGuard };
        }
        // non-branch instruction (const/local/arith) — allowed before the guard
    }
    GuardPos::NoGuard
}

/// Recurse the structured IR. On each `loop`, require a direct `_g` call.
fn walk_seq(lf: &LocalFunction, seq: InstrSeqId, g: FunctionId, label: &str, out: &mut Vec<Finding>) {
    for (instr, _) in lf.block(seq).instrs.iter() {
        match instr {
            Instr::Loop(l) => {
                match loop_guard_pos(lf, l.seq, g) {
                    GuardPos::Compliant => {}
                    GuardPos::Mispositioned => out.push(Finding::error(
                        "GUARD_NOT_FIRST",
                        format!(
                            "guard in `{}` is not the first instruction in the loop — xahaud \
                             requires `_g` to be the first branch in a loop or it rejects the \
                             hook (temMALFORMED). `xahc build` repositions it automatically; for a \
                             hand-built wasm, put XAHC_GUARD() at the loop head.",
                            label
                        ),
                    )),
                    GuardPos::NoGuard => out.push(Finding::error(
                        "UNGUARDED_LOOP",
                        format!("unguarded loop in `{}` — add XAHC_GUARD(max) at the top of the loop (xahaud rejects unguarded loops: temMALFORMED)", label),
                    )),
                }
                walk_seq(lf, l.seq, g, label, out);
            }
            Instr::Block(b) => walk_seq(lf, b.seq, g, label, out),
            Instr::IfElse(ie) => {
                walk_seq(lf, ie.consequent, g, label, out);
                walk_seq(lf, ie.alternative, g, label, out);
            }
            _ => {}
        }
    }
}

/// Heuristic stack-budget analysis: hooks get no heap, so a deep call chain of
/// large stack frames overflows into data/heap and corrupts execution. We read
/// each function's frame size from its prologue (sp = sp - N), walk the call
/// graph for the deepest cumulative frame, and compare to the available stack
/// region (stack-pointer init - end of data).
fn check_stack(m: &Module) -> Vec<Finding> {
    use walrus::ConstExpr;
    use walrus::ir::Value;

    let mut out = Vec::new();

    // Stack pointer = the mutable i32 global with the largest constant init.
    let mut sp: Option<(walrus::GlobalId, i64)> = None;
    for g in m.globals.iter() {
        if g.ty == walrus::ValType::I32 && g.mutable {
            if let walrus::GlobalKind::Local(ConstExpr::Value(Value::I32(v))) = &g.kind {
                let v = *v as i64;
                if sp.is_none_or(|(_, cur)| v > cur) {
                    sp = Some((g.id(), v));
                }
            }
        }
    }
    let (sp_id, sp_init) = match sp {
        Some(x) => x,
        None => return out, // no detectable stack pointer; skip silently
    };

    // End of static data = max(offset + len) over active data segments.
    let mut data_end: i64 = 0;
    for d in m.data.iter() {
        if let walrus::DataKind::Active { offset: ConstExpr::Value(Value::I32(off)), .. } = &d.kind {
            data_end = data_end.max(*off as i64 + d.value.len() as i64);
        }
    }
    let available = (sp_init - data_end).max(0);
    if available == 0 {
        return out;
    }

    // Per-function frame size from prologue: sp_init pattern global.get(sp) ...
    // i32.const N ... i32.sub ... global.set(sp). Take the const feeding the sub.
    let frame_size = |lf: &LocalFunction| -> u32 {
        let seq = lf.block(lf.entry_block());
        let mut saw_sp_get = false;
        let mut last_const: i64 = 0;
        let mut candidate: u32 = 0;
        for (instr, _) in seq.instrs.iter() {
            match instr {
                Instr::GlobalGet(gg) if gg.global == sp_id => saw_sp_get = true,
                Instr::Const(c) => {
                    if let Value::I32(n) = c.value { last_const = n as i64; }
                }
                Instr::Binop(b)
                    if matches!(b.op, walrus::ir::BinaryOp::I32Sub)
                        && saw_sp_get
                        && last_const > 0 =>
                {
                    candidate = candidate.max(last_const as u32);
                }
                _ => {}
            }
        }
        candidate
    };

    // Build frame map + call edges (local callees only).
    let mut frames: std::collections::HashMap<FunctionId, u32> = Default::default();
    let mut edges: std::collections::HashMap<FunctionId, Vec<FunctionId>> = Default::default();
    for func in m.funcs.iter() {
        if let FunctionKind::Local(lf) = &func.kind {
            frames.insert(func.id(), frame_size(lf));
            let mut callees = Vec::new();
            collect_calls(lf, lf.entry_block(), &mut callees);
            edges.insert(func.id(), callees);
        }
    }

    // Deepest cumulative frame from each root, with cycle (recursion) detection.
    let mut recursion = false;
    let mut memo: std::collections::HashMap<FunctionId, u32> = Default::default();
    let mut deepest = 0u32;
    let roots: Vec<FunctionId> = m
        .exports
        .iter()
        .filter_map(|e| match e.item {
            ExportItem::Function(fid) if e.name == "hook" || e.name == "cbak" => Some(fid),
            _ => None,
        })
        .collect();
    for r in roots {
        let mut stack = std::collections::HashSet::new();
        deepest = deepest.max(deepest_chain(r, &frames, &edges, &mut memo, &mut stack, &mut recursion));
    }

    if recursion {
        out.push(Finding::warn("RECURSION",
            "recursion detected in call graph — stack-budget analysis is unbounded; hooks should not recurse",
        ));
    }
    let pct = (deepest as f64 / available as f64) * 100.0;
    if deepest as i64 > available {
        out.push(Finding::warn("STACK_OVERFLOW", format!(
            "stack may overflow: deepest call chain ~{} bytes > available stack {} bytes (sp_init {} - data {})",
            deepest, available, sp_init, data_end
        )));
    } else if pct >= 80.0 {
        out.push(Finding::warn("STACK_HIGH", format!(
            "stack usage high: deepest call chain ~{} bytes is {:.0}% of {} available",
            deepest, pct, available
        )));
    }
    out
}

fn collect_calls(lf: &LocalFunction, seq: InstrSeqId, out: &mut Vec<FunctionId>) {
    for (instr, _) in lf.block(seq).instrs.iter() {
        match instr {
            Instr::Call(c) => out.push(c.func),
            Instr::Loop(l) => collect_calls(lf, l.seq, out),
            Instr::Block(b) => collect_calls(lf, b.seq, out),
            Instr::IfElse(ie) => {
                collect_calls(lf, ie.consequent, out);
                collect_calls(lf, ie.alternative, out);
            }
            _ => {}
        }
    }
}

fn deepest_chain(
    f: FunctionId,
    frames: &std::collections::HashMap<FunctionId, u32>,
    edges: &std::collections::HashMap<FunctionId, Vec<FunctionId>>,
    memo: &mut std::collections::HashMap<FunctionId, u32>,
    on_stack: &mut std::collections::HashSet<FunctionId>,
    recursion: &mut bool,
) -> u32 {
    let own = *frames.get(&f).unwrap_or(&0);
    if on_stack.contains(&f) {
        *recursion = true;
        return own; // break the cycle
    }
    if let Some(&v) = memo.get(&f) {
        return v;
    }
    on_stack.insert(f);
    let mut max_child = 0u32;
    if let Some(cs) = edges.get(&f) {
        for &c in cs {
            if frames.contains_key(&c) {
                max_child = max_child.max(deepest_chain(c, frames, edges, memo, on_stack, recursion));
            }
        }
    }
    on_stack.remove(&f);
    let total = own.saturating_add(max_child);
    memo.insert(f, total);
    total
}

pub fn report(findings: &[Finding]) {
    if findings.is_empty() {
        println!("{} no issues", "lint".green().bold());
        return;
    }
    for fd in findings {
        match fd.level {
            Level::Error => println!("{} {}", "error".red().bold(), fd.msg),
            Level::Warn => println!("{} {}", "warn".yellow().bold(), fd.msg),
        }
    }
    let errs = findings.iter().filter(|f| f.level == Level::Error).count();
    let warns = findings.len() - errs;
    println!("{} error(s), {} warning(s)", errs, warns);
}

/// Same as `report` but to stderr — used by `build` (whose lint is a diagnostic
/// sub-step), so `xahc build --json` keeps machine output clean on stdout.
pub fn report_stderr(findings: &[Finding]) {
    if findings.is_empty() {
        eprintln!("{} no issues", "lint".green().bold());
        return;
    }
    for fd in findings {
        match fd.level {
            Level::Error => eprintln!("{} {}", "error".red().bold(), fd.msg),
            Level::Warn => eprintln!("{} {}", "warn".yellow().bold(), fd.msg),
        }
    }
    let errs = findings.iter().filter(|f| f.level == Level::Error).count();
    let warns = findings.len() - errs;
    eprintln!("{} error(s), {} warning(s)", errs, warns);
}
