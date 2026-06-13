//! Static checks the on-chain validator would otherwise reject your hook for —
//! caught locally, before deploy.

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
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

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Level { Error, Warn }

pub struct Finding {
    pub level: Level,
    pub msg: String,
}

impl Finding {
    pub fn error(msg: impl Into<String>) -> Self { Finding { level: Level::Error, msg: msg.into() } }
    pub fn warn(msg: impl Into<String>) -> Self { Finding { level: Level::Warn, msg: msg.into() } }
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
                    f.push(Finding::error(format!(
                        "illegal export `{}` — run `xahc clean` or it will be rejected on-chain", e.name)));
                }
            }
            ExportItem::Memory(_) => { /* `memory` export is fine */ }
            _ => f.push(Finding::error(format!(
                "illegal export `{}` (non-function/memory) — will be rejected", e.name))),
        }
    }
    if !has_hook {
        f.push(Finding::error("no `hook` export — every hook must export `hook`"));
    }

    // 2. Every host import must be a real Hook API function.
    let mut imports_g = false;
    for imp in m.imports.iter() {
        if imp.module != "env" {
            f.push(Finding::error(format!(
                "import from `{}` — only `env` (Hook API) imports allowed", imp.module)));
            continue;
        }
        if imp.name == "_g" { imports_g = true; }
        if !HOOK_API.contains(&imp.name.as_str()) {
            f.push(Finding::error(format!(
                "unknown host import `env.{}` — not in the Hook API", imp.name)));
        }
    }

    // 3. Guard function must be imported. No `_g` => no guards => rejected.
    if !imports_g {
        f.push(Finding::error("no `_g` import — hook declares no guards, will be rejected"));
    }

    // 4. Guard-presence per loop: every wasm `loop` must call `_g` directly in
    //    its body, or the on-chain validator rejects the hook.
    if let Some(g) = find_g(&m) {
        f.extend(check_guards(&m, g));
    }

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

/// Does this instruction sequence directly (not in a nested seq) call `_g`?
fn directly_guards(lf: &LocalFunction, seq: InstrSeqId, g: FunctionId) -> bool {
    lf.block(seq)
        .instrs
        .iter()
        .any(|(instr, _)| matches!(instr, Instr::Call(c) if c.func == g))
}

/// Recurse the structured IR. On each `loop`, require a direct `_g` call.
fn walk_seq(lf: &LocalFunction, seq: InstrSeqId, g: FunctionId, label: &str, out: &mut Vec<Finding>) {
    for (instr, _) in lf.block(seq).instrs.iter() {
        match instr {
            Instr::Loop(l) => {
                if !directly_guards(lf, l.seq, g) {
                    out.push(Finding::warn(format!(
                        "unguarded loop in `{}` — add XAHC_GUARD(max) at the top of the loop \
                         (heuristic: looks for a direct `_g` call in the loop body)",
                        label
                    )));
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
