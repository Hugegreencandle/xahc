//! Rust reimplementation of hook-cleaner: make a clang-produced wasm acceptable
//! to xahaud's SetHook validator.
//!
//! xahaud rejects (temMALFORMED) a hook module that exports anything other than
//! the `hook`/`cbak` FUNCTIONS — in particular it must NOT export `memory`
//! (the host provides memory) or the compiler's globals. It also wants the
//! compiler's custom sections (`name`, `producers`, `target_features`) gone.
//! This was verified on Xahau testnet: a known-good mainnet hook installs, and
//! our output only installs once these are stripped.

use anyhow::{Context, Result};
use std::path::Path;
use walrus::{ExportItem, ModuleConfig};

use crate::lint::ALLOWED_EXPORT_FNS as ALLOWED;

pub fn run(input: &Path, output: &Path) -> Result<usize> {
    let wasm = std::fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let (bytes, removed) = clean_bytes(&wasm)?;
    std::fs::write(output, bytes).with_context(|| format!("write {}", output.display()))?;
    Ok(removed)
}

pub fn clean_bytes(wasm: &[u8]) -> Result<(Vec<u8>, usize)> {
    // Don't let walrus regenerate the name/producers custom sections on emit.
    let mut cfg = ModuleConfig::new();
    cfg.generate_name_section(false);
    cfg.generate_producers_section(false);
    let mut m = cfg.parse(wasm).context("parse wasm")?;

    // Keep ONLY the hook/cbak function exports. Everything else — `memory`,
    // exported globals/tables, linker artifacts — is stripped (xahaud rejects them).
    let to_remove: Vec<_> = m
        .exports
        .iter()
        .filter(|e| !matches!(&e.item, ExportItem::Function(_)) || !ALLOWED.contains(&e.name.as_str()))
        .map(|e| e.id())
        .collect();
    let removed = to_remove.len();
    for id in to_remove {
        m.exports.delete(id);
    }

    // Drop leftover compiler custom sections (target_features etc.).
    for name in ["target_features", "producers", "name"] {
        m.customs.remove_raw(name);
    }

    Ok((m.emit_wasm(), removed))
}
