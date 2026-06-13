//! Rust reimplementation of hook-cleaner: drop exports a hook may not have.
//! Keeps `hook`, `cbak`, and the `memory` export; strips the rest
//! (compiler linking artifacts like __wasm_call_ctors, __heap_base, etc).

use anyhow::{Context, Result};
use std::path::Path;
use walrus::{ExportItem, Module};

use crate::lint::ALLOWED_EXPORT_FNS as ALLOWED;

pub fn run(input: &Path, output: &Path) -> Result<usize> {
    let wasm = std::fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let (bytes, removed) = clean_bytes(&wasm)?;
    std::fs::write(output, bytes).with_context(|| format!("write {}", output.display()))?;
    Ok(removed)
}

pub fn clean_bytes(wasm: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut m = Module::from_buffer(wasm).context("parse wasm")?;

    // Collect export ids to remove (can't mutate while iterating).
    let to_remove: Vec<_> = m
        .exports
        .iter()
        .filter(|e| match &e.item {
            ExportItem::Function(_) => !ALLOWED.contains(&e.name.as_str()),
            ExportItem::Memory(_) => false, // keep memory
            _ => true,                       // strip globals/tables exports
        })
        .map(|e| e.id())
        .collect();

    let removed = to_remove.len();
    for id in to_remove {
        m.exports.delete(id);
    }

    Ok((m.emit_wasm(), removed))
}
