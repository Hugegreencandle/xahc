//! build pipeline: C -> wasm (clang) -> clean (strip exports) -> lint.
//! Assumes a wasm-capable clang in PATH. We keep flags explicit so the
//! output matches what xahaud expects (freestanding, no builtins, wasm32).

use anyhow::{bail, Context, Result};
use include_dir::{include_dir, Dir};
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{clean, lint};

/// The safe-header library, embedded in the binary so an installed `xahc`
/// (cargo install / release tarball) is fully self-contained — no repo checkout.
static HEADERS: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../include");

pub fn run(input: &Path, output: &Path, extra_includes: &[PathBuf], do_lint: bool) -> Result<()> {
    let raw = output.with_extension("raw.wasm");

    let mut cmd = Command::new("clang");
    cmd.args([
        "--target=wasm32",
        "-O2",
        "-nostdlib",
        "-fno-builtin",
        "-Wl,--no-entry",
        "-Wl,--export-all",      // export hook/cbak regardless of visibility; clean strips the rest
        "-Wl,--allow-undefined", // host (env) imports resolved by xahaud
    ]);
    // Headers are embedded in the binary; materialize them and point clang there.
    let inc = materialize_headers().context("materialize xahc headers")?;
    cmd.arg(format!("-I{}", inc.display()));
    for inc in extra_includes {
        cmd.arg(format!("-I{}", inc.display()));
    }
    cmd.arg(input).arg("-o").arg(&raw);

    let status = cmd.status().context("run clang (is a wasm-capable clang in PATH?)")?;
    if !status.success() {
        bail!("clang failed");
    }

    // clean
    let wasm = std::fs::read(&raw)?;
    let (cleaned, removed) = clean::clean_bytes(&wasm)?;
    if removed > 0 {
        println!("{} stripped {} stray export(s)", "clean".green(), removed);
    }
    std::fs::write(output, &cleaned)?;
    let _ = std::fs::remove_file(&raw);

    // lint
    if do_lint {
        let findings = lint::lint(&cleaned)?;
        lint::report(&findings);
        if findings.iter().any(|f| f.level == lint::Level::Error) {
            bail!("lint failed — fix errors above before deploying");
        }
    }
    Ok(())
}

/// Materialize the embedded headers to a versioned cache dir and return the
/// include root (so `#include "xahc/xahc.h"` resolves). `XAHC_INCLUDE` overrides
/// (for developing the headers against a working tree).
pub fn materialize_headers() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("XAHC_INCLUDE") {
        let p = PathBuf::from(p);
        if p.join("xahc/xahc.h").exists() {
            return Ok(p);
        }
    }
    let root = cache_root()
        .join("xahc")
        .join(concat!("v", env!("CARGO_PKG_VERSION")))
        .join("include");
    if !root.join("xahc/xahc.h").exists() {
        std::fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
        HEADERS.extract(&root).context("extract embedded headers")?;
    }
    Ok(root)
}

fn cache_root() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_CACHE_HOME") {
        if !x.is_empty() {
            return PathBuf::from(x);
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h).join(".cache");
    }
    std::env::temp_dir()
}
