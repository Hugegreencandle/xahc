//! build pipeline: C -> wasm (clang) -> clean (strip exports) -> lint.
//! Assumes a wasm-capable clang in PATH. We keep flags explicit so the
//! output matches what xahaud expects (freestanding, no builtins, wasm32).

use anyhow::{bail, Context, Result};
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{clean, lint};

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
    // Bundle our headers automatically if present next to the binary / repo.
    if let Some(inc) = locate_xahc_include() {
        cmd.arg(format!("-I{}", inc.display()));
    }
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

/// Look for the include/ dir: env override, then ./include, then ../../include.
fn locate_xahc_include() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("XAHC_INCLUDE") {
        let p = PathBuf::from(p);
        if p.is_dir() { return Some(p); }
    }
    for cand in ["include", "../include", "../../include"] {
        let p = Path::new(cand).join("xahc");
        if p.is_dir() { return Some(Path::new(cand).to_path_buf()); }
    }
    None
}
