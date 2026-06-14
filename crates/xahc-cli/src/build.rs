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
        // -O2 is fine: the guard-reposition pass (see guardpass) hoists each
        // loop's `_g` back to the loop head after the optimizer's loop rotation,
        // satisfying xahaud's guard rule. (A guarded source loop contains the
        // `_g` call, which blocks loop-idiom recognition, so the optimizer won't
        // synthesize an unguarded memset/memcpy loop from it.)
        "-O2",
        "-nostdlib",
        "-fno-builtin",
        "-Wl,--no-entry",
        // Export ONLY hook (required) + cbak (if present), and garbage-collect
        // everything else. Without --gc-sections, lld leaves dead functions like
        // __wasm_call_ctors in the module; xahaud validates EVERY function and
        // rejects the unguarded dead one (temMALFORMED on SetHook). Verified on
        // Xahau testnet: hooks only install once these dead functions are GC'd.
        "-Wl,--gc-sections",
        "-Wl,--export=hook",
        "-Wl,--export-if-defined=cbak",
        "-Wl,--allow-undefined", // host (env) imports resolved by xahaud
    ]);
    // Headers are embedded in the binary; materialize them and point clang there.
    let inc = materialize_headers().context("materialize xahc headers")?;
    cmd.arg(format!("-I{}", inc.display()));
    for inc in extra_includes {
        cmd.arg(format!("-I{}", inc.display()));
    }
    cmd.arg(input).arg("-o").arg(&raw);

    let status = cmd
        .status()
        .context("could not run `clang` — is clang installed and on PATH?")?;
    if !status.success() {
        // The most common build failure on macOS is Apple's system clang, which
        // lacks the wasm32 target (`--target=wasm32` then errors). Point the user
        // at a wasm-capable clang explicitly rather than just "clang failed".
        bail!(
            "clang failed to compile to wasm32. The most likely cause is a clang \
             without wasm32 support (Apple's system clang lacks it). Install LLVM \
             and put its clang first on PATH, e.g.:\n  \
             brew install llvm && export PATH=\"/opt/homebrew/opt/llvm/bin:$PATH\"\n\
             Then re-run `xahc build`. (Run `xahc doctor` to check your toolchain.)"
        );
    }

    // guard-reposition: hoist each loop's `_g` to the loop head (the optimizer
    // may have rotated it to the bottom), satisfying xahaud's guard rule.
    let wasm = std::fs::read(&raw)?;
    let (guarded, grep) = crate::guardpass::reposition(&wasm)?;
    if grep.repositioned > 0 {
        println!("{} repositioned {} guard(s) to loop head", "guard".green(), grep.repositioned);
    }
    if grep.unguarded_loops > 0 {
        println!(
            "{} {} loop(s) without a `_g` guard — xahaud will reject; add XAHC_GUARD()",
            "warn".yellow(), grep.unguarded_loops
        );
    }
    if grep.skipped > 0 {
        println!(
            "{} {} loop guard(s) had non-literal args, left in place — may be rejected on-chain; verify on testnet",
            "warn".yellow(), grep.skipped
        );
    }

    // clean
    let (cleaned, removed) = clean::clean_bytes(&guarded)?;
    if removed > 0 {
        // Diagnostic, not data — stderr keeps `xahc build --json` stdout clean.
        eprintln!("{} stripped {} stray export(s)", "clean".green(), removed);
    }
    std::fs::write(output, &cleaned)?;
    let _ = std::fs::remove_file(&raw);

    // lint
    if do_lint {
        let findings = lint::lint(&cleaned)?;
        lint::report_stderr(&findings);
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
