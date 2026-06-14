//! `xahc prove` — prove an invariant holds for ALL inputs, via xahc-prover
//! (symbolic execution + Z3). This shells out to the Python prover; the verdict's
//! exit code is propagated (0 PROVEN, 2 COUNTEREXAMPLE, 3 INCONCLUSIVE).

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Opts<'a> {
    pub invariant: &'a str,
    pub rest: &'a [String],
}

/// invariant name -> prover driver script
const INVARIANTS: &[(&str, &str)] = &[
    ("limit", "prove_limit.py"),
    ("guardrail", "prove_guardrail.py"),
    ("termination", "prove_termination.py"),
    ("monotonic", "prove_monotonic.py"),
    ("nospend", "prove_nospend.py"),
    ("conservation", "prove_conservation.py"),
];

fn prover_dir() -> Result<PathBuf> {
    if let Ok(d) = std::env::var("XAHC_PROVER_DIR") {
        let p = PathBuf::from(d);
        if p.join("src").is_dir() {
            return Ok(p);
        }
        bail!("XAHC_PROVER_DIR={} has no src/ — not an xahc-prover checkout", p.display());
    }
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        cands.push(PathBuf::from(&home).join("Desktop/xahc-prover"));
        cands.push(PathBuf::from(&home).join("xahc-prover"));
    }
    cands.push(PathBuf::from("../xahc-prover"));
    cands.push(PathBuf::from("xahc-prover"));
    for c in cands {
        if c.join("src").is_dir() {
            return Ok(c);
        }
    }
    bail!(
        "xahc-prover not found. Clone it and set XAHC_PROVER_DIR=/path/to/xahc-prover\n  \
         https://github.com/Hugegreencandle/xahc-prover"
    )
}

/// Prefer the prover's venv interpreter (it has z3), else fall back to python3.
fn python(dir: &Path) -> PathBuf {
    let venv = dir.join(".venv/bin/python");
    if venv.exists() {
        venv
    } else {
        PathBuf::from("python3")
    }
}

pub fn run(input: &Path, opts: &Opts) -> Result<i32> {
    let script = INVARIANTS
        .iter()
        .find(|(k, _)| *k == opts.invariant)
        .map(|(_, s)| *s)
        .with_context(|| {
            format!(
                "unknown invariant '{}'. one of: {}",
                opts.invariant,
                INVARIANTS.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(", ")
            )
        })?;

    let dir = prover_dir()?;
    let py = python(&dir);

    // A .c input is built to a temporary .wasm first; a .wasm is proven directly.
    let wasm: PathBuf = if input.extension().is_some_and(|e| e == "c") {
        let out = std::env::temp_dir().join(format!("xahc_prove_{}.wasm", std::process::id()));
        crate::build::run(input, &out, &[], true)?;
        out
    } else {
        input.to_path_buf()
    };

    let mut cmd = Command::new(&py);
    cmd.arg(dir.join("src").join(script)).arg(&wasm).args(opts.rest);
    let status = cmd
        .status()
        .with_context(|| format!("failed to run the prover ({})", py.display()))?;
    Ok(status.code().unwrap_or(1))
}
