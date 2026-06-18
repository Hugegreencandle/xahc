//! `xahc registry` — the Proof Registry: a tamper-evident, queryable record of
//! PROVEN hook proofs. Fifth leg: write → simulate → prove → watch → REGISTER.
//!
//! This is a thin passthrough to the prover's `python -m registry` CLI (it lives
//! beside the prover so it can read the ProofManifest the prover emits). The
//! prover checkout is resolved the same way `xahc prove` resolves it.
//!
//! Subcommands (forwarded verbatim):
//!   add <manifest.json> [--key K] [--store P]   register a PROVEN manifest (signed if a key)
//!   get <HookHash> [--json]                      proof status for a HookHash
//!   check <hook.wasm> [--json]                   resolve wasm → HookHash → status
//!   verify [--json]                              re-check the whole chain + signatures
//!   list [--json]                                per-hook rollup + head + integrity
//!   head                                         the head commitment (on-chain anchorable)
//!   keygen [--out keyfile]                       generate an Ed25519 attester key
//!
//! Exit code is propagated from the Python CLI (0 ok/PROVEN · 2 UNPROVEN/TAMPERED · 3 usage).

use anyhow::{Context, Result};
use std::process::Command;

pub fn run(args: &[String]) -> Result<i32> {
    let dir = crate::prove::prover_dir()?;
    let py = crate::prove::python(&dir);
    let src = dir.join("src");

    let mut cmd = Command::new(&py);
    // `-m registry` needs src/ on the import path (registry + its watch.manifest dep).
    cmd.env("PYTHONPATH", &src).arg("-m").arg("registry").args(args);
    let status = cmd
        .status()
        .with_context(|| format!("failed to run the proof registry ({})", py.display()))?;
    Ok(status.code().unwrap_or(1))
}
