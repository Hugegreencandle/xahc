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

use anyhow::{bail, Context, Result};
use owo_colors::OwoColorize;
use std::path::PathBuf;
use std::process::Command;

pub fn run(args: &[String]) -> Result<i32> {
    // `reverify` is orchestrated in Rust (it must re-run the prover via prove::run); every other
    // subcommand is a thin passthrough to the prover's python registry CLI. Detect `reverify`
    // anywhere (a global `--store` may precede it), then hand the rest to the Rust handler.
    if args.iter().any(|s| s == "reverify") {
        let rest: Vec<String> = args.iter().filter(|s| *s != "reverify").cloned().collect();
        return reverify(&rest);
    }

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

/// `xahc registry reverify <hook.wasm> [--store P]` — independently RE-DERIVE the registered
/// proofs by re-running the open, deterministic prover on the bytecode for each registered
/// invariant (with its recorded prover args) and confirming the verdict reproduces.
///
/// HONEST SCOPE: this re-runs the prover ("re-derive it yourself with the open tool"), it does
/// NOT check a standalone Z3 proof object (that re-checkable-artifact step is future work). It
/// upgrades the trust model from "trust the attester" to "trust the open, deterministic prover —
/// and here's the one command to reproduce the result." A reproduced PROVEN is the all-clear; any
/// invariant that fails to reproduce is a loud MISMATCH (the attestation does not hold up).
fn reverify(args: &[String]) -> Result<i32> {
    let mut wasm: Option<PathBuf> = None;
    let mut store: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--store" => {
                store = Some(args.get(i + 1).cloned().context("--store requires a path value")?);
                i += 2;
            }
            s if !s.starts_with("--") && wasm.is_none() => {
                wasm = Some(PathBuf::from(s));
                i += 1;
            }
            _ => i += 1,
        }
    }
    let wasm = wasm.context("usage: xahc registry reverify <hook.wasm> [--store P]")?;
    if !wasm.is_file() {
        bail!("hook wasm not found: {}", wasm.display());
    }

    let dir = crate::prove::prover_dir()?;
    let py = crate::prove::python(&dir);

    // 1) Ask the registry what's on record for this bytecode (resolves wasm -> HookHash -> status).
    let mut q = Command::new(&py);
    q.env("PYTHONPATH", dir.join("src")).arg("-m").arg("registry");
    // `--store` is a GLOBAL option on the python CLI — it must precede the subcommand.
    if let Some(s) = &store {
        q.arg("--store").arg(s);
    }
    q.arg("check").arg(&wasm).arg("--json");
    let out = q.output().with_context(|| "failed to query the proof registry")?;
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)
        .with_context(|| "could not parse registry check output")?;

    let status = report.get("status").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
    let hook_hash = report.get("hook_hash").and_then(|v| v.as_str()).unwrap_or("");
    if status != "PROVEN" {
        println!("{}  {}…  ({})", "○ NOTHING TO REVERIFY".yellow().bold(),
            &hook_hash.chars().take(16).collect::<String>(), status);
        println!("  {}", report.get("detail").and_then(|v| v.as_str()).unwrap_or("not PROVEN on record"));
        return Ok(2);
    }

    let empty = vec![];
    let proofs = report.get("proofs").and_then(|v| v.as_array()).unwrap_or(&empty);
    if proofs.is_empty() {
        bail!("registry reports PROVEN but lists no proofs to reverify");
    }

    // 2) Re-derive each registered proof by re-running the prover on THIS bytecode.
    println!("reverifying {} proof(s) for hook {}… by re-running the prover\n",
        proofs.len(), &hook_hash.chars().take(16).collect::<String>());
    let mut all_match = true;
    let fail = "✗ DID NOT REPRODUCE".red().bold().to_string();
    for p in proofs {
        let inv = p.get("invariant").and_then(|v| v.as_str()).unwrap_or("");
        let rest: Vec<String> = p.get("prover_args").and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        // Fail closed per-proof: a malformed entry OR a prover error counts as "did not
        // reproduce" (never a silent pass), and we keep checking the remaining proofs.
        if inv.is_empty() {
            all_match = false;
            println!("  {} <malformed registry entry: missing invariant>", fail);
            continue;
        }
        let argnote = if rest.is_empty() { String::new() } else { format!(" [{}]", rest.join(" ")) };
        match crate::prove::run(&wasm, &crate::prove::Opts { invariant: inv, rest: &rest }) {
            // The registry only holds PROVEN; reproduction means re-running yields PROVEN (exit 0).
            Ok(0) => println!("  {} {}{}  (re-ran prover, exit 0)", "✓ REPRODUCED".green().bold(), inv, argnote),
            Ok(code) => {
                all_match = false;
                println!("  {} {}{}  (re-ran prover, exit {})", fail, inv, argnote, code);
            }
            Err(e) => {
                all_match = false;
                println!("  {} {}{}  (prover error: {})", fail, inv, argnote, e);
            }
        }
    }

    println!();
    if all_match {
        println!("{} every registered proof re-derived PROVEN on this bytecode \
                  (re-ran the open prover; did not trust the attestation).", "✓".green().bold());
        Ok(0)
    } else {
        println!("{} at least one registered proof did NOT reproduce — the attestation does not \
                  hold up for this bytecode. Investigate (tampered record, wrong wasm, or a prover \
                  change since the proof).", "✗".red().bold());
        Ok(2)
    }
}
