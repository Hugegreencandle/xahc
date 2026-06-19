//! `xahc compose` — composition prover for a CHAIN of Hooks on one account.
//!
//! A Xahau account installs an ordered chain of up to 10 hooks. A strong-TSH hook that
//! calls `rollback()` aborts the whole transaction; `accept()` lets execution continue to
//! the next hook. So the transactions a chain lets through are the INTERSECTION of what
//! every hook accepts — and therefore every per-hook safety invariant (`accept ⟹ P`)
//! also holds for the chain. Composition = conjunction.
//!
//! That lift is only SOUND if the hooks don't interfere. The dominant interference vector
//! is shared Hook state: the prover models a hook's state by bare key, NOT by namespace,
//! so a per-hook state proof is only valid for the chain if stateful hooks use DISTINCT
//! `HookNamespace`s (Xahau partitions state by (account, namespace, key)). Two stateful
//! hooks sharing a namespace (incl. the all-zeros default) can clobber each other's state,
//! voiding the per-hook proofs. Emission is bounded per-hook by `etxn_reserve`, but a hook
//! that exports `cbak` and emits has an unmodeled dynamic re-entry chain — so a chain
//! containing one cannot get a static total-emit bound.
//!
//! This prover does NOT re-derive per-hook proofs symbolically — it PROVES each hook's
//! claimed invariant via `xahc prove` (the engine), then proves the COMPOSITION is sound:
//! every claimed invariant PROVEN + no namespace interference among stateful hooks. It is
//! fail-closed: any unproven hook, any shared-namespace stateful pair, or any unresolved
//! capability ⇒ the chain is NOT certified composable.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walrus::{ExportItem, ImportKind, Module};

#[derive(Deserialize)]
struct ChainSpec {
    #[allow(dead_code)]
    account: Option<String>,
    #[serde(rename = "hook")]
    hooks: Vec<HookSpec>,
}

#[derive(Deserialize)]
struct HookSpec {
    /// Path to the hook .wasm (relative to the chain file or cwd).
    wasm: String,
    /// 64-hex HookNamespace, OR namespace_label (sha256'd), OR neither (all-zeros default).
    namespace: Option<String>,
    namespace_label: Option<String>,
    /// Invariants this hook must satisfy in the chain (each is PROVEN via `xahc prove`).
    #[serde(default)]
    invariants: Vec<String>,
}

/// Static capability signal read from the wasm's import/export sections.
struct Caps {
    stateful: bool, // imports state_set / state_foreign_set (writes own-namespace state)
    foreign: bool,  // imports state_foreign_set (can write ANOTHER account/namespace's state)
    emits: bool,    // imports emit
    dynamic: bool,  // exports cbak (dynamic re-entry)
}

fn caps(wasm: &[u8]) -> Result<Caps> {
    // A malformed/unparseable wasm errors here (fail-closed) — never silently caps=false,
    // which would let a real state-writer dodge the interference check.
    let m = Module::from_buffer(wasm).context("parsing wasm for composition analysis")?;
    let imports: HashSet<String> = m
        .imports
        .iter()
        .filter(|i| i.module == "env" && matches!(i.kind, ImportKind::Function(_)))
        .map(|i| i.name.clone())
        .collect();
    let exports: HashSet<String> = m
        .exports
        .iter()
        .filter(|e| matches!(e.item, ExportItem::Function(_)))
        .map(|e| e.name.clone())
        .collect();
    Ok(Caps {
        stateful: imports.contains("state_set") || imports.contains("state_foreign_set"),
        foreign: imports.contains("state_foreign_set"),
        emits: imports.contains("emit"),
        dynamic: exports.contains("cbak"),
    })
}

/// Resolve a hook's namespace EXACTLY as install would: explicit hex, sha256(label), or
/// the all-zeros default. (Same code path keeps the interference check honest.)
fn resolve_namespace(h: &HookSpec) -> Result<String> {
    match (&h.namespace, &h.namespace_label) {
        (Some(_), Some(_)) => bail!("hook `{}`: set namespace OR namespace_label, not both", h.wasm),
        (Some(ns), None) => crate::installtx::norm_hex_namespace(ns),
        (None, Some(label)) => Ok(crate::installtx::sha256_hex(label)),
        (None, None) => Ok("0".repeat(64)),
    }
}

#[derive(Serialize)]
pub struct ComposeReport {
    pub chain_file: String,
    pub hooks: Vec<HookResult>,
    /// Invariants that hold for the WHOLE chain (the sound conjunction lift).
    pub chain_invariants: Vec<String>,
    pub composable: bool,
    /// "bounded" | "inconclusive (dynamic cbak emit in chain)" | "none (no emits)"
    pub emit_bound: String,
    pub reason: Option<String>,
    /// Stated residual: interference vectors the check does NOT model (never silently "safe").
    pub caveats: Vec<String>,
}

#[derive(Serialize)]
pub struct HookResult {
    pub wasm: String,
    pub namespace: String,
    pub stateful: bool,
    pub emits: bool,
    pub dynamic: bool,
    pub invariants: Vec<InvProof>,
}

#[derive(Serialize)]
pub struct InvProof {
    pub invariant: String,
    pub verdict: String,
    pub exit_code: i32,
}

pub fn run(chain_file: &Path) -> Result<ComposeReport> {
    let text = std::fs::read_to_string(chain_file)
        .with_context(|| format!("reading chain file {}", chain_file.display()))?;
    let spec: ChainSpec = toml::from_str(&text).context("parsing chain TOML")?;
    if spec.hooks.is_empty() {
        bail!("chain has no hooks");
    }
    let base = chain_file.parent().unwrap_or(Path::new("."));

    let mut hook_results = Vec::new();
    let mut all_proven = true;
    let mut chain_invariants: HashSet<String> = HashSet::new();
    // namespace -> first stateful hook using it (to report interference precisely)
    let mut stateful_ns: Vec<(String, String)> = Vec::new();
    let mut interference: Option<String> = None;
    let mut any_dynamic_emit = false;
    let mut any_emit = false;
    let mut foreign_writers: Vec<String> = Vec::new();

    for h in &spec.hooks {
        let wasm_path = resolve_path(base, &h.wasm);
        let bytes = std::fs::read(&wasm_path)
            .with_context(|| format!("reading hook wasm {}", wasm_path.display()))?;
        let c = caps(&bytes)?;
        let ns = resolve_namespace(h)?;
        any_emit |= c.emits;
        if c.emits && c.dynamic {
            any_dynamic_emit = true;
        }
        if c.foreign {
            foreign_writers.push(h.wasm.clone());
        }

        // Namespace interference: two STATEFUL hooks must not share a namespace.
        if c.stateful {
            if let Some((_, other)) = stateful_ns.iter().find(|(n, _)| *n == ns) {
                interference.get_or_insert(format!(
                    "stateful hooks `{}` and `{}` share HookNamespace {}… — per-hook state \
                     proofs do not compose (state can be clobbered). Give them distinct namespaces.",
                    other, h.wasm, &ns[..8.min(ns.len())]
                ));
            } else {
                stateful_ns.push((ns.clone(), h.wasm.clone()));
            }
        }

        // Prove each claimed invariant for this hook (the real engine, not a claim).
        let mut inv_proofs = Vec::new();
        for inv in &h.invariants {
            let code = crate::prove::run(&wasm_path, &crate::prove::Opts { invariant: inv, rest: &[] })?;
            let verdict = match code {
                0 => "PROVEN",
                2 => "COUNTEREXAMPLE",
                3 => "INCONCLUSIVE",
                _ => "ERROR",
            };
            if code != 0 {
                all_proven = false;
            } else {
                chain_invariants.insert(inv.clone());
            }
            inv_proofs.push(InvProof { invariant: inv.clone(), verdict: verdict.to_string(), exit_code: code });
        }

        hook_results.push(HookResult {
            wasm: h.wasm.clone(),
            namespace: ns,
            stateful: c.stateful,
            emits: c.emits,
            dynamic: c.dynamic,
            invariants: inv_proofs,
        });
    }

    // Verdict — fail-closed: any unproven hook OR any namespace interference ⇒ not composable.
    let (composable, reason) = if !all_proven {
        (false, Some("a hook's claimed invariant did not prove — the chain inherits nothing".into()))
    } else if let Some(why) = interference.clone() {
        (false, Some(why))
    } else {
        (true, None)
    };

    let emit_bound = if !any_emit {
        "none (no hook emits)".to_string()
    } else if any_dynamic_emit {
        "inconclusive (a hook exports cbak and emits — dynamic re-entry is unmodeled)".to_string()
    } else {
        "bounded (static per-hook etxn_reserve; chain total ≤ sum)".to_string()
    };

    let mut chain_inv: Vec<String> = if composable {
        chain_invariants.into_iter().collect()
    } else {
        Vec::new()
    };
    chain_inv.sort();

    // Stated residual: the interference check is same-account, namespace-local. A hook that
    // calls state_foreign_set can write ANOTHER account's (or namespace's) state — including
    // a sibling hook's slot — which this namespace-distinctness check does not model. Surface
    // it rather than imply the chain is interference-free.
    let mut caveats = Vec::new();
    if !foreign_writers.is_empty() {
        caveats.push(format!(
            "hook(s) [{}] use state_foreign_set — cross-account/foreign-namespace writes are \
             NOT modeled by the namespace-distinctness check; co-analyze if any foreign target \
             is another chain hook's (account, namespace).",
            foreign_writers.join(", ")
        ));
    }

    Ok(ComposeReport {
        chain_file: chain_file.display().to_string(),
        hooks: hook_results,
        chain_invariants: chain_inv,
        composable,
        emit_bound,
        reason,
        caveats,
    })
}

fn resolve_path(base: &Path, p: &str) -> PathBuf {
    let pb = PathBuf::from(p);
    if pb.is_absolute() {
        pb
    } else {
        base.join(pb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_namespace_is_zeros() {
        let h = HookSpec { wasm: "a.wasm".into(), namespace: None, namespace_label: None, invariants: vec![] };
        assert_eq!(resolve_namespace(&h).unwrap(), "0".repeat(64));
    }

    #[test]
    fn label_namespace_is_sha256_and_distinct_labels_differ() {
        let a = HookSpec { wasm: "a".into(), namespace: None, namespace_label: Some("alpha".into()), invariants: vec![] };
        let b = HookSpec { wasm: "b".into(), namespace: None, namespace_label: Some("beta".into()), invariants: vec![] };
        let na = resolve_namespace(&a).unwrap();
        let nb = resolve_namespace(&b).unwrap();
        assert_ne!(na, nb);
        assert_eq!(na.len(), 64);
    }

    #[test]
    fn default_and_explicit_zeros_namespace_compare_equal() {
        // Audit regression: the all-zeros default must compare EQUAL to an explicit
        // all-zeros namespace (so two stateful hooks sharing it are caught as interfering),
        // regardless of the normalization path. Zeros are case-neutral; this pins it.
        let default = HookSpec { wasm: "a".into(), namespace: None, namespace_label: None, invariants: vec![] };
        let explicit = HookSpec { wasm: "b".into(), namespace: Some("0".repeat(64)), namespace_label: None, invariants: vec![] };
        assert_eq!(resolve_namespace(&default).unwrap(), resolve_namespace(&explicit).unwrap());
    }

    #[test]
    fn namespace_resolution_is_case_normalized() {
        // lower/upper hex must resolve to the SAME namespace (on-chain they're identical),
        // so the interference comparison can't be fooled by case.
        let lo = HookSpec { wasm: "a".into(), namespace: Some("ab".repeat(32)), namespace_label: None, invariants: vec![] };
        let hi = HookSpec { wasm: "b".into(), namespace: Some("AB".repeat(32)), namespace_label: None, invariants: vec![] };
        assert_eq!(resolve_namespace(&lo).unwrap(), resolve_namespace(&hi).unwrap());
    }

    #[test]
    fn explicit_and_label_namespace_conflict_is_rejected() {
        let h = HookSpec {
            wasm: "a".into(),
            namespace: Some("00".repeat(32)),
            namespace_label: Some("x".into()),
            invariants: vec![],
        };
        assert!(resolve_namespace(&h).is_err());
    }
}
