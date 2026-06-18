//! `xahc author` — self-certifying Hook generator (intent → invariant → proven Hook).
//!
//! The front of the pipeline: **AUTHOR → build → prove → (watch) → register.**
//!
//! You describe what you want ("limit payments to 5 XAH", "owner-only", "lock spends to
//! one destination"); xahc-author maps that to a proven-safe archetype, builds it, and
//! then PROVES the invariant(s) that archetype is supposed to guarantee. It only emits a
//! "certified" hook if every required invariant comes back PROVEN — otherwise it refuses
//! (fail-closed). The certification is the *live proof*, never a claim baked into a template.
//!
//! Why this is sound: the prover proves invariants *parametrically* (e.g. `accept ⟹ drops
//! ≤ LIM` for ALL values of the LIM hook-parameter), so one proof covers every parameter
//! value. The concrete value the user asked for is baked into the SetHook install-tx at the
//! end — it never affects the proof. And the C template is pulled from the prover's own
//! proven `hooks/` so the bytecode we certify is the exact source the engine reasons about
//! (no template drift). xahc-author requires the prover checkout — it cannot certify without it.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::PathBuf;

/// A hook parameter the user can set at install time (baked into SetHook, not the proof).
pub struct ParamSpec {
    /// 3-char hook-param key, e.g. "LIM" or "DST".
    pub key: &'static str,
    /// How to source it from the intent: a drops amount, or a destination r-address.
    pub kind: ParamKind,
    pub required: bool,
}

pub enum ParamKind {
    /// An 8-byte big-endian drops amount, parsed from "<n> XAH" or "<n> drops" in the intent.
    Drops,
    /// A 20-byte destination accountID, from an r-address in the intent.
    DestAddr,
}

/// A proven-safe archetype: an intent maps here, we prove `invariants`, set `params`.
pub struct Archetype {
    pub name: &'static str,
    /// The proven C source in the prover's hooks/ dir (zero-drift: the exact source proven).
    pub hook_src: &'static str,
    /// Keywords that pull an intent toward this archetype (scored).
    pub keywords: &'static [&'static str],
    /// Invariants that MUST all return PROVEN for this hook to be certified.
    pub invariants: &'static [&'static str],
    pub params: &'static [ParamSpec],
    pub summary: &'static str,
}

pub const CATALOG: &[Archetype] = &[
    Archetype {
        name: "spend-limit",
        hook_src: "limit.c",
        keywords: &["limit", "cap", "max", "most", "ceiling", "no more than", "at most", "under"],
        invariants: &["limit"],
        params: &[ParamSpec { key: "LIM", kind: ParamKind::Drops, required: true }],
        summary: "accept ⟹ payment drops ≤ LIM (per-tx spend cap)",
    },
    Archetype {
        name: "agent-guardrail",
        hook_src: "agent_guardrail.c",
        keywords: &["guardrail", "agent", "allowlist", "only to", "lock to", "destination",
                    "whitelist", "budget"],
        invariants: &["guardrail"],
        params: &[
            ParamSpec { key: "LIM", kind: ParamKind::Drops, required: true },
            ParamSpec { key: "DST", kind: ParamKind::DestAddr, required: false },
        ],
        summary: "accept ⟹ spend ≤ LIM AND destination ∈ {DST} (agent spending guard)",
    },
    Archetype {
        name: "owner-only",
        hook_src: "authz.c",
        keywords: &["owner", "owner-only", "only me", "only the owner", "authorize", "authz",
                    "permission", "only owner"],
        invariants: &["authz"],
        params: &[],
        summary: "accept ⟹ originating account == hook owner (owner-only gate)",
    },
    Archetype {
        name: "replay-guard",
        hook_src: "monotonic.c",
        keywords: &["replay", "nonce", "monotonic", "once", "no replay", "increment", "sequence"],
        invariants: &["monotonic"],
        params: &[ParamSpec { key: "NON", kind: ParamKind::Drops, required: true }],
        summary: "accept ⟹ incoming nonce strictly exceeds stored nonce (replay protection)",
    },
    Archetype {
        name: "overflow-safe-limit",
        hook_src: "overflow.c",
        keywords: &["overflow", "wrap", "tip", "safe limit", "drops plus", "no overflow"],
        invariants: &["overflow"],
        params: &[
            ParamSpec { key: "LIM", kind: ParamKind::Drops, required: true },
            ParamSpec { key: "TIP", kind: ParamKind::Drops, required: false },
        ],
        summary: "accept ⟹ (drops + tip) ≤ LIM with no uint64 wrap bypass",
    },
];

#[derive(Serialize)]
pub struct AuthorReport {
    pub intent: String,
    pub archetype: String,
    /// The invariant guarantee this archetype certifies, in plain English.
    pub guarantee: String,
    pub hook_path: String,
    pub wasm_path: String,
    pub invariants: Vec<InvariantResult>,
    pub certified: bool,
    pub install_tx: Option<String>,
    pub registered: bool,
}

#[derive(Serialize)]
pub struct InvariantResult {
    pub invariant: String,
    pub verdict: String,
    pub exit_code: i32,
}

pub struct Opts<'a> {
    pub intent: &'a str,
    pub name: Option<&'a str>,
    pub account: Option<&'a str>,
    pub network: &'a str,
    pub register: bool,
    pub key: Option<&'a str>,
}

/// Match a keyword against intent text. Multi-word keywords ("no more than") match as a
/// phrase substring; single words match on word boundaries so "limit" can't be triggered by
/// a larger word that merely contains those letters (no silent wrong-archetype selection).
fn matches_keyword(haystack: &str, kw: &str) -> bool {
    if kw.contains(' ') {
        return haystack.contains(kw);
    }
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(rel) = haystack[from..].find(kw) {
        let i = from + rel;
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let after = i + kw.len();
        let after_ok = after >= bytes.len() || !bytes[after].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
        if from >= haystack.len() {
            break;
        }
    }
    false
}

/// Resolve an intent string to exactly one archetype, fail-closed on ambiguity / no match.
pub fn resolve<'a>(intent: &str) -> Result<&'a Archetype> {
    let lc = intent.to_lowercase();
    let mut scored: Vec<(usize, &Archetype)> = CATALOG
        .iter()
        .map(|a| (a.keywords.iter().filter(|k| matches_keyword(&lc, k)).count(), a))
        .filter(|(n, _)| *n > 0)
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    match scored.as_slice() {
        [] => bail!(
            "could not map intent to a known archetype.\n  intents I understand: {}\n  \
             (be explicit, e.g. \"limit payments to 5 XAH\" or \"owner-only\")",
            CATALOG.iter().map(|a| a.name).collect::<Vec<_>>().join(", ")
        ),
        [(top, a)] => {
            let _ = top;
            Ok(a)
        }
        [(n0, a0), (n1, _a1), ..] => {
            if n0 == n1 {
                bail!(
                    "intent is ambiguous (ties between archetypes). Be more specific.\n  \
                     candidates: {}",
                    scored.iter().take(3).map(|(_, a)| a.name).collect::<Vec<_>>().join(", ")
                );
            }
            Ok(a0)
        }
    }
}

pub fn run(opts: &Opts) -> Result<AuthorReport> {
    let arch = resolve(opts.intent)?;
    // Fail-closed: a hook can only be "certified" by PROVING something. An archetype with
    // no invariants would sail through the (empty) prove loop with certified=true — refuse
    // it at runtime, not just in tests, so a future catalog edit can't ship an uncertified hook.
    if arch.invariants.is_empty() {
        bail!("archetype `{}` defines no invariant to prove — refusing to certify", arch.name);
    }
    let dir = crate::prove::prover_dir()?;
    let src = dir.join("hooks").join(arch.hook_src);
    if !src.is_file() {
        bail!("proven template {} not found in prover hooks/ ({})", arch.hook_src, src.display());
    }

    // 1) Materialize the proven C source as <name>.c (zero-drift copy).
    let name = opts.name.unwrap_or(arch.name);
    let hook_c = PathBuf::from(format!("{name}.c"));
    let wasm = PathBuf::from(format!("{name}.wasm"));
    std::fs::copy(&src, &hook_c)
        .with_context(|| format!("copying template {} -> {}", src.display(), hook_c.display()))?;

    // 2) Build to .wasm (clean + lint via the normal build path).
    crate::build::run(&hook_c, &wasm, &[], true)
        .with_context(|| "build failed — cannot certify a hook that does not compile clean")?;

    // 3) PROVE every required invariant. Fail-closed: any non-PROVEN ⇒ not certified.
    let mut results = Vec::new();
    let mut certified = true;
    for inv in arch.invariants {
        let code = crate::prove::run(&wasm, &crate::prove::Opts { invariant: inv, rest: &[] })?;
        let verdict = match code {
            0 => "PROVEN",
            2 => "COUNTEREXAMPLE",
            3 => "INCONCLUSIVE",
            _ => "ERROR",
        };
        if code != 0 {
            certified = false;
        }
        results.push(InvariantResult { invariant: inv.to_string(), verdict: verdict.to_string(), exit_code: code });
    }

    // 4) Only a fully-PROVEN hook earns an install-tx + registry entry.
    let mut install_tx = None;
    let mut registered = false;
    if certified {
        if let Some(account) = opts.account {
            let params = build_params(arch, opts.intent)?;
            let on = on_clause(arch);
            install_tx = Some(crate::installtx::run(&wasm, &crate::installtx::Opts {
                account,
                on: &on,
                namespace: None,
                namespace_label: None,
                network: opts.network,
                flags: 1,
                params: &params,
            })?);
        }
        if opts.register {
            register_proof(&dir, &wasm, arch, opts)?;
            registered = true;
        }
    }

    Ok(AuthorReport {
        intent: opts.intent.to_string(),
        archetype: arch.name.to_string(),
        guarantee: arch.summary.to_string(),
        hook_path: hook_c.display().to_string(),
        wasm_path: wasm.display().to_string(),
        invariants: results,
        certified,
        install_tx,
        registered,
    })
}

/// Extract install-time hook params (nameHex=valueHex) from the intent per the archetype schema.
fn build_params(arch: &Archetype, intent: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for p in arch.params {
        let val = match p.kind {
            ParamKind::Drops => extract_drops(intent).map(|d| format!("{:016X}", d)),
            ParamKind::DestAddr => extract_dest(intent),
        };
        match (val, p.required) {
            (Some(v), _) => out.push(format!("{}={}", hex_key(p.key), v)),
            (None, true) => bail!(
                "archetype `{}` needs a valid {} value but none was found in the intent \
                 (e.g. add \"5 XAH\"; a too-large/invalid amount is rejected rather than \
                 silently truncated)",
                arch.name, p.key
            ),
            (None, false) => {}
        }
    }
    Ok(out)
}

fn hex_key(key: &str) -> String {
    key.bytes().map(|b| format!("{:02X}", b)).collect()
}

/// Parse a drops amount from "<n> XAH" / "<n> drops" (XAH → drops = *1_000_000).
fn extract_drops(intent: &str) -> Option<u64> {
    let lc = intent.to_lowercase();
    // crude but deterministic: find a number immediately followed by a unit.
    let bytes = lc.as_bytes();
    for unit in ["xah", "drops"] {
        if let Some(pos) = lc.find(unit) {
            // walk back over spaces + digits/decimal
            let mut end = pos;
            while end > 0 && bytes[end - 1] == b' ' { end -= 1; }
            let mut start = end;
            while start > 0 && (bytes[start - 1].is_ascii_digit() || bytes[start - 1] == b'.') {
                start -= 1;
            }
            // If the digits are glued to a larger alphanumeric token (e.g. "1e30" -> "30"),
            // don't trust the fragment — reject rather than bake a silently-wrong value.
            if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
                continue;
            }
            if start < end {
                if let Ok(num) = lc[start..end].parse::<f64>() {
                    // Reject NaN/inf/negative and any value that would saturate the f64->u64
                    // cast: a silently-wrong LIM baked into a SetHook is worse than no answer.
                    if !num.is_finite() || num < 0.0 {
                        return None;
                    }
                    let scaled = if unit == "xah" { num * 1_000_000.0 } else { num };
                    if scaled > u64::MAX as f64 {
                        return None;
                    }
                    return Some(scaled as u64);
                }
            }
        }
    }
    None
}

/// Pull a destination accountID from the intent. MVP: accept a 40-char hex accountID
/// directly (r-address base58check decoding is a future nicety — kept out to avoid a
/// crypto dep; until then DST is set only when an explicit 20-byte hex is supplied).
fn extract_dest(intent: &str) -> Option<String> {
    for tok in intent.split_whitespace() {
        let t = tok.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if t.len() == 40 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(t.to_uppercase());
        }
    }
    None
}

fn on_clause(arch: &Archetype) -> String {
    // All current archetypes police Payment; widen per-archetype later if needed.
    let _ = arch;
    "Payment".to_string()
}

fn register_proof(dir: &std::path::Path, wasm: &std::path::Path, arch: &Archetype, opts: &Opts) -> Result<()> {
    // Build a PROVEN manifest for each invariant and register it (shells the prover's registry).
    // We register one entry per invariant via `python -m registry add`, using a manifest the
    // prover builds from the wasm. Done through the registry CLI to keep one code path.
    for inv in arch.invariants {
        let mut args = vec![
            "make-manifest".to_string(), wasm.display().to_string(),
            "--invariant".to_string(), inv.to_string(),
        ];
        if let Some(acct) = opts.account {
            args.push("--account".to_string());
            args.push(acct.to_string());
        }
        // Emit a manifest to a temp path, then add it.
        let manifest = std::env::temp_dir().join(format!("xahc_author_{}_{}.json", arch.name, inv));
        args.push("--out".to_string());
        args.push(manifest.display().to_string());
        registry_cli(dir, &args)?;

        let mut add = vec!["add".to_string(), manifest.display().to_string()];
        if let Some(k) = opts.key {
            add.push("--key".to_string());
            add.push(k.to_string());
        }
        registry_cli(dir, &add)?;
        let _ = std::fs::remove_file(&manifest);
    }
    Ok(())
}

fn registry_cli(dir: &std::path::Path, args: &[String]) -> Result<()> {
    let py = crate::prove::python(dir);
    let status = std::process::Command::new(&py)
        .env("PYTHONPATH", dir.join("src"))
        .arg("-m").arg("registry").args(args)
        .status()
        .with_context(|| "failed to run the proof registry")?;
    if !status.success() {
        bail!("registry step failed (exit {:?})", status.code());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_clear_intents() {
        assert_eq!(resolve("limit payments to 5 XAH").unwrap().name, "spend-limit");
        assert_eq!(resolve("owner-only please").unwrap().name, "owner-only");
        assert_eq!(resolve("agent guardrail with allowlist").unwrap().name, "agent-guardrail");
        assert_eq!(resolve("replay protection via nonce").unwrap().name, "replay-guard");
    }

    #[test]
    fn unknown_intent_fails_closed() {
        assert!(resolve("make me a sandwich").is_err());
    }

    #[test]
    fn every_archetype_self_certifies_at_least_one_invariant() {
        // The whole premise: an archetype with no invariant could never be "certified".
        for a in CATALOG {
            assert!(!a.invariants.is_empty(), "archetype {} has no invariant to prove", a.name);
        }
    }

    #[test]
    fn drops_extraction_xah_and_drops() {
        assert_eq!(extract_drops("limit to 5 XAH"), Some(5_000_000));
        assert_eq!(extract_drops("cap at 250 drops"), Some(250));
        assert_eq!(extract_drops("2.5 xah max"), Some(2_500_000));
        assert_eq!(extract_drops("owner only"), None);
    }

    #[test]
    fn dest_extraction_takes_40hex_only() {
        let hex = "A".repeat(40);
        assert_eq!(extract_dest(&format!("lock to {hex}")), Some(hex.clone()));
        assert_eq!(extract_dest("lock to rEXAMPLEaccount"), None); // r-address decode is future work
    }

    #[test]
    fn missing_required_param_is_an_error() {
        // spend-limit needs LIM; an intent with no amount must fail when building params.
        let arch = resolve("limit the spend").unwrap();
        assert!(build_params(arch, "limit the spend").is_err());
    }

    #[test]
    fn hex_key_encodes_ascii() {
        assert_eq!(hex_key("LIM"), "4C494D");
        assert_eq!(hex_key("DST"), "445354");
    }

    // ---- audit-regression tests ----

    #[test]
    fn huge_amount_is_rejected_not_truncated() {
        // f64->u64 saturation would silently bake u64::MAX; we must refuse instead.
        assert_eq!(extract_drops("limit to 99999999999999999999 XAH"), None);
        assert_eq!(extract_drops("limit to 1e30 drops"), None);
        // a normal value still parses
        assert_eq!(extract_drops("limit to 5 XAH"), Some(5_000_000));
    }

    #[test]
    fn keyword_match_is_word_bounded() {
        // "limit" must not be triggered by a larger word that merely contains it.
        assert!(!matches_keyword("delimitation policy", "limit"));
        assert!(matches_keyword("limit the spend", "limit"));
        assert!(matches_keyword("set a cap", "cap"));
        assert!(!matches_keyword("escape capsule", "cap"));
        // multi-word phrase still matches as a substring
        assert!(matches_keyword("send no more than 5", "no more than"));
    }

    #[test]
    fn every_catalog_archetype_has_a_proven_template_ref_and_invariant() {
        for a in CATALOG {
            assert!(!a.invariants.is_empty(), "{} has no invariant", a.name);
            assert!(a.hook_src.ends_with(".c"), "{} hook_src not a .c", a.name);
            assert!(!a.keywords.is_empty(), "{} has no keywords", a.name);
        }
    }
}
