//! `xahc prove` — prove an invariant holds for ALL inputs, via xahc-prover
//! (symbolic execution + Z3). This shells out to the Python prover; the verdict's
//! exit code is propagated (0 PROVEN, 2 COUNTEREXAMPLE, 3 INCONCLUSIVE).

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// RAII guard that deletes a temp file on drop — covers the prover-success,
/// disprove, AND early-return/`?`-error paths so a built `.wasm` is never leaked.
struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        // Best-effort: a failed unlink (already gone, permissions) must not panic.
        let _ = std::fs::remove_file(&self.0);
    }
}

pub struct Opts<'a> {
    pub invariant: &'a str,
    pub rest: &'a [String],
    /// Wall-clock limit in seconds. On expiry the prover is stopped and the result is
    /// INCONCLUSIVE (exit 3) with a message, instead of being killed with no output.
    pub timeout_secs: Option<u64>,
}

/// Exit code for a run stopped at `--timeout`: INCONCLUSIVE, never a pass.
pub const EXIT_INCONCLUSIVE: i32 = 3;

/// invariant name -> prover driver script
const INVARIANTS: &[(&str, &str)] = &[
    ("limit", "prove_limit.py"),
    ("guardrail", "prove_guardrail.py"),
    ("termination", "prove_termination.py"),
    ("monotonic", "prove_monotonic.py"),
    ("nospend", "prove_nospend.py"),
    ("conservation", "prove_conservation.py"),
    ("limit-iou", "prove_limit_iou.py"),
    ("authz", "prove_authz.py"),
    ("validate", "prove_validate.py"),
    ("overflow", "prove_overflow.py"),
    ("foreign-authz", "prove_foreign_authz.py"),
    ("reserve", "prove_reserve.py"),
    ("time-nonce", "prove_time_nonce.py"),
    ("emission", "prove_emission.py"),
    ("period-budget", "prove_period_budget.py"),
    ("reentrancy", "prove_reentrancy.py"),
    ("unchecked-return", "prove_unchecked_return.py"),
    ("validate-range", "prove_validate_range.py"),
    ("bootloader", "prove_bootloader.py"),
    ("resource-conservation", "prove_resource_conservation.py"),
    ("commitment", "prove_commitment.py"),
    ("preview-faithfulness", "prove_preview_faithfulness.py"),
    ("boot-upgrade-authz", "prove_boot_upgrade.py"),
    ("permissioned-transfer", "prove_permissioned_transfer.py"),
    ("dst-lock", "prove_dst_lock.py"),
    ("rate-limit", "prove_rate_limit.py"),
    ("cron", "prove_cron.py"),
    ("partial-payment", "prove_partial_payment.py"),
    ("constant-product", "prove_constant_product.py"),
    ("native-amount", "prove_native_amount.py"),
    ("emit-budget", "prove_emit_budget.py"),
    ("emit-dst-lock", "prove_emit_dst_lock.py"),
    ("trigger-lock", "prove_trigger_lock.py"),
    ("time-release", "prove_time_release.py"),
    ("inactivity-release", "prove_inactivity_release.py"),
    ("split-conservation", "prove_split_conservation.py"),
    ("hashlock", "prove_hashlock.py"),
    ("quorum", "prove_quorum.py"),
    ("master-disuse", "prove_master_disuse.py"),
    ("qday-freeze", "prove_qday_freeze.py"),
];

/// Resolve the xahc-prover checkout.
///
/// SECURITY: the resolved directory's scripts are executed as TRUSTED CODE
/// (the host Python runs `src/<invariant>.py`). The auto-discovery fallbacks
/// (`$HOME/Desktop/xahc-prover`, `$HOME/xahc-prover`, `../xahc-prover`,
/// `./xahc-prover`) only confirm a `src/` dir exists — they do NOT authenticate
/// the contents. In CI or any untrusted working directory, set `XAHC_PROVER_DIR`
/// explicitly to a known-good checkout so a stray sibling/cwd `xahc-prover` can't
/// be picked up and run.
pub(crate) fn prover_dir() -> Result<PathBuf> {
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
pub(crate) fn python(dir: &Path) -> PathBuf {
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
    // The temp build is wrapped in a drop-guard so it's unlinked on every exit
    // path — prover success, disprove, or an early `?` error (e.g. a build or
    // spawn failure). `_guard` is held for the whole fn so cleanup runs last.
    let (wasm, _guard): (PathBuf, Option<TempFileGuard>) =
        if input.extension().is_some_and(|e| e == "c") {
            let out = std::env::temp_dir().join(temp_wasm_name());
            // Register the guard BEFORE the build so a build that partially wrote
            // the file (then errored) is still cleaned up.
            let guard = TempFileGuard(out.clone());
            crate::build::run(input, &out, &[], true)?;
            (out, Some(guard))
        } else {
            (input.to_path_buf(), None)
        };

    let mut cmd = Command::new(&py);
    cmd.arg(dir.join("src").join(script)).arg(&wasm).args(opts.rest);
    // Ask the prover for a progress line on stderr every 30 s (xahc-prover >= 8125029; older
    // provers ignore it). A user-set XAHC_PROVER_PROGRESS wins.
    if std::env::var_os("XAHC_PROVER_PROGRESS").is_none() {
        cmd.env("XAHC_PROVER_PROGRESS", "30");
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to run the prover ({})", py.display()))?;
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().context("wait for the prover")? {
            break st;
        }
        if let Some(limit) = opts.timeout_secs {
            if started.elapsed().as_secs() >= limit {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!(
                    "TIMEOUT: invariant '{}' stopped after {} s with no verdict. This is INCONCLUSIVE: \
                     not PROVEN and not a counterexample. Symbolic execution may not finish on large hooks \
                     (many guarded loops, slot/sto parsing); try a longer --timeout, a narrower invariant, \
                     or a smaller harness around the code path you care about.",
                    opts.invariant, limit
                );
                return Ok(EXIT_INCONCLUSIVE);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    match status.code() {
        Some(c) => Ok(c),
        None => {
            // Killed by a signal (e.g. an outer `timeout`, OOM). Say so rather than exit silently.
            eprintln!(
                "prover for '{}' was terminated by a signal after {} s with no verdict (INCONCLUSIVE). \
                 Use `xahc prove --timeout <secs>` to get a clean INCONCLUSIVE result instead.",
                opts.invariant,
                started.elapsed().as_secs()
            );
            Ok(EXIT_INCONCLUSIVE)
        }
    }
}

/// A non-predictable temp .wasm filename. PID alone is predictable and reused
/// across runs/processes; mixing in a nanosecond timestamp and the file count
/// makes accidental collision / pre-creation by another actor impractical
/// without pulling in an extra crate.
fn temp_wasm_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // A relaxed counter disambiguates two builds within the same nanosecond tick.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("xahc_prove_{}_{:x}_{:x}.wasm", std::process::id(), nanos, seq)
}
