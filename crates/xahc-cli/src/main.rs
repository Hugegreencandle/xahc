//! xahc — Xahau Hooks, Checked.
//! Safe build/clean/lint toolchain for C Hooks on Xahau.

mod author;
mod build;
mod clean;
mod compose;
mod fuzz;
mod doctor;
mod guardpass;
mod installtx;
mod lint;
mod prove;
mod registry;
mod scaffold;
mod sim;
mod test;
mod verify;

use anyhow::Result;
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "xahc", version, about = "Xahau Hooks, Checked")]
struct Cli {
    /// Emit machine-readable JSON on stdout (diagnostics stay on stderr). Lets
    /// CI, the web funnel, and xahau-mcp consume xahc results without parsing prose.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

// ---- stable --json result envelopes (consumed by CI / xahau-mcp / the web tool) ----

#[derive(Serialize)]
struct LintJson<'a> {
    ok: bool,
    error_count: usize,
    findings: &'a [lint::Finding],
}

#[derive(Serialize)]
struct BuildJson<'a> {
    wasm_path: String,
    wasm_hex: String,
    bytes: usize,
    lint: LintJson<'a>,
}

#[derive(Serialize)]
struct EmitJson {
    bytes: usize,
    hex: String,
}

#[derive(Serialize)]
struct SimJson {
    outcome: String,
    return_code: i64,
    emitted: Vec<EmitJson>,
    state_keys: usize,
}

#[derive(Serialize)]
struct CleanJson {
    out_path: String,
    removed: usize,
}

#[derive(Serialize)]
struct ProveJson {
    invariant: String,
    input: String,
    /// proven | counterexample | inconclusive | error — derived from exit_code.
    verdict: &'static str,
    exit_code: i32,
}

/// Map the prover's exit code to a stable verdict string.
/// 0 PROVEN, 1 N/A (not exercised — not a pass), 2 COUNTEREXAMPLE, 3 INCONCLUSIVE,
/// anything else = prover/tool error.
fn prove_verdict(code: i32) -> &'static str {
    match code {
        0 => "proven",
        1 => "n/a", // property not exercised by the hook — NOT a pass
        2 => "counterexample",
        3 => "inconclusive",
        _ => "error",
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02X}", x)).collect()
}

fn print_json<T: Serialize>(v: &T) {
    println!("{}", serde_json::to_string_pretty(v).expect("serialize json"));
}

#[derive(Subcommand)]
enum Cmd {
    /// Compile a C hook to a clean, lint-passed .wasm ready for deploy.
    Build {
        /// Input .c file
        input: PathBuf,
        /// Output .wasm (default: <input>.wasm)
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Extra include dirs (the xahc headers dir is added automatically if found)
        #[arg(short = 'I', long = "include")]
        includes: Vec<PathBuf>,
        /// Skip lint (not recommended)
        #[arg(long)]
        no_lint: bool,
    },
    /// Strip illegal exports from a .wasm (Rust reimpl of hook-cleaner).
    Clean {
        input: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Static-check a .wasm: export allowlist, import allowlist, guard presence.
    Lint { input: PathBuf },
    /// Simulate a hook against a synthetic transaction (no testnet).
    Sim {
        input: PathBuf,
        /// Transaction type (0 = Payment)
        #[arg(long, default_value_t = 0)]
        tt: i64,
        /// Native amount in drops (sfAmount)
        #[arg(long, default_value_t = 0)]
        drops: u64,
    },
    /// Run a declarative TOML test suite against a hook (sim-based).
    Test { file: PathBuf },
    /// Emit an UNSIGNED SetHook tx to install a built .wasm on an account.
    #[command(name = "install-tx")]
    InstallTx {
        /// The built hook .wasm
        wasm: PathBuf,
        /// Account the hook installs on (r-address)
        #[arg(long)]
        account: String,
        /// Comma list of tx types to fire on, e.g. "Payment" or "Payment,Invoke" (names or numbers). Required — no implicit fire-on-all.
        #[arg(long)]
        on: String,
        /// HookNamespace, 64 hex. Default: all-zeros.
        #[arg(long)]
        namespace: Option<String>,
        /// Derive HookNamespace as sha256(label) instead of raw hex.
        #[arg(long)]
        namespace_label: Option<String>,
        /// HookParameter as nameHex=valueHex (repeatable).
        #[arg(long = "param")]
        params: Vec<String>,
        /// testnet | mainnet
        #[arg(long, default_value = "testnet")]
        network: String,
        /// Hook Flags (1 = hsfOverride, replace existing hook in slot)
        #[arg(long, default_value_t = 1)]
        flags: u32,
    },
    /// Differential check: run a built .wasm through the local sim AND a hosted
    /// xahau-mcp /execute, and flag any accept/rollback disagreement.
    Verify {
        /// The built hook .wasm
        wasm: PathBuf,
        /// Originating tx type name or number (seeded identically to both VMs)
        #[arg(long, default_value = "Payment")]
        tt: String,
        /// Native amount in drops (sfAmount), seeded identically to both VMs
        #[arg(long, default_value_t = 0)]
        drops: u64,
        /// Simulator base URL (else XAHC_SIM_URL), e.g. http://localhost:8787
        #[arg(long)]
        remote: Option<String>,
    },
    /// Prove an invariant holds for ALL inputs (xahc-prover, symbolic execution + Z3).
    /// Exit code: 0 PROVEN, 2 COUNTEREXAMPLE, 3 INCONCLUSIVE. With --json, also emits
    /// a {invariant,input,verdict,exit_code} envelope (the prover's own output is prose).
    Prove {
        /// Hook .wasm (or .c, built first)
        input: PathBuf,
        /// Invariant: limit | guardrail | termination | monotonic | nospend | conservation | limit-iou | authz | validate | overflow | foreign-authz | reserve | time-nonce | emission | period-budget | reentrancy | unchecked-return | validate-range | bootloader | resource-conservation
        #[arg(long, default_value = "termination")]
        invariant: String,
        /// Extra args forwarded to the prover (e.g. a max_drops bound)
        #[arg(last = true)]
        rest: Vec<String>,
    },
    /// Self-certifying generator: intent → proven-safe Hook. Maps a plain-English
    /// intent to a proven archetype, builds it, PROVES its invariant(s), and only emits a
    /// certified hook (+ optional install-tx / registry entry) if every invariant is PROVEN.
    /// Fail-closed: it never ships a hook it could not prove. Requires the prover checkout.
    Author {
        /// What the hook should do, e.g. "limit payments to 5 XAH" or "owner-only".
        intent: String,
        /// Output basename (default: the archetype name). Writes <name>.c and <name>.wasm.
        #[arg(long)]
        name: Option<String>,
        /// Account to emit an install-tx for (r-address). Omit to just author + certify.
        #[arg(long)]
        account: Option<String>,
        /// testnet | mainnet (for the install-tx)
        #[arg(long, default_value = "testnet")]
        network: String,
        /// Register the proof(s) in the proof registry once certified.
        #[arg(long)]
        register: bool,
        /// Attester keyfile for signing registry entries (with --register).
        #[arg(long)]
        key: Option<String>,
    },
    /// Hunt counterexamples to an invariant with boundary-biased concrete fuzzing — the
    /// complement to `prove` for INCONCLUSIVE cases. A found counterexample DISPROVES the
    /// hook; finding none raises confidence but NEVER proves it (only `prove` proves).
    /// Stateless invariants: limit | overflow | authz | guardrail. Exit: 0 none · 2 DISPROVEN.
    Fuzz {
        /// Hook .wasm (or .c, built first)
        input: PathBuf,
        #[arg(long, default_value = "limit")]
        invariant: String,
        /// Number of fuzz runs
        #[arg(long, default_value_t = 20000)]
        runs: u64,
        /// PRNG seed (reproducible)
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// LIM hook-param the oracle checks against (drops)
        #[arg(long, default_value_t = 1_000_000)]
        lim: u64,
        /// TIP hook-param for the overflow invariant (drops)
        #[arg(long, default_value_t = 10)]
        tip: u64,
        /// 40-hex destination accountID for the guardrail DST lock (optional)
        #[arg(long)]
        dst: Option<String>,
    },
    /// Composition prover: prove a safety property over a CHAIN of hooks on one account.
    /// Proves each hook's claimed invariant, then proves the composition is sound — every
    /// invariant PROVEN + no state-namespace interference among stateful hooks. The chain
    /// inherits the conjunction of per-hook safety invariants. Fail-closed. Takes a chain TOML.
    Compose {
        /// Chain spec TOML: ordered [[hook]] entries with wasm, namespace, invariants.
        chain: PathBuf,
    },
    /// Proof Registry: tamper-evident, queryable record of PROVEN hook proofs
    /// (write → simulate → prove → watch → REGISTER). Subcommands forwarded to the
    /// prover's registry CLI: add | get | check | verify | list | head | keygen.
    /// Exit: 0 ok/PROVEN · 2 UNPROVEN/TAMPERED · 3 usage.
    Registry {
        /// Subcommand + args, e.g. `check hook.wasm --json` or `add m.json --key k`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Check the local toolchain can build hooks (clang/wasm-ld), with fix hints.
    Doctor,
    /// Scaffold a buildable hook project.
    New {
        /// Project name (a directory is created)
        name: String,
        /// firewall | accept_all | emitter
        #[arg(long, default_value = "firewall")]
        archetype: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build { input, out, includes, no_lint } => {
            let out = out.unwrap_or_else(|| input.with_extension("wasm"));
            build::run(&input, &out, &includes, !no_lint)?;
            if cli.json {
                let bytes = std::fs::read(&out)?;
                let findings = lint::lint(&bytes)?;
                let error_count = findings.iter().filter(|f| f.level == lint::Level::Error).count();
                print_json(&BuildJson {
                    wasm_path: out.display().to_string(),
                    wasm_hex: hex(&bytes),
                    bytes: bytes.len(),
                    lint: LintJson { ok: error_count == 0, error_count, findings: &findings },
                });
            } else {
                println!("{} {}", "built".green().bold(), out.display());
            }
        }
        Cmd::Clean { input, out } => {
            let out = out.unwrap_or_else(|| input.clone());
            let removed = clean::run(&input, &out)?;
            if cli.json {
                print_json(&CleanJson { out_path: out.display().to_string(), removed });
            } else {
                println!("{} stripped {} stray export(s) -> {}", "clean".green().bold(), removed, out.display());
            }
        }
        Cmd::Lint { input } => {
            let findings = lint::lint_file(&input)?;
            let error_count = findings.iter().filter(|f| f.level == lint::Level::Error).count();
            if cli.json {
                print_json(&LintJson { ok: error_count == 0, error_count, findings: &findings });
            } else {
                lint::report(&findings);
            }
            if error_count > 0 {
                std::process::exit(1);
            }
        }
        Cmd::Sim { input, tt, drops } => {
            let tx = sim::TxFixture { tt, drops, ..Default::default() };
            let (outcome, emitted, state) = sim::run(&input, tx)?;
            let (name, code) = match &outcome {
                sim::Outcome::Accept(c) => ("ACCEPT", *c),
                sim::Outcome::Rollback(c) => ("ROLLBACK", *c),
                sim::Outcome::Returned(c) => ("RETURNED", *c),
                sim::Outcome::GuardViolation(id) => ("GUARD_VIOLATION", *id as u32 as i64),
            };
            if cli.json {
                print_json(&SimJson {
                    outcome: name.to_string(),
                    return_code: code,
                    emitted: emitted.iter().map(|b| EmitJson { bytes: b.len(), hex: hex(b) }).collect(),
                    state_keys: state.len(),
                });
            } else {
                let label = match &outcome {
                    sim::Outcome::Accept(c) => format!("{} (code {})", "ACCEPT".green().bold(), c),
                    sim::Outcome::Rollback(c) => format!("{} (code {})", "ROLLBACK".red().bold(), c),
                    sim::Outcome::Returned(c) => format!("{} (rc {})", "RETURNED".yellow().bold(), c),
                    sim::Outcome::GuardViolation(id) => format!("{} (guard {})", "GUARD_VIOLATION".red().bold(), *id as u32),
                };
                println!("outcome:  {}", label);
                println!("emitted:  {} txn(s)", emitted.len());
                for (i, blob) in emitted.iter().enumerate() {
                    println!("  emit[{}] ({} bytes): {}", i, blob.len(), hex(blob));
                }
                println!("state:    {} key(s) written", state.len());
            }
            if matches!(outcome, sim::Outcome::Rollback(_) | sim::Outcome::GuardViolation(_)) {
                std::process::exit(2);
            }
        }
        Cmd::Test { file } => {
            let s = test::run(&file)?;
            if cli.json {
                print_json(&s);
            } else {
                println!("{} {}  ({} case(s))", "test".bold(), s.wasm, s.cases.len());
                for c in &s.cases {
                    if c.ok {
                        println!("  {} {:<32} {}", "✓".green().bold(), c.name, c.detail.dimmed());
                    } else {
                        println!("  {} {:<32} {}", "✗".red().bold(), c.name, c.detail.red());
                    }
                }
                println!("{} passed, {} failed", s.passed, if s.failed > 0 { s.failed.to_string() } else { "0".to_string() });
            }
            if s.failed > 0 {
                std::process::exit(1);
            }
        }
        Cmd::Verify { wasm, tt, drops, remote } => {
            let v = verify::run(&wasm, &tt, drops, remote.as_deref())?;
            if cli.json {
                print_json(&v);
            } else {
                let mark = if v.agree {
                    "✓ AGREE".green().bold().to_string()
                } else {
                    "✗ DISAGREE".red().bold().to_string()
                };
                let deg = if v.remote_degraded { " (remote DEGRADED — fidelity not guaranteed)" } else { "" };
                println!("{}  local={} remote={}{}", mark, v.local, v.remote, deg);
                println!("  tx={} drops={} via {}", v.tx_type, v.drops, v.remote_url);
            }
            if !v.agree {
                std::process::exit(1);
            }
        }
        Cmd::Author { intent, name, account, network, register, key } => {
            let report = author::run(&author::Opts {
                intent: &intent,
                name: name.as_deref(),
                account: account.as_deref(),
                network: &network,
                register,
                key: key.as_deref(),
            })?;
            if cli.json {
                print_json(&report);
            } else {
                let mark = if report.certified {
                    "✓ CERTIFIED".green().bold().to_string()
                } else {
                    "✗ NOT CERTIFIED".red().bold().to_string()
                };
                println!("{}  archetype={}  -> {}", mark, report.archetype, report.wasm_path);
                println!("  guarantee: {}", report.guarantee.dimmed());
                for r in &report.invariants {
                    let m = if r.exit_code == 0 { "✓".green().to_string() } else { "✗".red().to_string() };
                    println!("  {} {:<22} {}", m, r.invariant, r.verdict);
                }
                if report.registered {
                    println!("  {} proof(s) registered", "registry:".bold());
                }
                if let Some(tx) = &report.install_tx {
                    println!("\n{}", tx);
                    eprintln!("{} UNSIGNED SetHook — sign offline; params baked from your intent.",
                        "note:".yellow().bold());
                }
            }
            if !report.certified {
                std::process::exit(2);
            }
        }
        Cmd::Fuzz { input, invariant, runs, seed, lim, tip, dst } => {
            // Build a .c input first; fuzz a .wasm directly.
            let wasm = if input.extension().is_some_and(|e| e == "c") {
                let out = input.with_extension("wasm");
                build::run(&input, &out, &[], true)?;
                out
            } else {
                input.clone()
            };
            let rep = fuzz::run(&wasm, &fuzz::Opts {
                invariant: &invariant, runs, seed, lim, tip, dst: dst.as_deref(),
            })?;
            // Honesty signal in BOTH modes (stderr keeps --json stdout clean): if no input
            // reached an accept, absence of a counterexample means little.
            if !rep.exercised_accept {
                eprintln!("{} accept path never hit — fuzz is weak; widen inputs or check params",
                    "warning:".yellow().bold());
            }
            if cli.json {
                print_json(&rep);
            } else {
                let verdict = if rep.disproven() {
                    "✗ DISPROVEN".red().bold().to_string()
                } else {
                    "no counterexample".yellow().bold().to_string()
                };
                println!("{}  invariant={}  ({} runs, seed {})", verdict, rep.invariant, rep.runs, rep.seed);
                println!("  outcomes: {} accept · {} rollback · {} guard-violation · {} returned",
                    rep.accepts, rep.rollbacks, rep.guard_violations, rep.returned);
                for c in rep.counterexamples.iter().take(5) {
                    println!("  {} {}  [drops={} tip={} owner={} dst={}]",
                        "CEX:".red().bold(), c.why, c.drops, c.tip, c.account_is_owner, c.destination_hex);
                }
                if rep.disproven() {
                    println!("  -> DISPROVEN: {} counterexample(s). The hook violates `{}`.",
                        rep.counterexamples.len(), rep.invariant);
                } else {
                    println!("  -> no counterexample in {} runs. NOT a proof — run `xahc prove` for ∀-inputs.", rep.runs);
                }
            }
            if rep.disproven() {
                std::process::exit(2);
            }
        }
        Cmd::Compose { chain } => {
            let report = compose::run(&chain)?;
            if cli.json {
                print_json(&report);
            } else {
                let mark = if report.composable {
                    "✓ COMPOSABLE".green().bold().to_string()
                } else {
                    "✗ NOT COMPOSABLE".red().bold().to_string()
                };
                println!("{}  ({} hooks)  -> {}", mark, report.hooks.len(), report.chain_file);
                for h in &report.hooks {
                    let tags = format!("{}{}{}",
                        if h.stateful { "state " } else { "" },
                        if h.emits { "emit " } else { "" },
                        if h.dynamic { "cbak " } else { "" });
                    println!("  {} [ns {}…] {}", h.wasm, &h.namespace[..8.min(h.namespace.len())], tags.dimmed());
                    for p in &h.invariants {
                        let m = if p.exit_code == 0 { "✓".green().to_string() } else { "✗".red().to_string() };
                        println!("      {} {:<20} {}", m, p.invariant, p.verdict);
                    }
                }
                if report.composable {
                    println!("\n  chain guarantees: {}", report.chain_invariants.join(", ").green());
                    println!("  emit bound: {}", report.emit_bound);
                } else if let Some(why) = &report.reason {
                    println!("\n  {} {}", "reason:".red().bold(), why);
                }
                for c in &report.caveats {
                    println!("  {} {}", "caveat:".yellow().bold(), c);
                }
            }
            if !report.composable {
                std::process::exit(2);
            }
        }
        Cmd::Registry { args } => {
            let code = registry::run(&args)?;
            std::process::exit(code);
        }
        Cmd::Doctor => {
            doctor::run()?;
        }
        Cmd::New { name, archetype } => {
            scaffold::run(&name, &archetype)?;
        }
        Cmd::InstallTx { wasm, account, on, namespace, namespace_label, params, network, flags } => {
            let json = installtx::run(&wasm, &installtx::Opts {
                account: &account,
                on: &on,
                namespace: namespace.as_deref(),
                namespace_label: namespace_label.as_deref(),
                network: &network,
                flags,
                params: &params,
            })?;
            println!("{}", json);
            eprintln!("{} UNSIGNED — sign offline (xaman / xrpl-accountlib). Set Fee/Sequence at signing.",
                "note:".yellow().bold());
        }
        Cmd::Prove { input, invariant, rest } => {
            let code = prove::run(&input, &prove::Opts { invariant: &invariant, rest: &rest })?;
            if cli.json {
                // Machine signal: the prover only speaks via exit code, so the
                // envelope derives the verdict from it. The human prose the prover
                // printed went to stdout above; in --json mode CI should read this
                // envelope (and exit_code) rather than parse that prose.
                print_json(&ProveJson {
                    invariant: invariant.clone(),
                    input: input.display().to_string(),
                    verdict: prove_verdict(code),
                    exit_code: code,
                });
            }
            std::process::exit(code);
        }
    }
    Ok(())
}
