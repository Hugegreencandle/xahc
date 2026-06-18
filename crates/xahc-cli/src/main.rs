//! xahc — Xahau Hooks, Checked.
//! Safe build/clean/lint toolchain for C Hooks on Xahau.

mod build;
mod clean;
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
/// 0 PROVEN, 2 COUNTEREXAMPLE, 3 INCONCLUSIVE, anything else = prover/tool error.
fn prove_verdict(code: i32) -> &'static str {
    match code {
        0 => "proven",
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
