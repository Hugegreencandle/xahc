//! xahc — Xahau Hooks, Checked.
//! Safe build/clean/lint toolchain for C Hooks on Xahau.

mod build;
mod clean;
mod installtx;
mod lint;
mod sim;
mod test;

use anyhow::Result;
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "xahc", version, about = "Xahau Hooks, Checked")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
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
        /// Comma list of tx types to fire on (names or numbers). Default: all.
        #[arg(long)]
        on: Option<String>,
        /// HookNamespace, 64 hex. Default: all-zeros.
        #[arg(long)]
        namespace: Option<String>,
        /// testnet | mainnet
        #[arg(long, default_value = "testnet")]
        network: String,
        /// Hook Flags (1 = hsfOverride, replace existing hook in slot)
        #[arg(long, default_value_t = 1)]
        flags: u32,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build { input, out, includes, no_lint } => {
            let out = out.unwrap_or_else(|| input.with_extension("wasm"));
            build::run(&input, &out, &includes, !no_lint)?;
            println!("{} {}", "built".green().bold(), out.display());
        }
        Cmd::Clean { input, out } => {
            let out = out.unwrap_or_else(|| input.clone());
            let removed = clean::run(&input, &out)?;
            println!("{} stripped {} stray export(s) -> {}", "clean".green().bold(), removed, out.display());
        }
        Cmd::Lint { input } => {
            let findings = lint::lint_file(&input)?;
            lint::report(&findings);
            if findings.iter().any(|f| f.level == lint::Level::Error) {
                std::process::exit(1);
            }
        }
        Cmd::Sim { input, tt, drops } => {
            let tx = sim::TxFixture { tt, drops, ..Default::default() };
            let (outcome, emitted, state) = sim::run(&input, tx)?;
            let label = match &outcome {
                sim::Outcome::Accept(c) => format!("{} (code {})", "ACCEPT".green().bold(), c),
                sim::Outcome::Rollback(c) => format!("{} (code {})", "ROLLBACK".red().bold(), c),
                sim::Outcome::Returned(c) => format!("{} (rc {})", "RETURNED".yellow().bold(), c),
            };
            println!("outcome:  {}", label);
            println!("emitted:  {} txn(s)", emitted.len());
            for (i, blob) in emitted.iter().enumerate() {
                let hex: String = blob.iter().map(|b| format!("{:02X}", b)).collect();
                println!("  emit[{}] ({} bytes): {}", i, blob.len(), hex);
            }
            println!("state:    {} key(s) written", state.len());
            if matches!(outcome, sim::Outcome::Rollback(_)) {
                std::process::exit(2);
            }
        }
        Cmd::Test { file } => {
            test::run(&file)?;
        }
        Cmd::InstallTx { wasm, account, on, namespace, network, flags } => {
            let json = installtx::run(&wasm, &installtx::Opts {
                account: &account,
                on: on.as_deref(),
                namespace: namespace.as_deref(),
                network: &network,
                flags,
            })?;
            println!("{}", json);
            eprintln!("{} UNSIGNED — sign offline (xaman / xrpl-accountlib). Set Fee/Sequence at signing.",
                "note:".yellow().bold());
        }
    }
    Ok(())
}
