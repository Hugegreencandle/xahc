//! xahc — Xahau Hooks, Checked.
//! Safe build/clean/lint toolchain for C Hooks on Xahau.

mod build;
mod clean;
mod lint;

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
    }
    Ok(())
}
