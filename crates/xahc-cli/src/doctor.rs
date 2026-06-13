//! `xahc doctor` — check the local toolchain can build hooks, with fix hints.

use anyhow::Result;
use owo_colors::OwoColorize;
use std::process::Command;

use crate::build;

pub fn run() -> Result<()> {
    let mut ok = true;

    ok &= check(
        "clang",
        "clang",
        &["--version"],
        "brew install llvm (add /opt/homebrew/opt/llvm/bin to PATH) · apt install clang",
    );
    ok &= check(
        "wasm-ld",
        "wasm-ld",
        &["--version"],
        "brew install lld · apt install lld",
    );

    // The definitive check: actually compile a trivial hook end-to-end.
    let e2e = end_to_end();
    print!("{:<10} ", "compile");
    match &e2e {
        Ok(()) => println!("{} compiles a hook end-to-end", "OK".green().bold()),
        Err(e) => {
            ok = false;
            println!("{} {}", "FAIL".red().bold(), e);
        }
    }

    if ok {
        println!("\n{} toolchain ready — try `xahc new myhook`", "✓".green().bold());
        Ok(())
    } else {
        println!("\n{} toolchain incomplete — see hints above", "✗".red().bold());
        std::process::exit(1);
    }
}

fn check(label: &str, bin: &str, args: &[&str], hint: &str) -> bool {
    match Command::new(bin).args(args).output() {
        Ok(o) if o.status.success() => {
            let out = String::from_utf8_lossy(&o.stdout);
            let line = out.lines().next().unwrap_or("").trim();
            println!("{:<10} {} {}", label, "OK".green().bold(), line.dimmed());
            true
        }
        _ => {
            println!("{:<10} {} not found — {}", label, "FAIL".red().bold(), hint);
            false
        }
    }
}

fn end_to_end() -> Result<()> {
    let dir = std::env::temp_dir().join("xahc-doctor");
    std::fs::create_dir_all(&dir)?;
    let src = dir.join("doctor.c");
    std::fs::write(
        &src,
        "#include \"xahc/xahc.h\"\n\
         int64_t hook(uint32_t r){ XAHC_HOOK_ENTRY(); XAHC_ACCEPT(\"ok\"); return 0; }\n",
    )?;
    // do_lint=false: keep doctor output quiet; we only care that it compiles+cleans.
    build::run(&src, &dir.join("doctor.wasm"), &[], false)
}
