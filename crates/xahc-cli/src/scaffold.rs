//! `xahc new <name>` — scaffold a buildable hook project using the safe headers.

use anyhow::{bail, Result};
use owo_colors::OwoColorize;
use std::fs;
use std::path::Path;

pub const ARCHETYPES: &[&str] = &["firewall", "accept_all", "emitter"];

pub fn run(name: &str, archetype: &str) -> Result<()> {
    if !ARCHETYPES.contains(&archetype) {
        bail!("unknown archetype `{}` — one of: {}", archetype, ARCHETYPES.join(", "));
    }
    let dir = Path::new(name);
    if dir.exists() {
        bail!("`{}` already exists", name);
    }
    fs::create_dir_all(dir)?;

    let (hook, test) = template(archetype);
    let test = test.replace("%C%", &format!("{name}.c"));
    fs::write(dir.join(format!("{name}.c")), hook)?;
    fs::write(dir.join(format!("{name}.test.toml")), test)?;
    fs::write(dir.join("justfile"), justfile(name))?;
    fs::write(dir.join("README.md"), readme(name, archetype))?;
    fs::write(dir.join(".gitignore"), "*.wasm\n*.raw.wasm\n")?;

    println!("{} {}/ ({} archetype)", "scaffolded".green().bold(), name, archetype);
    println!("  next: cd {name} && xahc build {name}.c -o {name}.wasm && xahc test {name}.test.toml");
    Ok(())
}

fn template(archetype: &str) -> (String, String) {
    match archetype {
        "accept_all" => (
            r#"#include "xahc/xahc.h"

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    XAHC_ACCEPT("ok");
    return 0;
}
"#
            .into(),
            r#"build = "%C%"

[[case]]
name = "accepts payment"
tt = 0
expect = "accept"

[[case]]
name = "accepts non-payment"
tt = 99
expect = "accept"
"#
            .into(),
        ),
        "emitter" => (
            r#"#include "xahc/xahc.h"

/* On any incoming Payment, emit a fixed 1 XAH payment to a destination. */
#define EMIT_DROPS 1000000ULL

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    if (otxn_type() != XAHC_ttPAYMENT)
        XAHC_ACCEPT("not a payment");

    uint8_t dest[20];
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
        dest[i] = 0xBB; /* TODO: real 20-byte destination account-id */

    XAHC_EMIT_PAYMENT(dest, EMIT_DROPS, 0, 0);
    XAHC_ACCEPT("emitted");
    return 0;
}
"#
            .into(),
            r#"build = "%C%"

[[case]]
name = "payment triggers one emit"
tt = 0
drops = 50000000
expect = "accept"
emits = 1

[[case]]
name = "non-payment emits nothing"
tt = 99
expect = "accept"
emits = 0
"#
            .into(),
        ),
        // firewall (default)
        _ => (
            r#"#include "xahc/xahc.h"

/* Reject incoming Payments below MIN_DROPS; pass everything else. */
#define MIN_DROPS 10000000ULL /* 10 XAH */

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();
    if (otxn_type() != XAHC_ttPAYMENT)
        XAHC_ACCEPT("not a payment");

    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native amount read");
    XAHC_REQUIRE(drops >= (int64_t)MIN_DROPS, "below minimum");

    XAHC_ACCEPT("ok");
    return 0;
}
"#
            .into(),
            r#"build = "%C%"

[[case]]
name = "below 10 XAH rejects"
tt = 0
drops = 5000000
expect = "rollback"

[[case]]
name = "above floor accepts"
tt = 0
drops = 20000000
expect = "accept"

[[case]]
name = "non-payment passes"
tt = 99
expect = "accept"
"#
            .into(),
        ),
    }
}

fn justfile(name: &str) -> String {
    format!(
        "# xahc project — `just <recipe>`\n\
         wasm := \"{name}.wasm\"\n\n\
         build:\n\txahc build {name}.c -o {name}.wasm\n\n\
         test:\n\txahc test {name}.test.toml\n\n\
         lint: build\n\txahc lint {name}.wasm\n\n\
         # usage: just install rYourAccount...\n\
         install ACCOUNT: build\n\txahc install-tx {name}.wasm --account {{{{ACCOUNT}}}}\n"
    )
}

fn readme(name: &str, archetype: &str) -> String {
    format!(
        "# {name}\n\n\
         An Xahau Hook scaffolded with [`xahc`](https://github.com/Hugegreencandle/xahc) \
         (`{archetype}` archetype).\n\n\
         ## Build & test\n\n\
         ```sh\n\
         xahc build {name}.c -o {name}.wasm   # compile -> clean -> lint\n\
         xahc test {name}.test.toml            # run the assertions\n\
         ```\n\n\
         ## Deploy\n\n\
         ```sh\n\
         xahc install-tx {name}.wasm --account rYOURACCOUNT --on Payment\n\
         ```\n\
         Outputs an UNSIGNED SetHook — sign offline. For a security audit before \
         installing, run the wasm through xahau-mcp's `analyze_hook`.\n\n\
         Prereqs: a wasm-capable LLVM (`brew install llvm lld` / `apt install clang lld`). \
         Run `xahc doctor` to verify.\n"
    )
}
