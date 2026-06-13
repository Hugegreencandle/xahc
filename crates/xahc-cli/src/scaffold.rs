//! `xahc new <name>` — scaffold a buildable hook project using the safe headers.

use anyhow::{bail, Result};
use owo_colors::OwoColorize;
use std::fs;
use std::path::Path;

pub const ARCHETYPES: &[&str] = &["firewall", "accept_all", "emitter", "agent_guardrail"];

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
        "agent_guardrail" => (
            AGENT_GUARDRAIL_C.into(),
            AGENT_GUARDRAIL_TEST.into(),
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

const AGENT_GUARDRAIL_C: &str = r#"#include "xahc/xahc.h"

/* Agent spending guardrail — install on an autonomous agent's account.
 *
 * Enforces, at layer 1, limits an off-chain agent must not exceed:
 *   HookParameter "LIM" (8 bytes, big-endian drops)  REQUIRED — max per-tx spend
 *   HookParameter "DST" (20-byte account-id)          OPTIONAL — lock outgoing to one dest
 *
 * Policies OUTGOING Payments from this account; passes everything else.
 * Pairs with x402/agentic payments: the agent signs payments off-chain, this
 * Hook bounds them on-chain (see docs/X402-XAHAU.md). */

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    if (otxn_type() != XAHC_ttPAYMENT)
        XAHC_ACCEPT("not a payment");

    /* Only police OUTGOING payments (origin == this hook's account). */
    uint8_t origin[20], me[20];
    XAHC_OTXN_ACCOUNT(origin);
    hook_account(XAHC_SBUF(me));
    int outgoing = 1;
    for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
        if (origin[i] != me[i]) outgoing = 0;
    if (!outgoing)
        XAHC_ACCEPT("incoming");

    /* Per-tx spend cap from hook parameter LIM (8-byte drops). */
    uint8_t lim_key[3] = { 'L', 'I', 'M' };
    uint8_t lim[8];
    XAHC_HOOK_PARAM_REQUIRE(lim, lim_key, 8);
    uint64_t limit =
        ((uint64_t)lim[0] << 56) | ((uint64_t)lim[1] << 48) |
        ((uint64_t)lim[2] << 40) | ((uint64_t)lim[3] << 32) |
        ((uint64_t)lim[4] << 24) | ((uint64_t)lim[5] << 16) |
        ((uint64_t)lim[6] << 8)  | ((uint64_t)lim[7]);

    int64_t drops = xahc_otxn_drops();
    XAHC_REQUIRE(drops >= 0, "native amount only");
    XAHC_REQUIRE((uint64_t)drops <= limit, "over per-tx spend limit");

    /* Optional destination lock from hook parameter DST (20-byte account-id). */
    uint8_t dst_key[3] = { 'D', 'S', 'T' };
    uint8_t allowed[20];
    if (hook_param(XAHC_SBUF(allowed), XAHC_SBUF(dst_key)) == 20) {
        uint8_t dest[20];
        XAHC_OTXN_DESTINATION(dest);
        int ok = 1;
        for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
            if (dest[i] != allowed[i]) ok = 0;
        XAHC_REQUIRE(ok, "destination not in policy");
    }

    XAHC_ACCEPT("within policy");
    return 0;
}
"#;

const AGENT_GUARDRAIL_TEST: &str = r#"build = "%C%"

# sfAccount AAAA... == the sim's hook_account (0xAA*20) -> marks an OUTGOING payment.
# LIM = 0x0000000000989680 = 10,000,000 drops (10 XAH) per-tx cap.

[[case]]
name = "outgoing within limit accepts"
tt = 0
drops = 5000000
fields = { sfAccount = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
hook_params = { LIM = "0000000000989680" }
expect = "accept"

[[case]]
name = "outgoing over limit rolls back"
tt = 0
drops = 20000000
fields = { sfAccount = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
hook_params = { LIM = "0000000000989680" }
expect = "rollback"

[[case]]
name = "incoming payment passes (not policed)"
tt = 0
drops = 99000000
fields = { sfAccount = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" }
expect = "accept"

[[case]]
name = "non-payment passes"
tt = 99
expect = "accept"
"#;
