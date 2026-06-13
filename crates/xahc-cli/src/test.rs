//! `xahc test` — declarative, asserted test runner over the local simulator.
//!
//! Define cases in TOML; each runs the hook against a synthetic transaction and
//! asserts the accept/rollback outcome (and, optionally, emitted-txn / state
//! counts). Nonzero exit on any failure → drop straight into CI.

use anyhow::{bail, Context, Result};
use owo_colors::OwoColorize;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::{build, sim};

#[derive(Deserialize)]
struct TestFile {
    /// Compile this .c first (relative to the test file), then test the output.
    build: Option<String>,
    /// Or test an already-built .wasm.
    wasm: Option<String>,
    #[serde(default, rename = "case")]
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    tt: i64,
    #[serde(default)]
    drops: u64,
    /// "accept" | "rollback" | "returned"
    expect: String,
    /// Optional assertion: exact number of emitted transactions.
    emits: Option<usize>,
    /// Optional assertion: exact number of state keys written.
    state_keys: Option<usize>,
    /// Optional explicit otxn fields: "sfName" or "type.field" -> hex value.
    #[serde(default)]
    fields: HashMap<String, String>,
}

pub fn run(path: &Path) -> Result<()> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let tf: TestFile = toml::from_str(&text).context("parse test TOML")?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));

    // Resolve the wasm under test.
    let wasm_path: PathBuf = if let Some(src) = &tf.build {
        let src = base.join(src);
        let out = std::env::temp_dir().join(format!(
            "xahc-test-{}.wasm",
            src.file_stem().and_then(|s| s.to_str()).unwrap_or("hook")
        ));
        build::run(&src, &out, &[], false).with_context(|| format!("build {}", src.display()))?;
        out
    } else if let Some(w) = &tf.wasm {
        base.join(w)
    } else {
        bail!("test file must set `build = \"x.c\"` or `wasm = \"x.wasm\"`");
    };

    if tf.cases.is_empty() {
        bail!("no [[case]] entries in {}", path.display());
    }

    println!("{} {}  ({} case(s))", "test".bold(), wasm_path.display(), tf.cases.len());
    let mut passed = 0usize;
    let mut failed = 0usize;

    for c in &tf.cases {
        let mut fixture = sim::TxFixture { tt: c.tt, drops: c.drops, ..Default::default() };
        for (k, v) in &c.fields {
            let fid = parse_field_id(k).with_context(|| format!("case `{}`: bad field key `{}`", c.name, k))?;
            let bytes = parse_hex(v).with_context(|| format!("case `{}`: bad hex for `{}`", c.name, k))?;
            fixture.fields.insert(fid, bytes);
        }

        let result = sim::run(&wasm_path, fixture);
        let (ok, detail) = check(c, result);
        if ok {
            passed += 1;
            println!("  {} {:<32} {}", "✓".green().bold(), c.name, detail.dimmed());
        } else {
            failed += 1;
            println!("  {} {:<32} {}", "✗".red().bold(), c.name, detail.red());
        }
    }

    println!("{} passed, {} failed", passed, if failed > 0 { failed.to_string() } else { "0".to_string() });
    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Returns (passed, human-readable detail).
fn check(
    c: &Case,
    result: Result<(sim::Outcome, Vec<Vec<u8>>, HashMap<Vec<u8>, Vec<u8>>)>,
) -> (bool, String) {
    let (outcome, emitted, state) = match result {
        Ok(t) => t,
        Err(e) => return (false, format!("sim error: {}", e)),
    };
    let (got, code) = match &outcome {
        sim::Outcome::Accept(c) => ("accept", *c),
        sim::Outcome::Rollback(c) => ("rollback", *c),
        sim::Outcome::Returned(c) => ("returned", *c),
    };
    let want = c.expect.to_lowercase();
    if got != want {
        return (false, format!("expected {}, got {} (code {})", want, got, code));
    }
    if let Some(n) = c.emits {
        if emitted.len() != n {
            return (false, format!("{} ok but emits {} != {}", got, emitted.len(), n));
        }
    }
    if let Some(n) = c.state_keys {
        if state.len() != n {
            return (false, format!("{} ok but state_keys {} != {}", got, state.len(), n));
        }
    }
    let mut d = format!("{} code={}", got.to_uppercase(), code);
    if c.emits.is_some() { d += &format!(" emits={}", emitted.len()); }
    if c.state_keys.is_some() { d += &format!(" state={}", state.len()); }
    (true, d)
}

/// "type.field" (e.g. "2.14") or a known sf alias -> field-id (type<<16)+field.
fn parse_field_id(key: &str) -> Result<u32> {
    if let Some((t, f)) = key.split_once('.') {
        let t: u32 = t.trim().parse().context("field type")?;
        let f: u32 = f.trim().parse().context("field code")?;
        return Ok((t << 16) + f);
    }
    let id = match key {
        "sfAccount" => (8 << 16) + 1,
        "sfDestination" => (8 << 16) + 3,
        "sfIssuer" => (8 << 16) + 4,
        "sfAmount" => (6 << 16) + 1,
        "sfFee" => (6 << 16) + 8,
        "sfSendMax" => (6 << 16) + 9,
        "sfFlags" => (2 << 16) + 2,
        "sfSourceTag" => (2 << 16) + 3,
        "sfSequence" => (2 << 16) + 4,
        "sfDestinationTag" => (2 << 16) + 14,
        "sfInvoiceID" => (5 << 16) + 17,
        _ => bail!("unknown field `{}` — use \"type.field\" form (e.g. \"2.14\")", key),
    };
    Ok(id)
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() % 2 != 0 {
        bail!("odd-length hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("hex byte"))
        .collect()
}
