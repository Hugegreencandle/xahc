//! `xahc verify` — the differential gate that makes xahc + xahau-mcp one loop.
//!
//! Runs the built wasm through BOTH the fast local sim (sim.rs) AND a hosted
//! xahau-mcp `/execute` (the fidelity-locked VM), seeding BYTE-IDENTICAL inputs
//! to each, and flags any DISAGREEMENT on the accept/rollback decision. The
//! local sim is the fast inner loop; the MCP VM is the authoritative gate;
//! disagreement is itself a finding (nonzero exit).
//!
//! Talks ONLY to the public HTTP surface — never imports the private MCP — so
//! it runs for any user, not just a both-repos checkout.

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

use crate::sim;

const SF_AMOUNT_ID: &str = "393217"; // (6 << 16) + 1
const SF_ACCOUNT_ID: &str = "524289"; // (8 << 16) + 1
const SF_DESTINATION_ID: &str = "524291"; // (8 << 16) + 3

/// Collapse the two "neither accept nor rollback" labels (local "returned",
/// remote "no-exit-called") so they compare equal.
fn norm_exit(s: &str) -> &str {
    match s {
        "returned" | "no-exit-called" => "neither",
        other => other,
    }
}

#[derive(Serialize)]
pub struct VerifyResult {
    pub remote_url: String,
    pub tx_type: String,
    pub drops: u64,
    pub local: String,        // accept | rollback | returned
    pub remote: String,       // accept | rollback | no-exit-called | halted
    pub agree: bool,
    pub remote_degraded: bool,
    pub remote_code: Option<String>,
}

/// Map a tx-type name (or a raw number) to its numeric value for the local sim,
/// resolving from installtx's CANONICAL TX_TYPES table so the two sides of the
/// toolchain never diverge on a tx-type (e.g. install-tx accepting a name that
/// verify silently can't). Returns the canonical name too, so verify forwards a
/// normalized name to the remote and the SAME-basis number to the local sim.
fn tt_to_num(spec: &str) -> Result<(i64, String)> {
    let n = crate::installtx::resolve_tx_type(spec)?;
    // Canonical name for the resolved value (so a numeric `--tt 0` still sends a
    // proper "Payment" to the remote VM, matching the local sim's numeric input).
    let name = crate::installtx::TX_TYPES
        .iter()
        .find(|(_, v)| *v == n)
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| spec.to_string());
    Ok((n as i64, name))
}

/// Native XAH amount as the 8-byte STAmount the local sim builds (sim.rs):
/// positive (0x40), not-XRP bit (0x80) cleared, drops in the low 62 bits.
fn native_amount_hex(d: u64) -> String {
    let mut b = [0u8; 8];
    b[0] = 0x40 | (((d >> 56) & 0x3F) as u8);
    b[1] = (d >> 48) as u8;
    b[2] = (d >> 40) as u8;
    b[3] = (d >> 32) as u8;
    b[4] = (d >> 24) as u8;
    b[5] = (d >> 16) as u8;
    b[6] = (d >> 8) as u8;
    b[7] = d as u8;
    b.iter().map(|x| format!("{:02X}", x)).collect()
}

pub fn run(wasm: &Path, tt: &str, drops: u64, remote: Option<&str>) -> Result<VerifyResult> {
    let base = remote
        .map(String::from)
        .or_else(|| std::env::var("XAHC_SIM_URL").ok())
        .filter(|s| !s.is_empty())
        .context("no simulator URL — pass --remote <url> or set XAHC_SIM_URL (e.g. http://localhost:8787)")?;
    // Require an explicit http(s) scheme. Without this an attacker-influenced or
    // typo'd value (e.g. "file://", "localhost:8787" parsed oddly, or a bare host)
    // could send the request somewhere unintended — and a scheme-less string would
    // not be a usable URL anyway. Narrow the SSRF surface to deliberate http(s).
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        bail!(
            "simulator URL must start with http:// or https:// (got `{}`) — pass a full URL like http://localhost:8787",
            base
        );
    }
    let endpoint = format!("{}/execute", base.trim_end_matches('/'));
    let (tt_num, tt_name) = tt_to_num(tt)?;

    // --- local sim ---
    let fixture = sim::TxFixture { tt: tt_num, drops, ..Default::default() };
    let (outcome, _emitted, _state) = sim::run(wasm, fixture)?;
    let local = match outcome {
        sim::Outcome::Accept(_) => "accept",
        sim::Outcome::Rollback(_) => "rollback",
        sim::Outcome::Returned(_) => "returned",
        // a guard-budget violation is a rejection on chain (the MCP VM enforces it too)
        sim::Outcome::GuardViolation(_) => "rollback",
    };

    // --- remote VM (xahau-mcp /execute), byte-identical otxn ---
    let bytes = std::fs::read(wasm).with_context(|| format!("read {}", wasm.display()))?;
    let wasm_hex: String = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    // Forward the SAME otxn fields the local sim synthesizes: sim.rs serves sfAmount
    // always, and sfAccount/sfDestination as 20 zero bytes unconditionally. If verify
    // forwarded fewer, a hook reading those fields would see different inputs in the two
    // VMs and false-DISAGREE. Byte-identical inputs are the whole premise.
    let mut otxn = serde_json::Map::new();
    otxn.insert(SF_AMOUNT_ID.to_string(), Value::String(native_amount_hex(drops)));
    otxn.insert(SF_ACCOUNT_ID.to_string(), Value::String("00".repeat(20)));
    otxn.insert(SF_DESTINATION_ID.to_string(), Value::String("00".repeat(20)));
    // Send the CANONICAL name resolved from the shared table (not the raw `tt`), so
    // a numeric `--tt 0` and a name `--tt Payment` send the identical "Payment" to
    // the remote VM, matching the local sim's resolved numeric input exactly.
    let payload = serde_json::json!({ "wasmHex": wasm_hex, "txType": tt_name, "otxnFields": Value::Object(otxn) });
    let resp: Value = ureq::post(&endpoint)
        .send_json(payload)
        .map_err(|e| anyhow!("POST {} failed: {}", endpoint, e))?
        .into_json()
        .context("parse /execute response")?;
    let remote = resp["exit"].as_str().unwrap_or("unknown").to_string();
    let remote_rs = resp["returnString"].as_str().unwrap_or("");
    let remote_degraded = resp["degraded"].as_bool().unwrap_or(false);
    let remote_code = resp["returnCode"].as_str().map(String::from);

    // A runtime rejection in the VM (guard violation / trap) surfaces as exit "halted"
    // with a "runtime error:" message — on chain that is a rollback, the same as the local
    // sim's GuardViolation/trap. A "halted" with any other reason is a pre-execution
    // refusal (oversized module, no hook export, ...), which is NOT a rollback — leave it.
    let remote_for_agree = if remote == "halted" && remote_rs.starts_with("runtime error") {
        "rollback"
    } else {
        remote.as_str()
    };
    // "returned" (local) and "no-exit-called" (remote) are the same neither-accept-nor-rollback case.
    let agree = norm_exit(local) == norm_exit(remote_for_agree);

    Ok(VerifyResult {
        remote_url: endpoint,
        tx_type: tt_name,
        drops,
        local: local.to_string(),
        remote,
        agree,
        remote_degraded,
        remote_code,
    })
}
