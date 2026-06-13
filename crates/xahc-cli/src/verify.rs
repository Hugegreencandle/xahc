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

/// Map a tx-type name (or a raw number) to its numeric value for the local sim.
fn tt_to_num(spec: &str) -> Result<i64> {
    if let Ok(n) = spec.parse::<i64>() {
        return Ok(n);
    }
    let n = match spec {
        "Payment" => 0, "EscrowCreate" => 1, "EscrowFinish" => 2, "AccountSet" => 3,
        "EscrowCancel" => 4, "SetRegularKey" => 5, "OfferCreate" => 7, "OfferCancel" => 8,
        "TicketCreate" => 10, "SignerListSet" => 12, "TrustSet" => 20, "AccountDelete" => 21,
        "SetHook" => 22, "ClaimReward" => 98, "Invoke" => 99, "Remit" => 95,
        _ => bail!("unknown tx type `{}` (use a name like Payment/Invoke or a number)", spec),
    };
    Ok(n)
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
    let endpoint = format!("{}/execute", base.trim_end_matches('/'));
    let tt_num = tt_to_num(tt)?;

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
    let mut otxn = serde_json::Map::new();
    if drops > 0 {
        otxn.insert(SF_AMOUNT_ID.to_string(), Value::String(native_amount_hex(drops)));
    }
    let payload = serde_json::json!({ "wasmHex": wasm_hex, "txType": tt, "otxnFields": Value::Object(otxn) });
    let resp: Value = ureq::post(&endpoint)
        .send_json(payload)
        .map_err(|e| anyhow!("POST {} failed: {}", endpoint, e))?
        .into_json()
        .context("parse /execute response")?;
    let remote = resp["exit"].as_str().unwrap_or("unknown").to_string();
    let remote_degraded = resp["degraded"].as_bool().unwrap_or(false);
    let remote_code = resp["returnCode"].as_str().map(String::from);

    // "returned" (local) and "no-exit-called" (remote) are the same neither-accept-nor-rollback case.
    let agree = norm_exit(local) == norm_exit(&remote);

    Ok(VerifyResult {
        remote_url: endpoint,
        tx_type: tt.to_string(),
        drops,
        local: local.to_string(),
        remote,
        agree,
        remote_degraded,
        remote_code,
    })
}
