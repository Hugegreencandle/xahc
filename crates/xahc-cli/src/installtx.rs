//! `xahc install-tx` — emit an UNSIGNED SetHook transaction that installs a built
//! .wasm on an account. Closes the author→deploy gap.
//!
//! The hard part is HookOn — the 256-bit, inverted, active-low fire-on mask
//! (with the active-high SetHook bit). This implementation mirrors xahau-mcp's
//! verified `hookon.js` exactly and is cross-checked against it in CI-able form.
//!
//! Output is UNSIGNED. Sign offline (e.g. xaman / xrpl-accountlib) — xahc never
//! touches keys.

use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::Path;

/// (name, transaction-type value) — from Xahau's hookon tx-type table (47 types).
const TX_TYPES: &[(&str, u32)] = &[
    ("Payment", 0), ("EscrowCreate", 1), ("EscrowFinish", 2), ("AccountSet", 3),
    ("EscrowCancel", 4), ("SetRegularKey", 5), ("NicknameSet", 6), ("OfferCreate", 7),
    ("OfferCancel", 8), ("Contract", 9), ("TicketCreate", 10), ("SpinalTap", 11),
    ("SignerListSet", 12), ("PaymentChannelCreate", 13), ("PaymentChannelFund", 14),
    ("PaymentChannelClaim", 15), ("CheckCreate", 16), ("CheckCash", 17), ("CheckCancel", 18),
    ("DepositPreauth", 19), ("TrustSet", 20), ("AccountDelete", 21), ("SetHook", 22),
    ("NFTokenMint", 25), ("NFTokenBurn", 26), ("NFTokenCreateOffer", 27),
    ("NFTokenCancelOffer", 28), ("NFTokenAcceptOffer", 29), ("Clawback", 30),
    ("URITokenMint", 45), ("URITokenBurn", 46), ("URITokenBuy", 47),
    ("URITokenCreateSellOffer", 48), ("URITokenCancelSellOffer", 49), ("Cron", 92),
    ("CronSet", 93), ("SetRemarks", 94), ("Remit", 95), ("GenesisMint", 96),
    ("Import", 97), ("ClaimReward", 98), ("Invoke", 99), ("Amendment", 100),
    ("Fee", 101), ("UNLModify", 102), ("EmitFailure", 103), ("UNLReport", 104),
];
const SETHOOK_BIT: u32 = 22;

fn set_bit(buf: &mut [u8; 32], n: u32) {
    buf[31 - (n / 8) as usize] |= 1 << (n % 8);
}
fn clear_bit(buf: &mut [u8; 32], n: u32) {
    buf[31 - (n / 8) as usize] &= !(1 << (n % 8));
}

/// Encode the set of fire-on transaction-type values into canonical HookOn hex.
/// Mirrors hookon.js: start all-ones, then for each known type clear its bit to
/// fire (active-low) — except SetHook (bit 22) which is active-high.
fn encode_hook_on(want: &HashSet<u32>) -> String {
    let mut buf = [0xFFu8; 32];
    for &(_, v) in TX_TYPES {
        if v == SETHOOK_BIT {
            if want.contains(&v) { set_bit(&mut buf, v); } else { clear_bit(&mut buf, v); }
        } else if want.contains(&v) {
            clear_bit(&mut buf, v);
        }
    }
    buf.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Resolve a comma list of tx-type names/numbers to their values.
fn parse_types(spec: &str) -> Result<HashSet<u32>> {
    let mut out = HashSet::new();
    for tok in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(n) = tok.parse::<u32>() {
            out.insert(n);
            continue;
        }
        match TX_TYPES.iter().find(|(name, _)| *name == tok) {
            Some((_, v)) => { out.insert(*v); }
            None => bail!("unknown transaction type `{}` (use a name like Payment or a number)", tok),
        }
    }
    Ok(out)
}

fn all_type_values() -> HashSet<u32> {
    TX_TYPES.iter().map(|(_, v)| *v).collect()
}

fn norm_hex_namespace(s: &str) -> Result<String> {
    let h = s.trim().trim_start_matches("0x");
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("namespace must be 64 hex chars (32 bytes)");
    }
    Ok(h.to_uppercase())
}

pub struct Opts<'a> {
    pub account: &'a str,
    pub on: Option<&'a str>,        // comma list; None = fire on all known types
    pub namespace: Option<&'a str>, // 64 hex; None = all-zeros
    pub network: &'a str,           // "testnet" | "mainnet"
    pub flags: u32,                 // hsfOverride = 1
}

pub fn run(wasm: &Path, o: &Opts) -> Result<String> {
    let bytes = std::fs::read(wasm).with_context(|| format!("read {}", wasm.display()))?;
    let create_code: String = bytes.iter().map(|b| format!("{:02X}", b)).collect();

    let want = match o.on {
        Some(spec) => parse_types(spec)?,
        None => all_type_values(),
    };
    let hook_on = encode_hook_on(&want);

    let namespace = match o.namespace {
        Some(ns) => norm_hex_namespace(ns)?,
        None => "0".repeat(64),
    };

    let network_id = match o.network {
        "mainnet" => 21337u32,
        "testnet" => 21338u32,
        other => bail!("network must be testnet or mainnet (got `{}`)", other),
    };

    let tx = serde_json::json!({
        "TransactionType": "SetHook",
        "Account": o.account,
        "NetworkID": network_id,
        "Hooks": [{
            "Hook": {
                "CreateCode": create_code,
                "HookOn": hook_on,
                "HookNamespace": namespace,
                "HookApiVersion": 0,
                "Flags": o.flags,
            }
        }]
    });

    Ok(serde_json::to_string_pretty(&tx)?)
}
