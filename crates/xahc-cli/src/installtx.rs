//! `xahc install-tx` — emit an UNSIGNED SetHook transaction that installs a built
//! .wasm on an account. Closes the author→deploy gap.
//!
//! The hard part is HookOn — the 256-bit, inverted, active-low fire-on mask
//! (with the active-high SetHook bit). The algorithm follows the active-low mask
//! documented for Xahau (and xahau-mcp's hookon.js); golden HookOn values are
//! pinned in unit tests plus a CI regression (not a live cross-check).
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

#[cfg(test)]
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
    pub on: &'a str,                     // comma list of tx types to fire on (required — no implicit fire-on-all)
    pub namespace: Option<&'a str>,      // 64 hex; None = all-zeros
    pub namespace_label: Option<&'a str>, // convenience: sha256(label) as namespace
    pub network: &'a str,                // "testnet" | "mainnet"
    pub flags: u32,                      // hsfOverride = 1
    pub params: &'a [String],            // "nameHex=valueHex" pairs -> HookParameters
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(s.as_bytes());
    d.iter().map(|b| format!("{:02X}", b)).collect()
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Surface-level r-address sanity check (no checksum): starts with `r`, base58
/// ripple alphabet, classic-address length range. Catches typos before a tx is
/// signed/submitted (the signer's lib does the full checksum).
fn is_r_address(s: &str) -> bool {
    const ALPHABET: &[u8] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
    s.starts_with('r')
        && (25..=35).contains(&s.len())
        && s.bytes().all(|b| ALPHABET.contains(&b))
}

pub fn run(wasm: &Path, o: &Opts) -> Result<String> {
    if !is_r_address(o.account) {
        bail!("--account `{}` is not a valid r-address (expected a base58 classic address starting with `r`)", o.account);
    }

    let bytes = std::fs::read(wasm).with_context(|| format!("read {}", wasm.display()))?;

    // Don't package a wasm that wouldn't pass our own lint — install-tx must not be
    // an escape hatch around the safety checks. Run `xahc build` (clean+lint) first.
    let findings = crate::lint::lint(&bytes).with_context(|| format!("lint {}", wasm.display()))?;
    let errors: Vec<&crate::lint::Finding> = findings.iter().filter(|f| matches!(f.level, crate::lint::Level::Error)).collect();
    if !errors.is_empty() {
        let list = errors.iter().map(|f| format!("  - {}", f.msg)).collect::<Vec<_>>().join("\n");
        bail!("refusing to install-tx: the wasm fails lint ({} error(s)) — run `xahc build` first:\n{}", errors.len(), list);
    }
    // Errors block; warnings don't — but surface them so a risky hook (unguarded
    // loop, stack budget) is never packaged silently.
    for f in findings.iter().filter(|f| matches!(f.level, crate::lint::Level::Warn)) {
        eprintln!("warn: {}", f.msg);
    }

    let create_code: String = bytes.iter().map(|b| format!("{:02X}", b)).collect();

    let want = parse_types(o.on)?;
    if want.is_empty() {
        bail!("--on must name at least one transaction type to fire on (e.g. Payment)");
    }
    let hook_on = encode_hook_on(&want);

    let namespace = match (o.namespace, o.namespace_label) {
        (Some(_), Some(_)) => bail!("pass either --namespace or --namespace-label, not both"),
        (Some(ns), None) => norm_hex_namespace(ns)?,
        (None, Some(label)) => sha256_hex(label),
        (None, None) => "0".repeat(64),
    };

    // HookParameters from "nameHex=valueHex" pairs.
    let mut params_json = Vec::new();
    for p in o.params {
        let (name, value) = p
            .split_once('=')
            .with_context(|| format!("--param must be nameHex=valueHex (got `{}`)", p))?;
        if !is_hex(name) || !is_hex(value) {
            bail!("--param name and value must be hex (got `{}`)", p);
        }
        if name.len() > 64 {
            bail!("--param name too long: {} hex chars (max 32 bytes / 64 hex)", name.len());
        }
        if value.len() > 512 {
            bail!("--param value too long: {} hex chars (max 256 bytes / 512 hex)", value.len());
        }
        params_json.push(serde_json::json!({
            "HookParameter": {
                "HookParameterName": name.to_uppercase(),
                "HookParameterValue": value.to_uppercase(),
            }
        }));
    }

    let network_id = match o.network {
        "mainnet" => 21337u32,
        "testnet" => 21338u32,
        other => bail!("network must be testnet or mainnet (got `{}`)", other),
    };

    let mut hook = serde_json::json!({
        "CreateCode": create_code,
        "HookOn": hook_on,
        "HookNamespace": namespace,
        "HookApiVersion": 0,
        "Flags": o.flags,
    });
    if !params_json.is_empty() {
        hook["HookParameters"] = serde_json::Value::Array(params_json);
    }

    let tx = serde_json::json!({
        "TransactionType": "SetHook",
        "Account": o.account,
        "NetworkID": network_id,
        "Hooks": [{ "Hook": hook }]
    });

    Ok(serde_json::to_string_pretty(&tx)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn want(names: &[&str]) -> HashSet<u32> {
        names
            .iter()
            .map(|n| TX_TYPES.iter().find(|(x, _)| x == n).unwrap().1)
            .collect()
    }

    // Derivation: start all-ones; clear bit N to fire (active-low), except SetHook
    // (bit 22) which is active-high. Bit 22 lives in byte 29 (from MSB), bit 6 ->
    // 0xFF & !0x40 = 0xBF. Bit 0 (Payment) is byte 31 bit 0 -> 0xFE.
    #[test]
    fn hookon_empty_fires_nothing() {
        // nothing wanted -> all set, SetHook cleared -> ...BFFFFF
        assert_eq!(encode_hook_on(&HashSet::new()), format!("{}BFFFFF", "F".repeat(58)));
    }

    #[test]
    fn hookon_payment() {
        assert_eq!(encode_hook_on(&want(&["Payment"])), format!("{}BFFFFE", "F".repeat(58)));
    }

    #[test]
    fn hookon_sethook_only() {
        // SetHook wanted (bit stays set, active-high) and nothing else -> all F
        assert_eq!(encode_hook_on(&want(&["SetHook"])), "F".repeat(64));
    }

    #[test]
    fn hookon_is_64_hex() {
        assert_eq!(encode_hook_on(&all_type_values()).len(), 64);
    }

    #[test]
    fn parse_types_names_and_numbers() {
        let got = parse_types("Payment, 99").unwrap();
        let exp: HashSet<u32> = [0u32, 99].into_iter().collect();
        assert_eq!(got, exp);
    }

    #[test]
    fn parse_types_unknown_errs() {
        assert!(parse_types("NotAType").is_err());
    }

    #[test]
    fn namespace_validation() {
        assert!(norm_hex_namespace(&"0".repeat(64)).is_ok());
        assert!(norm_hex_namespace("zz").is_err());
        assert!(norm_hex_namespace(&"0".repeat(63)).is_err());
    }
}
