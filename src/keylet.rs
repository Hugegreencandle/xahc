//! keylet — `util_keylet` for the local hook sim, ported from xahaud.
//!
//! Argument decoding and return codes: applyHook.cpp:2136-2671 (xahaud rc-c63ee8c).
//! Index formulas: src/libxrpl/protocol/Indexes.cpp (`indexHash` = SHA-512Half over the
//! big-endian u16 namespace followed by each argument; integers big-endian, 160/256-bit values
//! as raw bytes — digest.h:176 `endian = big`, hash_append.h:460-466 for UInt32or256).
//! Ledger entry type codes: include/xrpl/protocol/detail/ledger_entries.macro.

use sha2::{Digest, Sha512};

use crate::sto::{rc, Rules};

/// First 32 bytes of SHA-512 over the concatenation of `parts` (digest.h:223-230).
pub fn sha512_half(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    out
}

/// `indexHash(space, args...)` (Indexes.cpp:106-111).
pub fn index_hash(space: u16, parts: &[&[u8]]) -> [u8; 32] {
    let ns = space.to_be_bytes();
    let mut all: Vec<&[u8]> = vec![&ns];
    all.extend_from_slice(parts);
    sha512_half(&all)
}

// LedgerNameSpace (Indexes.cpp:53-104)
const NS_ACCOUNT: u16 = b'a' as u16;
const NS_DIR_NODE: u16 = b'd' as u16;
const NS_TRUST_LINE: u16 = b'r' as u16;
const NS_OFFER: u16 = b'o' as u16;
const NS_OWNER_DIR: u16 = b'O' as u16;
const NS_SKIP_LIST: u16 = b's' as u16;
const NS_ESCROW: u16 = b'u' as u16;
const NS_AMENDMENTS: u16 = b'f' as u16;
const NS_FEE_SETTINGS: u16 = b'e' as u16;
const NS_SIGNER_LIST: u16 = b'S' as u16;
const NS_PAYMENT_CHANNEL: u16 = b'x' as u16;
const NS_CHECK: u16 = b'C' as u16;
const NS_DEPOSIT_PREAUTH: u16 = b'p' as u16;
const NS_NEGATIVE_UNL: u16 = b'N' as u16;
const NS_HOOK: u16 = b'H' as u16;
const NS_HOOK_STATE_DIR: u16 = b'J' as u16;
const NS_HOOK_STATE: u16 = b'v' as u16;
const NS_HOOK_DEFINITION: u16 = b'D' as u16;
const NS_EMITTED_TXN: u16 = b'E' as u16;
const NS_EMITTED_DIR: u16 = b'F' as u16;
const NS_NFTOKEN_OFFER: u16 = b'q' as u16;
const NS_CRON: u16 = b'L' as u16;
pub const NS_RANDOM: u16 = 0x526E;

// LedgerEntryType codes (ledger_entries.macro / LedgerFormats.h)
pub const LT_ANY: u16 = 0;
pub const LT_CHILD: u16 = 0x1CD2;
pub const LT_DIR_NODE: u16 = 0x0064;
const LT_ACCOUNT_ROOT: u16 = 0x0061;
const LT_AMENDMENTS: u16 = 0x0066;
const LT_LEDGER_HASHES: u16 = 0x0068;
const LT_FEE_SETTINGS: u16 = 0x0073;
const LT_NEGATIVE_UNL: u16 = 0x004e;
const LT_RIPPLE_STATE: u16 = 0x0072;
const LT_OFFER: u16 = 0x006f;
const LT_SIGNER_LIST: u16 = 0x0053;
const LT_CHECK: u16 = 0x0043;
const LT_DEPOSIT_PREAUTH: u16 = 0x0070;
const LT_ESCROW: u16 = 0x0075;
const LT_PAYCHAN: u16 = 0x0078;
const LT_HOOK: u16 = b'H' as u16;
const LT_HOOK_STATE: u16 = 0x0076;
const LT_HOOK_DEFINITION: u16 = b'D' as u16;
const LT_EMITTED_TXN: u16 = b'E' as u16;
const LT_NFTOKEN_OFFER: u16 = 0x0037;
const LT_CRON: u16 = 0x0041;

/// keylet_code (include/xrpl/hook/Enum.h:280-318)
pub fn keylet_name(kt: u32) -> &'static str {
    match kt {
        1 => "HOOK", 2 => "HOOK_STATE", 3 => "ACCOUNT", 4 => "AMENDMENTS", 5 => "CHILD", 6 => "SKIP",
        7 => "FEES", 8 => "NEGATIVE_UNL", 9 => "LINE", 10 => "OFFER", 11 => "QUALITY",
        12 => "EMITTED_DIR", 13 => "TICKET", 14 => "SIGNERS", 15 => "CHECK", 16 => "DEPOSIT_PREAUTH",
        17 => "UNCHECKED", 18 => "OWNER_DIR", 19 => "PAGE", 20 => "ESCROW", 21 => "PAYCHAN",
        22 => "EMITTED_TXN", 23 => "NFT_OFFER", 24 => "HOOK_DEFINITION", 25 => "HOOK_STATE_DIR",
        26 => "CRON", 27 => "AMM", 28 => "BRIDGE", 29 => "XCHAIN_OWNED_CLAIM_ID",
        30 => "XCHAIN_OWNED_CREATE_ACCOUNT_CLAIM_ID", 31 => "DID", 32 => "ORACLE",
        33 => "MPTOKEN_ISSUANCE", 34 => "MPTOKEN", 35 => "CREDENTIAL", 36 => "PERMISSIONED_DOMAIN",
        37 => "MANIFEST", _ => "unknown",
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyletOut {
    /// 34-byte serialized keylet: 2-byte BE ledger-entry type + 32-byte key (applyHook.cpp:638-655)
    Keylet([u8; 34]),
    /// a hook return code
    Code(i64),
    /// a keylet type the sim does not model (its result would depend on an amendment whose
    /// Xahau status xahc has not verified, or on code not ported yet)
    NotModeled(u32),
}

fn kl(ty: u16, key: [u8; 32]) -> KeyletOut {
    let mut o = [0u8; 34];
    o[..2].copy_from_slice(&ty.to_be_bytes());
    o[2..].copy_from_slice(&key);
    KeyletOut::Keylet(o)
}

/// Macro.h:230-233
fn not_in_bounds(ptr: u32, len: u32, mem_len: usize) -> bool {
    let (p, l, m) = (ptr as u64, len as u64, mem_len as u64);
    p >= m || p + l > m
}

/// `parseCurrency` (applyHook.cpp:583-636)
fn parse_currency(b: &[u8]) -> Option<[u8; 20]> {
    if b.len() == 20 {
        let mut c = [0u8; 20];
        c.copy_from_slice(b);
        return Some(c);
    }
    if b.len() == 3 {
        let ok = |c: u8| c.is_ascii_alphanumeric() || b"?!@#$%^&*<>(){}[]|".contains(&c);
        if !b.iter().all(|&c| ok(c)) {
            return None;
        }
        let mut c = [0u8; 20];
        c[12..15].copy_from_slice(b);
        return Some(c);
    }
    None
}

/// `util_keylet` after the wrapper's common checks (write bounds, write_len >= 34 —
/// applyHook.cpp:2150-2155, done by the caller). `mem` is the whole wasm linear memory.
#[allow(clippy::too_many_arguments)]
pub fn util_keylet(mem: &[u8], kt: u32, a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, rules: &Rules) -> KeyletOut {
    use KeyletOut::{Code, NotModeled};
    const IA: KeyletOut = Code(rc::INVALID_ARGUMENT);
    const OOB: KeyletOut = Code(rc::OUT_OF_BOUNDS);
    let m = mem.len();
    let rd = |p: u32, n: usize| &mem[p as usize..p as usize + n];
    let acc = |p: u32| -> [u8; 20] { rd(p, 20).try_into().unwrap() };
    let h256 = |p: u32| -> [u8; 32] { rd(p, 32).try_into().unwrap() };

    match kt {
        // QUALITY (applyHook.cpp:2162-2191): dir keylet + 8-byte quality
        11 => {
            if a == 0 || b == 0 || e != 0 || f != 0 {
                return IA;
            }
            if not_in_bounds(a, b, m) {
                return OOB;
            }
            if b != 34 || mem[a as usize] != 0 || mem[a as usize + 1] != 0x64 {
                return IA;
            }
            let mut key: [u8; 32] = rd(a + 2, 32).try_into().unwrap();
            let q = ((c as u64) << 32) + d as u64;
            key[24..].copy_from_slice(&q.to_be_bytes()); // Indexes.cpp:332-348
            kl(LT_DIR_NODE, key)
        }
        // 32-byte-uint keylets (applyHook.cpp:2193-2224)
        24 | 5 | 22 | 17 => {
            if a == 0 || b == 0 || c != 0 || d != 0 || e != 0 || f != 0 {
                return IA;
            }
            if not_in_bounds(a, b, m) {
                return OOB;
            }
            if b != 32 {
                return IA;
            }
            let id = h256(a);
            match kt {
                5 => kl(LT_CHILD, id),                                           // Indexes.cpp:220-224
                22 => kl(LT_EMITTED_TXN, index_hash(NS_EMITTED_TXN, &[&id])),     // :189-193
                24 => kl(LT_HOOK_DEFINITION, index_hash(NS_HOOK_DEFINITION, &[&id])), // :201-206
                _ => kl(LT_ANY, id),                                             // :419-423
            }
        }
        // DID (applyHook.cpp:2230-2235) is amendment-gated (featureDID) and its Xahau status is unverified
        31 => NotModeled(kt),
        // 20-byte-account keylets (applyHook.cpp:2225-2264)
        18 | 14 | 3 | 1 => {
            if a == 0 || b == 0 || c != 0 || d != 0 || e != 0 || f != 0 {
                return IA;
            }
            if not_in_bounds(a, b, m) {
                return OOB;
            }
            if b != 20 {
                return IA;
            }
            let id = acc(a);
            match kt {
                1 => kl(LT_HOOK, index_hash(NS_HOOK, &[&id])), // Indexes.cpp:195-199
                14 => kl(LT_SIGNER_LIST, index_hash(NS_SIGNER_LIST, &[&id, &0u32.to_be_bytes()])), // :374-385
                18 => kl(LT_DIR_NODE, index_hash(NS_OWNER_DIR, &[&id])), // :425-429
                _ => kl(LT_ACCOUNT_ROOT, index_hash(NS_ACCOUNT, &[&id])), // :214-218
            }
        }
        // MANIFEST (applyHook.cpp:2266, featureOnChainManifests), ORACLE (:2296, featurePriceOracle),
        // AMM (:2608, featureAMM):
        // amendment-gated with unverified Xahau status → not modelled
        37 | 32 | 27 => NotModeled(kt),
        // account + UInt32or256 keylets (applyHook.cpp:2323-2365)
        10 | 15 | 20 | 23 => {
            if a == 0 || b == 0 || e != 0 || f != 0 {
                return IA;
            }
            if not_in_bounds(a, b, m) {
                return OOB;
            }
            if b != 20 {
                return IA;
            }
            let id = acc(a);
            let seq: Vec<u8> = if d == 0 {
                c.to_be_bytes().to_vec()
            } else if d != 32 {
                return IA;
            } else {
                if not_in_bounds(c, 32, m) {
                    return OOB;
                }
                rd(c, 32).to_vec()
            };
            match kt {
                15 => kl(LT_CHECK, index_hash(NS_CHECK, &[&id, &seq])), // Indexes.cpp:387-391
                20 => kl(LT_ESCROW, index_hash(NS_ESCROW, &[&id, &seq])), // :440-444
                23 => kl(LT_NFTOKEN_OFFER, index_hash(NS_NFTOKEN_OFFER, &[&id, &seq])), // :480-485
                _ => kl(LT_OFFER, index_hash(NS_OFFER, &[&id, &seq])), // :325-329
            }
        }
        // CRON (applyHook.cpp:2366-2392; Indexes.cpp:529-559)
        26 => {
            if !rules.cron {
                return IA;
            }
            if a == 0 || b == 0 || e != 0 || f != 0 || d != 0 {
                return IA;
            }
            if not_in_bounds(a, b, m) {
                return OOB;
            }
            if b != 20 {
                return IA;
            }
            let id = acc(a);
            let ns = index_hash(NS_CRON, &[]);
            let acc_hash = index_hash(NS_CRON, &[&c.to_be_bytes(), &id]);
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&ns[..8]);
            key[8..12].copy_from_slice(&c.to_be_bytes());
            key[12..].copy_from_slice(&acc_hash[..20]);
            kl(LT_CRON, key)
        }
        // PAGE (applyHook.cpp:2393-2414; Indexes.cpp:431-438)
        19 => {
            if a == 0 || b == 0 || e != 0 || f != 0 {
                return IA;
            }
            if not_in_bounds(a, b, m) {
                return OOB;
            }
            if b != 32 {
                return IA;
            }
            let key = h256(a);
            let index = ((c as u64) << 32) + d as u64;
            if index == 0 {
                kl(LT_DIR_NODE, key)
            } else {
                kl(LT_DIR_NODE, index_hash(NS_DIR_NODE, &[&key, &index.to_be_bytes()]))
            }
        }
        // HOOK_STATE (applyHook.cpp:2415-2437; Indexes.cpp:208-212)
        2 => {
            if a == 0 || b == 0 || c == 0 || d == 0 || e == 0 || f == 0 {
                return IA;
            }
            if not_in_bounds(a, b, m) || not_in_bounds(c, d, m) || not_in_bounds(e, f, m) {
                return OOB;
            }
            if b != 20 || d != 32 || f != 32 {
                return IA;
            }
            kl(LT_HOOK_STATE, index_hash(NS_HOOK_STATE, &[&acc(a), &h256(c), &h256(e)]))
        }
        // HOOK_STATE_DIR (applyHook.cpp:2438-2465; Indexes.cpp:183-187)
        25 => {
            if !rules.hooks_update1 {
                return IA;
            }
            if a == 0 || b == 0 || c == 0 || d == 0 || e != 0 || f != 0 {
                return IA;
            }
            if not_in_bounds(a, b, m) || not_in_bounds(c, d, m) {
                return OOB;
            }
            if b != 20 || d != 32 {
                return IA;
            }
            kl(LT_DIR_NODE, index_hash(NS_HOOK_STATE_DIR, &[&acc(a), &h256(c)]))
        }
        // SKIP (applyHook.cpp:2466-2476; Indexes.cpp:226-242)
        6 => {
            if c != 0 || d != 0 || e != 0 || f != 0 || b > 1 {
                return IA;
            }
            if b == 0 {
                kl(LT_LEDGER_HASHES, index_hash(NS_SKIP_LIST, &[]))
            } else {
                kl(LT_LEDGER_HASHES, index_hash(NS_SKIP_LIST, &[&(a >> 16).to_be_bytes()]))
            }
        }
        // no-argument keylets (applyHook.cpp:2477-2517)
        4 | 7 | 8 | 12 => {
            if a != 0 || b != 0 || c != 0 || d != 0 || e != 0 || f != 0 {
                return IA;
            }
            match kt {
                4 => kl(LT_AMENDMENTS, index_hash(NS_AMENDMENTS, &[])),      // Indexes.cpp:244-250
                7 => kl(LT_FEE_SETTINGS, index_hash(NS_FEE_SETTINGS, &[])),  // :258-264
                8 => kl(LT_NEGATIVE_UNL, index_hash(NS_NEGATIVE_UNL, &[])),  // :266-272
                _ => kl(LT_DIR_NODE, index_hash(NS_EMITTED_DIR, &[])),       // :175-181
            }
        }
        // LINE (applyHook.cpp:2519-2545; Indexes.cpp:295-323): accounts in canonical order
        9 => {
            if a == 0 || b == 0 || c == 0 || d == 0 || e == 0 || f == 0 {
                return IA;
            }
            if not_in_bounds(a, b, m) || not_in_bounds(c, d, m) || not_in_bounds(e, f, m) {
                return OOB;
            }
            if b != 20 || d != 20 {
                return IA;
            }
            let cur = match parse_currency(rd(e, f as usize)) {
                Some(c) => c,
                None => return IA,
            };
            let (x, y) = (acc(a), acc(c));
            let (lo, hi) = if y < x { (y, x) } else { (x, y) }; // std::minmax
            kl(LT_RIPPLE_STATE, index_hash(NS_TRUST_LINE, &[&lo, &hi, &cur]))
        }
        // DEPOSIT_PREAUTH (applyHook.cpp:2546-2571; Indexes.cpp:393-399)
        16 => {
            if a == 0 || b == 0 || c == 0 || d == 0 || e != 0 || f != 0 {
                return IA;
            }
            if not_in_bounds(a, b, m) || not_in_bounds(c, d, m) {
                return OOB;
            }
            if b != 20 || d != 20 {
                return IA;
            }
            kl(LT_DEPOSIT_PREAUTH, index_hash(NS_DEPOSIT_PREAUTH, &[&acc(a), &acc(c)]))
        }
        // PAYCHAN (applyHook.cpp:2572-2606; Indexes.cpp:446-454)
        21 => {
            if a == 0 || b == 0 || c == 0 || d == 0 || e == 0 {
                return IA;
            }
            if not_in_bounds(a, b, m) || not_in_bounds(c, d, m) {
                return OOB;
            }
            if b != 20 || d != 20 {
                return IA;
            }
            let seq: Vec<u8> = if f == 0 {
                e.to_be_bytes().to_vec()
            } else if f != 32 {
                return IA;
            } else {
                if not_in_bounds(e, 32, m) {
                    return OOB;
                }
                rd(e, 32).to_vec()
            };
            kl(LT_PAYCHAN, index_hash(NS_PAYMENT_CHANNEL, &[&acc(a), &acc(c), &seq]))
        }
        // explicitly unimplemented in xahaud (applyHook.cpp:2642-2658) → INVALID_ARGUMENT;
        // TICKET (13) has no case at all and falls through to the same final return (:2668)
        _ => IA,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02X}")).collect()
    }
    fn key_of(o: KeyletOut) -> String {
        match o {
            KeyletOut::Keylet(k) => hex(&k),
            other => panic!("expected keylet, got {other:?}"),
        }
    }

    #[test]
    fn singleton_keylets_match_known_ledger_indexes() {
        let mem = [0u8; 64];
        let r = Rules::default();
        // well-known XRPL/Xahau singleton object indexes
        assert_eq!(key_of(util_keylet(&mem, 4, 0, 0, 0, 0, 0, 0, &r)),
            "00667DB0788C020F02780A673DC74757F23823FA3014C1866E72CC4CD8B226CD6EF4");
        assert_eq!(key_of(util_keylet(&mem, 7, 0, 0, 0, 0, 0, 0, &r)),
            "00734BC50C9B0D8515D3EAAE1E74B29A95804346C491EE1A95BF25E4AAB854A6A651");
        assert_eq!(key_of(util_keylet(&mem, 8, 0, 0, 0, 0, 0, 0, &r)),
            "004E2E8A59AA9D3B5B186B0B9E0F62E6C02587CA74A4D778938E957B6357D364B244");
        assert_eq!(util_keylet(&mem, 4, 1, 0, 0, 0, 0, 0, &r), KeyletOut::Code(rc::INVALID_ARGUMENT));
    }

    #[test]
    fn account_keylet_genesis() {
        // rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh = B5F762798A53D543A014CAF8B297CFF8F2F937E8
        let mut mem = vec![0u8; 128];
        let id = [0xB5u8, 0xF7, 0x62, 0x79, 0x8A, 0x53, 0xD5, 0x43, 0xA0, 0x14, 0xCA, 0xF8, 0xB2, 0x97, 0xCF, 0xF8, 0xF2, 0xF9, 0x37, 0xE8];
        mem[8..28].copy_from_slice(&id);
        let r = Rules::default();
        assert_eq!(key_of(util_keylet(&mem, 3, 8, 20, 0, 0, 0, 0, &r)),
            "00612B6AC232AA4C4BE41BF49D2459FA4A0347E1B543A4C92FCEE0821C0201E2E9A8");
        assert_eq!(util_keylet(&mem, 3, 8, 19, 0, 0, 0, 0, &r), KeyletOut::Code(rc::INVALID_ARGUMENT));
        assert_eq!(util_keylet(&mem, 3, 120, 20, 0, 0, 0, 0, &r), KeyletOut::Code(rc::OUT_OF_BOUNDS));
        assert_eq!(util_keylet(&mem, 13, 8, 20, 1, 0, 0, 0, &r), KeyletOut::Code(rc::INVALID_ARGUMENT)); // TICKET
        assert_eq!(util_keylet(&mem, 32, 8, 20, 1, 0, 0, 0, &r), KeyletOut::NotModeled(32));
    }

    #[test]
    fn page_zero_is_identity_and_quality_sets_low_bytes() {
        let mut mem = vec![0u8; 128];
        mem[32..64].copy_from_slice(&[7u8; 32]);
        mem[64] = 0x00;
        mem[65] = 0x64;
        mem[66..98].copy_from_slice(&[7u8; 32]);
        let r = Rules::default();
        assert_eq!(key_of(util_keylet(&mem, 19, 32, 32, 0, 0, 0, 0, &r)), format!("0064{}", "07".repeat(32)));
        // pointer arguments must be non-zero
        assert_eq!(util_keylet(&mem, 19, 0, 32, 0, 0, 0, 0, &r), KeyletOut::Code(rc::INVALID_ARGUMENT));
        // QUALITY writes the 8-byte quality big-endian into the low 8 bytes of a dir key
        let q = key_of(util_keylet(&mem, 11, 64, 34, 0x01020304, 0x05060708, 0, 0, &r));
        assert_eq!(q, format!("0064{}0102030405060708", "07".repeat(24)));
        // QUALITY on a non-dir keylet is INVALID_ARGUMENT
        mem[65] = 0x61;
        assert_eq!(util_keylet(&mem, 11, 64, 34, 1, 1, 0, 0, &r), KeyletOut::Code(rc::INVALID_ARGUMENT));
    }
}
