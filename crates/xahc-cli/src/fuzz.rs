//! `xahc fuzz` — boundary-biased concrete fuzzer that hunts COUNTEREXAMPLES to an
//! invariant, especially where `xahc prove` returns INCONCLUSIVE.
//!
//! The prover is sound and fails closed: when it can't settle an invariant symbolically
//! (hard arithmetic, an over-approximation, an unroll bound) it returns INCONCLUSIVE — it
//! never guesses. `xahc fuzz` is the concrete complement: it runs the real wasm (via the
//! `sim` host) on many boundary-biased inputs and checks the invariant on each outcome.
//!
//! HONESTY: fuzzing tests existentially, not universally. A found counterexample is a
//! definitive DISPROOF (the hook really is unsafe). Finding none does NOT prove the hook —
//! it only raises empirical confidence. So `xahc fuzz` can turn an INCONCLUSIVE into a
//! DISPROVEN, or into "no counterexample in N runs" — but NEVER into PROVEN. Only the
//! prover proves.
//!
//! Targets stateless invariants whose oracle is a function of (input, outcome): limit,
//! overflow, authz, guardrail. (Stateful invariants need seeded prior state — future work.)

use anyhow::{bail, Result};
use serde::Serialize;
use std::path::Path;

use crate::sim::{self, Outcome, TxFixture};

const OWNER: [u8; 20] = [0xAA; 20]; // sim's hook_account()
/// Native XRP amounts (sfAmount) carry only 62 bits of value. A hook reads `drops`
/// through that field, so the value it sees is the low 62 bits — the oracle MUST use the
/// same effective value or it would report false counterexamples for un-representable drops.
const NATIVE_DROPS_MASK: u64 = (1u64 << 62) - 1;

pub struct Opts<'a> {
    pub invariant: &'a str,
    pub runs: u64,
    pub seed: u64,
    pub lim: u64,
    pub tip: u64,
    /// 40-hex destination accountID for the guardrail DST policy (optional).
    pub dst: Option<&'a str>,
}

#[derive(Serialize)]
pub struct FuzzReport {
    pub invariant: String,
    pub runs: u64,
    pub seed: u64,
    pub accepts: u64,
    pub rollbacks: u64,
    pub guard_violations: u64,
    pub returned: u64,
    /// Counterexamples found — each is a concrete, reproducible disproof.
    pub counterexamples: Vec<Counterexample>,
    /// True only if the accept path was exercised at least once (else the fuzz is weak).
    pub exercised_accept: bool,
}

#[derive(Serialize, Clone)]
pub struct Counterexample {
    pub why: String,
    pub drops: u64,
    pub tip: u64,
    pub account_is_owner: bool,
    pub destination_hex: String,
    pub outcome: String,
}

impl FuzzReport {
    pub fn disproven(&self) -> bool {
        !self.counterexamples.is_empty()
    }
}

// ---- a tiny deterministic PRNG (splitmix64) — no external dep, reproducible by seed ----
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Boundary-biased value generator: hammers the edges where off-by-one and overflow live.
fn gen_value(r: &mut Rng, lim: u64, tip: u64) -> u64 {
    let pick = r.next() % 16;
    match pick {
        0 => 0,
        1 => 1,
        2 => lim.saturating_sub(1),
        3 => lim,
        4 => lim.saturating_add(1),
        5 => lim.saturating_mul(2),
        6 => u64::MAX,
        7 => u64::MAX - 1,
        8 => u64::MAX.saturating_sub(tip), // overflow sweet spot: drops+tip wraps past 0
        9 => u64::MAX - tip.saturating_add(1),
        10 => 1u64 << (r.next() % 64), // a random power of two
        _ => r.next(),                 // uniformly random u64
    }
}

fn u64_be(v: u64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn parse_dst(hex: &str) -> Result<[u8; 20]> {
    let h = hex.trim();
    if h.len() != 40 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("--dst must be a 40-char hex accountID");
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
    }
    Ok(out)
}

pub fn run(wasm: &Path, o: &Opts) -> Result<FuzzReport> {
    let known = ["limit", "overflow", "authz", "guardrail"];
    if !known.contains(&o.invariant) {
        bail!(
            "xahc fuzz supports stateless invariants: {} (got `{}`). For others use `xahc prove`.",
            known.join(", "),
            o.invariant
        );
    }
    let dst = match o.dst {
        Some(h) => Some(parse_dst(h)?),
        None => None,
    };

    let mut rng = Rng(o.seed ^ 0xF1F0_5EED_1234_ABCD);
    let mut rep = FuzzReport {
        invariant: o.invariant.to_string(),
        runs: o.runs,
        seed: o.seed,
        accepts: 0,
        rollbacks: 0,
        guard_violations: 0,
        returned: 0,
        counterexamples: Vec::new(),
        exercised_accept: false,
    };

    for _ in 0..o.runs {
        // drops is read via sfAmount (62-bit native range) — mask so the hook and the
        // oracle agree on the exact value the hook sees (no false counterexamples).
        let drops = gen_value(&mut rng, o.lim, o.tip) & NATIVE_DROPS_MASK;
        // TIP is a raw 8-byte hook param (full u64), and it's the real driver of the
        // drops+tip overflow — fuzz it for `overflow`, else keep the fixed --tip.
        let run_tip = if o.invariant == "overflow" {
            gen_value(&mut rng, o.lim, o.tip)
        } else {
            o.tip
        };
        // For policed/authz invariants, exercise the owner path most of the time.
        let account_is_owner = matches!(o.invariant, "authz" | "guardrail")
            && (rng.next() % 4 != 0);
        let mut destination = [0u8; 20];
        // half the time use the allowed DST, half a random one (to probe the dst lock).
        if let Some(d) = dst {
            if rng.next() % 2 == 0 {
                destination = d;
            } else {
                for b in destination.iter_mut() {
                    *b = (rng.next() & 0xFF) as u8;
                }
            }
        }

        let mut tx = TxFixture {
            tt: 0,
            drops,
            account: if account_is_owner { OWNER } else { [0x11; 20] },
            destination,
            ..Default::default()
        };
        // Install the params the hook reads (so the oracle and the hook agree on LIM/DST/TIP).
        tx.hook_params.insert(b"LIM".to_vec(), u64_be(o.lim));
        if o.invariant == "overflow" {
            tx.hook_params.insert(b"TIP".to_vec(), u64_be(run_tip));
        }
        if let Some(d) = dst {
            tx.hook_params.insert(b"DST".to_vec(), d.to_vec());
        }

        let (outcome, _emit, _state) = sim::run(wasm, tx)?;
        match &outcome {
            Outcome::Accept(_) => {
                rep.accepts += 1;
                rep.exercised_accept = true;
                if let Some(why) = oracle(o, drops, run_tip, account_is_owner, &destination, dst) {
                    rep.counterexamples.push(Counterexample {
                        why,
                        drops,
                        tip: run_tip,
                        account_is_owner,
                        destination_hex: hexstr(&destination),
                        outcome: "ACCEPT".into(),
                    });
                }
            }
            Outcome::Rollback(_) => rep.rollbacks += 1,
            Outcome::GuardViolation(_) => rep.guard_violations += 1,
            Outcome::Returned(_) => rep.returned += 1,
        }
    }
    Ok(rep)
}

/// The concrete invariant oracle: given that the hook ACCEPTED, did it violate the invariant?
/// Returns Some(reason) on a counterexample.
fn oracle(o: &Opts, drops: u64, tip: u64, owner: bool, dest: &[u8; 20], dst: Option<[u8; 20]>) -> Option<String> {
    match o.invariant {
        // accept ⟹ drops ≤ LIM
        "limit" => (drops > o.lim).then(|| format!("accepted drops={} > LIM={}", drops, o.lim)),
        // accept ⟹ true (drops+tip) ≤ LIM, with no uint64 wrap bypass
        "overflow" => {
            let true_sum = drops as u128 + tip as u128;
            (true_sum > o.lim as u128).then(|| {
                format!("accepted true(drops+tip)={} > LIM={} (uint64 wrap bypass)", true_sum, o.lim)
            })
        }
        // accept ⟹ origin == owner
        "authz" => (!owner).then(|| "accepted with origin != owner".to_string()),
        // accept ⟹ (not outgoing) OR (drops ≤ LIM AND dst ∈ allow)
        "guardrail" => {
            if !owner {
                return None; // incoming payment isn't policed by the guardrail
            }
            if drops > o.lim {
                return Some(format!("outgoing accepted drops={} > LIM={}", drops, o.lim));
            }
            if let Some(d) = dst {
                if *dest != d {
                    return Some("outgoing accepted to a destination outside the DST lock".into());
                }
            }
            None
        }
        _ => None,
    }
}

fn hexstr(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02X}", x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(inv: &'static str, lim: u64, tip: u64) -> Opts<'static> {
        Opts { invariant: inv, runs: 0, seed: 1, lim, tip, dst: None }
    }

    #[test]
    fn limit_oracle_flags_over_limit_accept() {
        assert!(oracle(&opts("limit", 100, 0), 101, 0, false, &[0; 20], None).is_some());
        assert!(oracle(&opts("limit", 100, 0), 100, 0, false, &[0; 20], None).is_none());
    }

    #[test]
    fn overflow_oracle_uses_true_128bit_sum() {
        // drops near u64::MAX + tip wraps in u64 but the true sum exceeds LIM => CEX.
        let o = opts("overflow", 1_000_000, 10);
        assert!(oracle(&o, u64::MAX, 10, false, &[0; 20], None).is_some());
        assert!(oracle(&o, 5, 10, false, &[0; 20], None).is_none()); // 5+10 <= 1e6
    }

    #[test]
    fn authz_oracle_flags_non_owner_accept() {
        assert!(oracle(&opts("authz", 0, 0), 0, 0, false, &[0; 20], None).is_some());
        assert!(oracle(&opts("authz", 0, 0), 0, 0, true, &[0; 20], None).is_none());
    }

    #[test]
    fn guardrail_oracle_ignores_incoming_but_flags_outgoing_overlimit() {
        let o = opts("guardrail", 100, 0);
        assert!(oracle(&o, 999, 0, false, &[0; 20], None).is_none()); // incoming: not policed
        assert!(oracle(&o, 999, 0, true, &[0; 20], None).is_some()); // outgoing over limit
    }

    #[test]
    fn rng_is_deterministic_by_seed() {
        let mut a = Rng(42);
        let mut b = Rng(42);
        assert_eq!(a.next(), b.next());
        let mut c = Rng(43);
        assert_ne!(Rng(42).next(), c.next());
    }

    #[test]
    fn gen_value_hits_overflow_boundary() {
        // over enough draws we must produce a value that wraps with a small tip.
        let mut r = Rng(7);
        let tip = 10u64;
        let mut saw_wrap = false;
        for _ in 0..1000 {
            let v = gen_value(&mut r, 1_000_000, tip);
            if v.checked_add(tip).is_none() {
                saw_wrap = true;
                break;
            }
        }
        assert!(saw_wrap, "generator never produced a u64+tip overflow input");
    }
}
