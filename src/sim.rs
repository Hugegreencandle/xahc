//! sim — run a hook .wasm locally with mocked Hook API host functions.
//!
//! The differentiator: unit-test a hook's accept/rollback decision against a
//! synthetic transaction WITHOUT deploying to testnet. This is an MVP host:
//! it implements the subset of the Hook API needed to drive transaction-
//! validation hooks (otxn_type, otxn_field for Amount, accept/rollback, _g,
//! in-memory state), plus slots (slot, slot_set, slot_subfield, slot_subarray,
//! slot_type, slot_count, slot_size, slot_clear, meta_slot), serialized-object
//! reads (sto_subfield, sto_subarray), otxn_id, otxn_param and the util
//! family (util_keylet, util_sha512h, util_verify) — those ported from xahaud
//! rc-c63ee8c with file:line citations at each rule. Unknown imports trap if
//! called, so you find out exactly which host fn a hook needs next.

use anyhow::{anyhow, Result};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use wasmtime::error::Context as _; // wasmtime 45 forked Error from anyhow; brings its .context()
use wasmtime::*;

use crate::keylet::{self, KeyletOut};
use crate::sto::{self, rc};

/// A synthetic originating transaction to feed the hook.
#[derive(Clone, Default)]
pub struct TxFixture {
    pub tt: i64,          // transaction type (0 = Payment)
    pub drops: u64,       // native amount, for sfAmount reads
    pub account: [u8; 20],
    pub destination: [u8; 20],
    /// Explicit field overrides: sfcode (field-id) -> raw serialized value bytes.
    /// Takes priority over the convenience fields above.
    pub fields: std::collections::HashMap<u32, Vec<u8>>,
    /// Install-time hook parameters: name bytes -> value bytes (for hook_param).
    pub hook_params: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    /// The originating transaction's `HookParameters` (name, value), in transaction order —
    /// read by `otxn_param`. An empty value reads as DOESNT_EXIST, as on chain.
    pub otxn_params: Vec<(Vec<u8>, Vec<u8>)>,
    /// Explicit originating-transaction id for `otxn_id`. When `None` the sim uses the
    /// deterministic placeholder [`default_otxn_id`] (NOT the real txn hash: the sim never
    /// holds the full serialized transaction).
    pub otxn_id: Option<[u8; 32]>,
    /// Ledger objects visible to `slot_set`: 32-byte keylet key -> serialized STObject (the
    /// SLE's fields, including sfLedgerEntryType). The keylet's 2-byte type is checked against
    /// the object's sfLedgerEntryType exactly like `Keylet::check`.
    pub ledger_objects: std::collections::HashMap<[u8; 32], Vec<u8>>,
    /// Transactions visible to a 32-byte `slot_set(txn_id)` — only consulted when
    /// `rules.fix20261005` is off (with the fix on, 32-byte lookups are INVALID_ARGUMENT).
    pub txns: std::collections::HashMap<[u8; 32], Vec<u8>>,
    /// True for a post-apply run (callback, weak TSH, again-as-weak): the only runs where
    /// xahaud hands the hook a provisional TxMeta (Transactor.cpp:2479-2520). `meta_slot`
    /// returns PREREQUISITE_NOT_MET otherwise.
    pub callback: bool,
    /// Provisional metadata STObject for `meta_slot` when `callback` is set. `None` uses
    /// [`DEFAULT_META`] (tesSUCCESS, TransactionIndex 0, empty AffectedNodes).
    pub meta: Option<Vec<u8>>,
    /// Amendment switches (defaults = Xahau mainnet as xahc understands it).
    pub rules: sto::Rules,
}

/// Placeholder txn id when the fixture gives none: SHA-512Half of
/// `"xahc-sim-otxn-id" || tt (i64 BE) || drops (u64 BE) || account || destination`.
/// Deterministic per fixture, distinct across fixtures, never a real ledger hash.
pub fn default_otxn_id(tx: &TxFixture) -> [u8; 32] {
    keylet::sha512_half(&[
        b"xahc-sim-otxn-id",
        &tx.tt.to_be_bytes(),
        &tx.drops.to_be_bytes(),
        &tx.account,
        &tx.destination,
    ])
}

/// Minimal provisional TxMeta (TxMeta::getAsObject, TxMeta.cpp:238-258, with
/// `setResult(tesSUCCESS, 0)`): TransactionIndex=0, AffectedNodes=[], TransactionResult=0.
pub const DEFAULT_META: [u8; 11] = [0x20, 0x1C, 0, 0, 0, 0, 0xF8, 0xF1, 0x03, 0x10, 0x00];

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Accept(i64),
    Rollback(i64),
    /// hook() returned without calling accept/rollback (unusual)
    Returned(i64),
    /// A guard `_g(id, maxiter)` was crossed more than `maxiter` times — on-chain
    /// this rejects the hook (the loop-bound enforcement). Carries the guard id.
    GuardViolation(i32),
}

struct Ctx {
    tx: TxFixture,
    state: HashMap<Vec<u8>, Vec<u8>>,
    emitted: Vec<Vec<u8>>,
    outcome: Option<Outcome>,
    /// per-guard-id crossing counts, for `_g` budget enforcement
    guards: HashMap<i32, u32>,
    /// names of install-time hook parameters the hook asked for via `hook_param`
    params_read: std::collections::HashSet<Vec<u8>>,
    /// slot table (hookCtx.slot / slot_free / slot_counter)
    slots: Slots,
    /// set when the sim hits something it refuses to guess (e.g. an unmodelled keylet type);
    /// becomes the run's error instead of a generic trap message
    sim_error: Option<String>,
}

/// hook_api::max_slots (include/xrpl/hook/Enum.h:402)
const MAX_SLOTS: u32 = 255;

const STI_OBJECT_KIND: i32 = sto::STI_OBJECT;
/// sfLedgerEntry / sfTransaction / sfTransactionMetaData field codes (sfields.macro:28-29,360)
const SF_LEDGER_ENTRY: u32 = (10002 << 16) | 257;
const SF_TRANSACTION: u32 = (10001 << 16) | 257;
const SF_TRANSACTION_METADATA: u32 = (14 << 16) | 2;
const SF_LEDGER_ENTRY_TYPE: u32 = (1 << 16) | 1;
const SF_TRANSACTION_TYPE: u32 = (1 << 16) | 2;

/// What a slot points at: an STObject, an STArray, or a leaf of serialized type `ty`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Object,
    Array,
    Leaf(i32),
}

/// One slot: the backing serialized object plus the entry inside it (hook::SlotEntry).
/// `start..end` is exactly what `entry->add(Serializer)` produces (see sto::FieldRef::content).
#[derive(Clone, Debug)]
struct SlotEntry {
    storage: Arc<Vec<u8>>,
    kind: Kind,
    /// SField::fieldCode of the entry's name (what slot_type(…, 0) returns)
    fcode: u32,
    start: usize,
    end: usize,
}

impl SlotEntry {
    fn top(storage: Vec<u8>, fcode: u32) -> Self {
        let end = storage.len();
        SlotEntry { storage: Arc::new(storage), kind: Kind::Object, fcode, start: 0, end }
    }
    fn bytes(&self) -> &[u8] {
        &self.storage[self.start..self.end]
    }
    fn child(&self, f: &sto::FieldRef) -> Self {
        let (start, end) = f.content();
        let kind = match f.ty {
            STI_OBJECT_KIND => Kind::Object,
            sto::STI_ARRAY => Kind::Array,
            t => Kind::Leaf(t),
        };
        SlotEntry { storage: self.storage.clone(), kind, fcode: f.code(), start, end }
    }
    fn fields(&self) -> std::result::Result<Vec<sto::FieldRef>, String> {
        sto::parse_fields(&self.storage, self.start, self.end)
    }
}

#[derive(Default)]
struct Slots {
    map: HashMap<u32, SlotEntry>,
    free: VecDeque<u32>,
    counter: u32,
}

impl Slots {
    /// HookAPI::no_free_slots (HookAPI.cpp:2696-2700)
    fn no_free(&self) -> bool {
        self.map.len() >= MAX_SLOTS as usize
    }
    /// HookAPI::get_free_slot (HookAPI.cpp:2702-2730): reuse cleared slots FIFO first, else
    /// advance the counter past occupied numbers; fail past max_slots.
    fn get_free(&mut self) -> Option<u32> {
        if let Some(s) = self.free.pop_front() {
            return Some(s);
        }
        let mut s;
        loop {
            self.counter += 1;
            s = self.counter;
            if !(self.map.contains_key(&s) && self.counter <= MAX_SLOTS) {
                break;
            }
        }
        if self.counter > MAX_SLOTS {
            return None;
        }
        Some(s)
    }
}

/// What a run touched, beyond its outcome. Lets callers (fuzz) tell whether an oracle that
/// assumes a parameter (e.g. LIM) even describes this hook.
#[derive(Default, Clone, Debug)]
pub struct Trace {
    pub params_read: std::collections::HashSet<Vec<u8>>,
}

const SF_AMOUNT: u32 = (6 << 16) + 1;
const SF_ACCOUNT: u32 = (8 << 16) + 1;
const SF_DESTINATION: u32 = (8 << 16) + 3;

/// Signal used to halt wasm execution when accept/rollback is called.
#[derive(Debug)]
struct Halt;
impl std::fmt::Display for Halt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "halt") }
}
impl std::error::Error for Halt {}

fn mem_of(caller: &mut Caller<'_, Ctx>) -> wasmtime::Result<Memory> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| wasmtime::format_err!("hook exports no memory"))
}

/// xahaud HOOK_EXIT bounds check: ptr != 0 and [ptr, ptr+min(len,256)) not inside memory.
fn reason_out_of_bounds(caller: &mut Caller<'_, Ctx>, p: i32, l: i32) -> wasmtime::Result<bool> {
    let ptr = p as u32 as u64;
    if ptr == 0 { return Ok(false); }
    let len = (l as u32 as u64).min(256);
    let size = mem_of(caller)?.data_size(&*caller) as u64;
    Ok(ptr >= size || ptr + len > size)
}

/// (outcome, emitted txn blobs, state writes key->value).
pub type SimResult = (Outcome, Vec<Vec<u8>>, HashMap<Vec<u8>, Vec<u8>>);

pub fn run(path: &Path, tx: TxFixture) -> Result<SimResult> {
    run_traced(path, tx).map(|(r, _)| r)
}

/// `run`, plus a [`Trace`] of what the hook read.
pub fn run_traced(path: &Path, tx: TxFixture) -> Result<(SimResult, Trace)> {
    // wasmtime 45's Error doesn't impl std::error::Error, so it can't cross into
    // anyhow via `?`. Keep the wasmtime work in run_inner (wasmtime::Result) and
    // convert once here.
    run_inner(path, tx).map_err(|e| anyhow!("{e}"))
}

/// Deployable hooks don't export `memory` (xahaud rejects that), but the sim
/// needs a handle to linear memory. Re-add a `memory` export in-memory before
/// instantiating — the on-disk/deploy wasm is untouched.
fn ensure_memory_export(wasm: &[u8]) -> wasmtime::Result<Vec<u8>> {
    let mut m = walrus::Module::from_buffer(wasm).map_err(|e| wasmtime::format_err!("{e}"))?;
    let has_mem = m
        .exports
        .iter()
        .any(|e| e.name == "memory" && matches!(e.item, walrus::ExportItem::Memory(_)));
    if !has_mem {
        if let Some(mem_id) = m.memories.iter().next().map(|x| x.id()) {
            m.exports.add("memory", mem_id);
        }
    }
    Ok(m.emit_wasm())
}

fn run_inner(path: &Path, tx: TxFixture) -> wasmtime::Result<(SimResult, Trace)> {
    let engine = Engine::default();
    let raw = std::fs::read(path).map_err(|e| wasmtime::format_err!("read {}: {e}", path.display()))?;
    let bytes = ensure_memory_export(&raw)?;
    let module = Module::from_binary(&engine, &bytes).with_context(|| format!("load {}", path.display()))?;
    let mut store = Store::new(&engine, Ctx {
        tx,
        state: HashMap::new(),
        emitted: vec![],
        outcome: None,
        guards: HashMap::new(),
        params_read: Default::default(),
        slots: Slots::default(),
        sim_error: None,
    });
    let mut linker: Linker<Ctx> = Linker::new(&engine);

    // Guard: enforce the per-id loop budget. `_g(id, maxiter)` is crossed once per
    // loop iteration; crossing it more than `maxiter` times rejects the hook on
    // chain, so we halt with a GuardViolation (catches infinite/over-budget loops
    // locally instead of falsely accepting them).
    linker.func_wrap("env", "_g", |mut c: Caller<'_, Ctx>, id: i32, max: i32| -> wasmtime::Result<i32> {
        let count = { let e = c.data_mut().guards.entry(id).or_insert(0); *e += 1; *e };
        if max > 0 && count > max as u32 {
            c.data_mut().outcome = Some(Outcome::GuardViolation(id));
            return Err(Halt.into());
        }
        Ok(1)
    })?;

    // Terminal calls: record outcome, then trap to stop execution (mirrors on-chain).
    // A non-zero reason pointer outside wasm memory (reason capped at 256 bytes) ends the
    // hook as a ROLLBACK with OUT_OF_BOUNDS (-1) under fix20260929 (xahaud Macro.h:247-253),
    // live on Xahau mainnet from ledger 26655745.
    linker.func_wrap("env", "accept", |mut c: Caller<'_, Ctx>, p: i32, l: i32, code: i64| -> wasmtime::Result<i64> {
        let out = if reason_out_of_bounds(&mut c, p, l)? { Outcome::Rollback(-1) } else { Outcome::Accept(code) };
        c.data_mut().outcome = Some(out);
        Err(Halt.into())
    })?;
    linker.func_wrap("env", "rollback", |mut c: Caller<'_, Ctx>, p: i32, l: i32, code: i64| -> wasmtime::Result<i64> {
        let out = if reason_out_of_bounds(&mut c, p, l)? { Outcome::Rollback(-1) } else { Outcome::Rollback(code) };
        c.data_mut().outcome = Some(out);
        Err(Halt.into())
    })?;

    // Originating-transaction reads.
    linker.func_wrap("env", "otxn_type", |c: Caller<'_, Ctx>| -> i64 { c.data().tx.tt })?;
    linker.func_wrap("env", "otxn_field", |mut c: Caller<'_, Ctx>, wptr: i32, wlen: i32, fid: i32| -> wasmtime::Result<i64> {
        let fid = fid as u32;
        // Explicit override wins.
        if let Some(bytes) = c.data().tx.fields.get(&fid).cloned() {
            if (wlen as usize) < bytes.len() { return Ok(-4); }
            let mem = mem_of(&mut c)?;
            mem.write(&mut c, wptr as usize, &bytes)?;
            return Ok(bytes.len() as i64);
        }
        let bytes: Vec<u8> = match fid {
            SF_AMOUNT => {
                let d = c.data().tx.drops;
                // native amount, 8 bytes, positive (0x40 bit), "not-XRP" bit (0x80) cleared
                let mut b = [0u8; 8];
                b[0] = 0x40 | (((d >> 56) & 0x3F) as u8);
                for (i, slot) in b.iter_mut().enumerate().skip(1) {
                    *slot = (d >> (56 - 8 * i)) as u8;
                }
                b.to_vec()
            }
            SF_ACCOUNT => c.data().tx.account.to_vec(),
            SF_DESTINATION => c.data().tx.destination.to_vec(),
            _ => return Ok(rc::DOESNT_EXIST),
        };
        if (wlen as usize) < bytes.len() { return Ok(-4); } // TOO_SMALL
        let mem = mem_of(&mut c)?;
        mem.write(&mut c, wptr as usize, &bytes)?;
        Ok(bytes.len() as i64)
    })?;

    // Hook account + ledger basics (stubs sufficient for emit builders).
    linker.func_wrap("env", "hook_account", |mut c: Caller<'_, Ctx>, wptr: i32, wlen: i32| -> wasmtime::Result<i64> {
        if (wlen as usize) < 20 { return Ok(-4); }
        let acc = [0xAAu8; 20];
        let mem = mem_of(&mut c)?;
        mem.write(&mut c, wptr as usize, &acc)?;
        Ok(20)
    })?;
    linker.func_wrap("env", "ledger_seq", |_c: Caller<'_, Ctx>| -> i64 { 1_000_000 })?;

    // Install-time hook parameters: key bytes -> value bytes.
    linker.func_wrap("env", "hook_param", |mut c: Caller<'_, Ctx>, wptr: i32, wlen: i32, rptr: i32, rlen: i32| -> wasmtime::Result<i64> {
        let mem = mem_of(&mut c)?;
        let mut key = vec![0u8; rlen.max(0) as usize];
        mem.read(&c, rptr as usize, &mut key)?;
        c.data_mut().params_read.insert(key.clone());
        let val = match c.data().tx.hook_params.get(&key) {
            Some(v) => v.clone(),
            None => return Ok(rc::DOESNT_EXIST),
        };
        if (wlen as usize) < val.len() { return Ok(-4); }
        mem.write(&mut c, wptr as usize, &val)?;
        Ok(val.len() as i64)
    })?;

    // In-memory hook state.
    linker.func_wrap("env", "state_set", |mut c: Caller<'_, Ctx>, rptr: i32, rlen: i32, kptr: i32, klen: i32| -> wasmtime::Result<i64> {
        let mem = mem_of(&mut c)?;
        let mut val = vec![0u8; rlen as usize];
        let mut key = vec![0u8; klen as usize];
        mem.read(&c, rptr as usize, &mut val)?;
        mem.read(&c, kptr as usize, &mut key)?;
        c.data_mut().state.insert(key, val);
        Ok(rlen as i64)
    })?;
    linker.func_wrap("env", "state", |mut c: Caller<'_, Ctx>, wptr: i32, wlen: i32, kptr: i32, klen: i32| -> wasmtime::Result<i64> {
        let mem = mem_of(&mut c)?;
        let mut key = vec![0u8; klen as usize];
        mem.read(&c, kptr as usize, &mut key)?;
        let val = match c.data().state.get(&key) { Some(v) => v.clone(), None => return Ok(rc::DOESNT_EXIST) };
        if (wlen as usize) < val.len() { return Ok(-4); }
        mem.write(&mut c, wptr as usize, &val)?;
        Ok(val.len() as i64)
    })?;

    // Emit: capture the serialized txn blob.
    linker.func_wrap("env", "emit", |mut c: Caller<'_, Ctx>, _wp: i32, _wl: i32, rptr: i32, rlen: i32| -> wasmtime::Result<i64> {
        let mem = mem_of(&mut c)?;
        let mut blob = vec![0u8; rlen as usize];
        mem.read(&c, rptr as usize, &mut blob)?;
        c.data_mut().emitted.push(blob);
        Ok(rlen as i64)
    })?;
    // Emit-prep stubs (return plausible values so builders proceed).
    linker.func_wrap("env", "etxn_reserve", |_c: Caller<'_, Ctx>, _n: i32| -> i64 { 1 })?;
    // Zero-fill the emit-details region so the blob is deterministic (the real
    // EmitDetails STObject is injected by xahaud; we only verify OUR fields).
    linker.func_wrap("env", "etxn_details", |mut c: Caller<'_, Ctx>, ptr: i32, len: i32| -> wasmtime::Result<i64> {
        let n = (116).min(len.max(0)) as usize;
        let mem = mem_of(&mut c)?;
        let zeros = vec![0u8; n];
        mem.write(&mut c, ptr as usize, &zeros)?;
        Ok(n as i64)
    })?;
    linker.func_wrap("env", "etxn_fee_base", |_c: Caller<'_, Ctx>, _p: i32, _l: i32| -> i64 { 10 })?;

    // Trace: no-op (could be wired to stdout later).
    linker.func_wrap("env", "trace", |_c: Caller<'_, Ctx>, _a: i32, _b: i32, _d: i32, _e: i32, _f: i32| -> i64 { 0 })?;
    linker.func_wrap("env", "trace_num", |_c: Caller<'_, Ctx>, _a: i32, _b: i32, _n: i64| -> i64 { 0 })?;

    register_xahaud_ports(&mut linker)?;

    // Anything else the hook imports → trap with a clear message if invoked.
    linker.define_unknown_imports_as_traps(&module)?;

    let instance = linker.instantiate(&mut store, &module)?;
    let hook = instance.get_typed_func::<i32, i64>(&mut store, "hook").context("hook export missing")?;

    let call = hook.call(&mut store, 0);
    if let Some(msg) = store.data().sim_error.clone() {
        return Err(wasmtime::format_err!("{msg}"));
    }
    let outcome = match store.data().outcome.clone() {
        Some(o) => o,
        None => match call {
            Ok(rc) => Outcome::Returned(rc),
            Err(e) => return Err(e).context(
                "hook trapped without accept/rollback — likely a host fn this local sim doesn't model; \
                 run `xahc verify` for the full-fidelity xahau-mcp VM",
            ),
        },
    };
    let emitted = store.data().emitted.clone();
    let state = store.data().state.clone();
    let trace = Trace { params_read: store.data().params_read.clone() };
    Ok(((outcome, emitted, state), trace))
}

// ---------------------------------------------------------------------------------------------
// Host functions ported from xahaud rc-c63ee8c. Wrapper checks come from
// src/xrpld/app/hook/detail/applyHook.cpp, API bodies from HookAPI.cpp, memory macros from
// include/xrpl/hook/Macro.h. Pointer/length args are wasm i32 reinterpreted as uint32_t.

/// Macro.h:230-233 NOT_IN_BOUNDS
fn oob(c: &mut Caller<'_, Ctx>, ptr: u32, len: u32) -> wasmtime::Result<bool> {
    let size = mem_of(c)?.data_size(&*c) as u64;
    let (p, l) = (ptr as u64, len as u64);
    Ok(p >= size || p + l > size)
}

fn read_mem(c: &mut Caller<'_, Ctx>, ptr: u32, len: u32) -> wasmtime::Result<Vec<u8>> {
    let mem = mem_of(c)?;
    let mut v = vec![0u8; len as usize];
    mem.read(&*c, ptr as usize, &mut v)?;
    Ok(v)
}

/// Macro.h:181-227 WRITE_WASM_MEMORY_AND_RETURN: writes min(src, dst_len) bytes,
/// OUT_OF_BOUNDS if that runs past memory, returns the count.
fn write_and_return(c: &mut Caller<'_, Ctx>, ptr: u32, dst_len: u32, src: &[u8]) -> wasmtime::Result<i64> {
    let n = src.len().min(dst_len as usize);
    let size = mem_of(c)?.data_size(&*c) as u64;
    if ptr as u64 + n as u64 > size {
        return Ok(rc::OUT_OF_BOUNDS);
    }
    let mem = mem_of(c)?;
    mem.write(&mut *c, ptr as usize, &src[..n])?;
    Ok(n as i64)
}

/// applyHook.cpp:696-709 data_as_int64
fn data_as_int64(d: &[u8]) -> i64 {
    if d.len() > 8 {
        return rc::TOO_BIG;
    }
    let mut out: u64 = 0;
    for &b in d {
        out = (out << 8) | b as u64;
    }
    if out & (1u64 << 63) != 0 {
        return rc::TOO_BIG;
    }
    out as i64
}

/// Macro.h:278-304 WRITE_WASM_MEMORY_OR_RETURN_AS_INT64 (incl. the STI_ACCOUNT VL-prefix strip)
fn write_or_int64(c: &mut Caller<'_, Ctx>, wptr: u32, wlen: u32, data: &[u8], is_account: bool) -> wasmtime::Result<i64> {
    let data = if is_account {
        match data.get(1..) {
            Some(d) => d,
            None => return Ok(rc::INTERNAL_ERROR),
        }
    } else {
        data
    };
    if data.is_empty() {
        return Ok(0);
    }
    if wptr == 0 {
        return Ok(data_as_int64(data));
    }
    if data.len() > wlen as usize {
        return Ok(rc::TOO_SMALL);
    }
    write_and_return(c, wptr, wlen, data)
}

/// secp256k1 group order n (PublicKey.cpp:123-124)
const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];
/// Ed25519 subgroup order L, big-endian (PublicKey.cpp:159-163)
const ED25519_L: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED,
];

/// PublicKey.cpp:50-75 sigPart
fn sig_part<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    if buf.len() < 3 || buf[0] != 0x02 {
        return None;
    }
    let len = buf[1] as usize;
    *buf = &buf[2..];
    if len > buf.len() || !(1..=33).contains(&len) {
        return None;
    }
    let num = &buf[..len];
    if num[0] & 0x80 != 0 {
        return None; // negative
    }
    if num[0] == 0 && (len == 1 || num[1] & 0x80 == 0) {
        return None; // zero or padded
    }
    *buf = &buf[len..];
    Some(num)
}

/// big-endian unsigned `x >= n` for a 32-byte n
fn ge_be(x: &[u8], n: &[u8; 32]) -> bool {
    let first = x.iter().position(|&b| b != 0).unwrap_or(x.len());
    let x = &x[first..];
    if x.len() != 32 {
        return x.len() > 32;
    }
    x >= &n[..]
}

/// PublicKey.cpp:112-152 ecdsaCanonicality != nullopt (canonical or fully canonical)
fn ecdsa_canonical(sig: &[u8]) -> bool {
    if sig.len() < 8 || sig.len() > 72 || sig[0] != 0x30 || sig[1] as usize != sig.len() - 2 {
        return false;
    }
    let mut p = &sig[2..];
    let (Some(r), Some(s)) = (sig_part(&mut p), sig_part(&mut p)) else { return false };
    p.is_empty() && !ge_be(r, &SECP256K1_N) && !ge_be(s, &SECP256K1_N)
}

/// ripple::verify(pk, m, sig, mustBeFullyCanonical=false) (PublicKey.cpp:221-300) for a key
/// already known to be 33 bytes with a valid type prefix.
fn verify_sig(data: &[u8], sig: &[u8], key: &[u8]) -> bool {
    if key[0] == 0xED {
        // ed25519Canonical: 64 bytes and S < L (PublicKey.cpp:154-172)
        if sig.len() != 64 {
            return false;
        }
        let mut s_be = [0u8; 32];
        for (i, b) in sig[32..].iter().rev().enumerate() {
            s_be[i] = *b;
        }
        if s_be >= ED25519_L {
            return false;
        }
        use ed25519_dalek::Verifier;
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(key[1..33].try_into().unwrap()) else { return false };
        let sig = ed25519_dalek::Signature::from_bytes(sig.try_into().unwrap());
        return vk.verify(data, &sig).is_ok();
    }
    // secp256k1: verifyDigest(pk, sha512Half(m), sig) — the MESSAGE is hashed with
    // SHA-512Half before ECDSA verification (PublicKey.cpp:280-283); a non-fully-canonical
    // (high-S) signature is normalized first (:252-263).
    if !ecdsa_canonical(sig) {
        return false;
    }
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let digest = keylet::sha512_half(&[data]);
    let Ok(vk) = k256::ecdsa::VerifyingKey::from_sec1_bytes(key) else { return false };
    let Ok(sig) = k256::ecdsa::Signature::from_der(sig) else { return false };
    let sig = sig.normalize_s().unwrap_or(sig);
    vk.verify_prehash(&digest, &sig).is_ok()
}

fn not_modeled(c: &mut Caller<'_, Ctx>, msg: String) -> wasmtime::Result<i64> {
    c.data_mut().sim_error = Some(msg.clone());
    Err(wasmtime::format_err!("{msg}"))
}

fn register_xahaud_ports(linker: &mut Linker<Ctx>) -> wasmtime::Result<()> {
    // otxn_id — applyHook.cpp:1788-1820; HookAPI.cpp:1609-1618 (emit-failure `flags` handling
    // not modelled: the sim never runs an emit-failure callback)
    linker.func_wrap("env", "otxn_id", |mut c: Caller<'_, Ctx>, wp: i32, wl: i32, _flags: i32| -> wasmtime::Result<i64> {
        let (wp, wl) = (wp as u32, wl as u32);
        let id = c.data().tx.otxn_id.unwrap_or_else(|| default_otxn_id(&c.data().tx));
        if 32 > wl {
            return Ok(rc::TOO_SMALL);
        }
        if oob(&mut c, wp, 32)? || oob(&mut c, wp, wl)? {
            return Ok(rc::OUT_OF_BOUNDS);
        }
        write_and_return(&mut c, wp, 32, &id)
    })?;

    // otxn_param — applyHook.cpp:3866-3897; HookAPI.cpp:1660-1693
    linker.func_wrap("env", "otxn_param", |mut c: Caller<'_, Ctx>, wp: i32, wl: i32, rp: i32, rl: i32| -> wasmtime::Result<i64> {
        let (wp, wl, rp, rl) = (wp as u32, wl as u32, rp as u32, rl as u32);
        if oob(&mut c, rp, rl)? || oob(&mut c, wp, wl)? {
            return Ok(rc::OUT_OF_BOUNDS);
        }
        let name = read_mem(&mut c, rp, rl)?;
        if name.is_empty() {
            return Ok(rc::TOO_SMALL);
        }
        if name.len() > 32 {
            return Ok(rc::TOO_BIG);
        }
        // first parameter with this name wins; a missing/empty value is DOESNT_EXIST (HookAPI.cpp:1674-1693)
        let val = match c.data().tx.otxn_params.iter().find(|(n, _)| *n == name) {
            Some((_, v)) if !v.is_empty() => v.clone(),
            _ => return Ok(rc::DOESNT_EXIST),
        };
        if val.len() > wl as usize {
            return Ok(rc::TOO_SMALL);
        }
        write_and_return(&mut c, wp, wl, &val)
    })?;

    // slot — applyHook.cpp:1954-1994; HookAPI.cpp:2252-2262
    linker.func_wrap("env", "slot", |mut c: Caller<'_, Ctx>, wp: i32, wl: i32, slot_no: i32| -> wasmtime::Result<i64> {
        let (wp, wl, slot_no) = (wp as u32, wl as u32, slot_no as u32);
        if wp == 0 {
            if wl != 0 {
                return Ok(rc::INVALID_ARGUMENT);
            }
        } else {
            if oob(&mut c, wp, wl)? {
                return Ok(rc::OUT_OF_BOUNDS);
            }
            if wl < 1 {
                return Ok(rc::TOO_SMALL);
            }
        }
        let Some(e) = c.data().slots.map.get(&slot_no).cloned() else { return Ok(rc::DOESNT_EXIST) };
        write_or_int64(&mut c, wp, wl, e.bytes(), e.kind == Kind::Leaf(sto::STI_ACCOUNT))
    })?;

    // slot_clear — HookAPI.cpp:2264-2273
    linker.func_wrap("env", "slot_clear", |mut c: Caller<'_, Ctx>, slot_no: i32| -> i64 {
        let slot_no = slot_no as u32;
        let s = &mut c.data_mut().slots;
        if s.map.remove(&slot_no).is_none() {
            return rc::DOESNT_EXIST;
        }
        s.free.push_back(slot_no);
        1
    })?;

    // slot_count — HookAPI.cpp:2275-2288
    linker.func_wrap("env", "slot_count", |mut c: Caller<'_, Ctx>, slot_no: i32| -> wasmtime::Result<i64> {
        let Some(e) = c.data().slots.map.get(&(slot_no as u32)).cloned() else { return Ok(rc::DOESNT_EXIST) };
        if e.kind != Kind::Array {
            return Ok(rc::NOT_AN_ARRAY);
        }
        match e.fields() {
            Ok(f) => Ok(f.len() as i64),
            Err(m) => not_modeled(&mut c, format!("slot {slot_no}: malformed array in fixture: {m}")),
        }
    })?;

    // slot_size — HookAPI.cpp:2367-2380 (length of entry->add() output)
    linker.func_wrap("env", "slot_size", |c: Caller<'_, Ctx>, slot_no: i32| -> i64 {
        match c.data().slots.map.get(&(slot_no as u32)) {
            Some(e) => (e.end - e.start) as i64,
            None => rc::DOESNT_EXIST,
        }
    })?;

    // slot_set — applyHook.cpp:2024-2045; HookAPI.cpp:2290-2365
    linker.func_wrap("env", "slot_set", |mut c: Caller<'_, Ctx>, rp: i32, rl: i32, slot_into: i32| -> wasmtime::Result<i64> {
        let (rp, rl, mut slot_into) = (rp as u32, rl as u32, slot_into as u32);
        if oob(&mut c, rp, rl)? {
            return Ok(rc::OUT_OF_BOUNDS);
        }
        let data = read_mem(&mut c, rp, rl)?;
        if (data.len() != 32 && data.len() != 34) || slot_into > MAX_SLOTS {
            return Ok(rc::INVALID_ARGUMENT);
        }
        if slot_into == 0 && c.data().slots.no_free() {
            return Ok(rc::NO_FREE_SLOTS);
        }
        let entry = if data.len() == 34 {
            let ktype = u16::from_be_bytes([data[0], data[1]]);
            let key: [u8; 32] = data[2..].try_into().unwrap();
            if key == [0u8; 32] {
                return Ok(rc::DOESNT_EXIST); // HookAPI.cpp:2309-2310
            }
            if key == keylet::index_hash(keylet::NS_RANDOM, &[]) {
                return Ok(rc::DOESNT_EXIST); // featureRNG guard, HookAPI.cpp:2312-2316
            }
            let Some(obj) = c.data().tx.ledger_objects.get(&key).cloned() else { return Ok(rc::DOESNT_EXIST) };
            let top = SlotEntry::top(obj, SF_LEDGER_ENTRY);
            let fields = match top.fields() {
                Ok(f) => f,
                Err(m) => return not_modeled(&mut c, format!("ledger_objects fixture {}: malformed STObject: {m}", hex32(&key))),
            };
            let lt = fields.iter().find(|f| f.code() == SF_LEDGER_ENTRY_TYPE).map(|f| {
                let (s, _) = f.content();
                u16::from_be_bytes([top.storage[s], top.storage[s + 1]])
            });
            let Some(lt) = lt else {
                return not_modeled(&mut c, format!("ledger_objects fixture {} has no sfLedgerEntryType", hex32(&key)));
            };
            // view().read(kl) applies Keylet::check (Keylet.cpp:25-38; Ledger.cpp:493)
            let ok = ktype == keylet::LT_ANY || (ktype == keylet::LT_CHILD && lt != keylet::LT_DIR_NODE) || ktype == lt;
            if !ok {
                return Ok(rc::DOESNT_EXIST);
            }
            top
        } else {
            // 32-byte txn id: refused outright under fix20261005 (HookAPI.cpp:2326-2327)
            if c.data().tx.rules.fix20261005 {
                return Ok(rc::INVALID_ARGUMENT);
            }
            let key: [u8; 32] = data[..].try_into().unwrap();
            let Some(txb) = c.data().tx.txns.get(&key).cloned() else { return Ok(rc::DOESNT_EXIST) };
            let top = SlotEntry::top(txb, SF_TRANSACTION);
            let fields = match top.fields() {
                Ok(f) => f,
                Err(m) => return not_modeled(&mut c, format!("txns fixture {}: malformed STObject: {m}", hex32(&key))),
            };
            // featureRNG: ttENTROPY (89) is never readable (HookAPI.cpp:2342-2345)
            if fields.iter().any(|f| f.code() == SF_TRANSACTION_TYPE && top.storage[f.body..f.end] == [0, 89]) {
                return Ok(rc::DOESNT_EXIST);
            }
            top
        };
        if slot_into == 0 {
            match c.data_mut().slots.get_free() {
                Some(s) => slot_into = s,
                None => return Ok(rc::NO_FREE_SLOTS),
            }
        }
        c.data_mut().slots.map.insert(slot_into, entry);
        Ok(slot_into as i64)
    })?;

    // slot_subarray — HookAPI.cpp:2382-2441
    linker.func_wrap("env", "slot_subarray", |mut c: Caller<'_, Ctx>, parent: i32, idx: i32, new_slot: i32| -> wasmtime::Result<i64> {
        let (parent, idx, mut new_slot) = (parent as u32, idx as u32, new_slot as u32);
        let Some(p) = c.data().slots.map.get(&parent).cloned() else { return Ok(rc::DOESNT_EXIST) };
        if p.kind != Kind::Array {
            return Ok(rc::NOT_AN_ARRAY);
        }
        if new_slot == 0 && c.data().slots.no_free() {
            return Ok(rc::NO_FREE_SLOTS);
        }
        if new_slot > MAX_SLOTS {
            return Ok(rc::INVALID_ARGUMENT);
        }
        let elems = match p.fields() {
            Ok(f) => f,
            Err(m) => return not_modeled(&mut c, format!("slot {parent}: malformed array in fixture: {m}")),
        };
        let Some(el) = elems.get(idx as usize) else { return Ok(rc::DOESNT_EXIST) };
        let child = p.child(el);
        if new_slot == 0 {
            match c.data_mut().slots.get_free() {
                Some(s) => new_slot = s,
                None => return Ok(rc::NO_FREE_SLOTS),
            }
        }
        c.data_mut().slots.map.insert(new_slot, child);
        Ok(new_slot as i64)
    })?;

    // slot_subfield — applyHook.cpp:2080-2097; HookAPI.cpp:2443-2504
    linker.func_wrap("env", "slot_subfield", |mut c: Caller<'_, Ctx>, parent: i32, field_id: i32, new_slot: i32| -> wasmtime::Result<i64> {
        let (parent, field_id, mut new_slot) = (parent as u32, field_id as u32, new_slot as u32);
        let Some(p) = c.data().slots.map.get(&parent).cloned() else { return Ok(rc::DOESNT_EXIST) };
        if new_slot == 0 && c.data().slots.no_free() {
            return Ok(rc::NO_FREE_SLOTS);
        }
        if new_slot > MAX_SLOTS {
            return Ok(rc::INVALID_ARGUMENT);
        }
        if !sto::is_known_field(field_id) {
            return Ok(rc::INVALID_FIELD); // SField::getField == sfInvalid (HookAPI.cpp:2458-2461)
        }
        // downcast<STObject> throws bad_cast for arrays and leaves (HookAPI.cpp:2468-2472, :2495-2503)
        if p.kind != Kind::Object {
            return Ok(rc::NOT_AN_OBJECT);
        }
        let fields = match p.fields() {
            Ok(f) => f,
            Err(m) => return not_modeled(&mut c, format!("slot {parent}: malformed object in fixture: {m}")),
        };
        let Some(f) = fields.iter().find(|f| f.code() == field_id) else { return Ok(rc::DOESNT_EXIST) };
        let child = p.child(f);
        if new_slot == 0 {
            match c.data_mut().slots.get_free() {
                Some(s) => new_slot = s,
                None => return Ok(rc::NO_FREE_SLOTS),
            }
        }
        c.data_mut().slots.map.insert(new_slot, child);
        Ok(new_slot as i64)
    })?;

    // slot_type — applyHook.cpp:2099-2120; HookAPI.cpp:2506-2537
    linker.func_wrap("env", "slot_type", |c: Caller<'_, Ctx>, slot_no: i32, flags: i32| -> i64 {
        let Some(e) = c.data().slots.map.get(&(slot_no as u32)) else { return rc::DOESNT_EXIST };
        match flags as u32 {
            0 => e.fcode as i64, // getFName().fieldCode
            1 => {
                if e.kind != Kind::Leaf(sto::STI_AMOUNT) {
                    return rc::NOT_AN_AMOUNT;
                }
                // STAmount::native(): the not-native bit 0x80 of the first byte is clear
                (e.storage[e.start] & 0x80 == 0) as i64
            }
            _ => rc::INVALID_ARGUMENT,
        }
    })?;

    // meta_slot — applyHook.cpp:4022-4033; HookAPI.cpp:2599-2626
    linker.func_wrap("env", "meta_slot", |mut c: Caller<'_, Ctx>, slot_into: i32| -> wasmtime::Result<i64> {
        let mut slot_into = slot_into as u32;
        if !c.data().tx.callback {
            return Ok(rc::PREREQUISITE_NOT_MET); // no provisionalMeta in a strong run
        }
        if slot_into > MAX_SLOTS {
            return Ok(rc::INVALID_ARGUMENT);
        }
        if slot_into == 0 && c.data().slots.no_free() {
            return Ok(rc::NO_FREE_SLOTS);
        }
        if slot_into == 0 {
            match c.data_mut().slots.get_free() {
                Some(s) => slot_into = s,
                None => return Ok(rc::NO_FREE_SLOTS),
            }
        }
        let meta = c.data().tx.meta.clone().unwrap_or_else(|| DEFAULT_META.to_vec());
        c.data_mut().slots.map.insert(slot_into, SlotEntry::top(meta, SF_TRANSACTION_METADATA));
        Ok(slot_into as i64)
    })?;

    // sto_subfield / sto_subarray — applyHook.cpp:3027-3073; bodies in sto.rs
    linker.func_wrap("env", "sto_subfield", |mut c: Caller<'_, Ctx>, rp: i32, rl: i32, fid: i32| -> wasmtime::Result<i64> {
        let (rp, rl) = (rp as u32, rl as u32);
        if oob(&mut c, rp, rl)? {
            return Ok(rc::OUT_OF_BOUNDS);
        }
        let data = read_mem(&mut c, rp, rl)?;
        let rules = c.data().tx.rules;
        Ok(match sto::sto_subfield(&data, fid as u32, &rules) {
            Ok((off, len)) => (((off as u64) << 32) + len as u64) as i64,
            Err(code) => code,
        })
    })?;
    linker.func_wrap("env", "sto_subarray", |mut c: Caller<'_, Ctx>, rp: i32, rl: i32, idx: i32| -> wasmtime::Result<i64> {
        let (rp, rl) = (rp as u32, rl as u32);
        if oob(&mut c, rp, rl)? {
            return Ok(rc::OUT_OF_BOUNDS);
        }
        let data = read_mem(&mut c, rp, rl)?;
        let rules = c.data().tx.rules;
        Ok(match sto::sto_subarray(&data, idx as u32, &rules) {
            Ok((off, len)) => (((off as u64) << 32) + len as u64) as i64,
            Err(code) => code,
        })
    })?;

    // util_keylet — applyHook.cpp:2136-2671; per-type logic in keylet.rs
    linker.func_wrap(
        "env",
        "util_keylet",
        |mut c: Caller<'_, Ctx>, wp: i32, wl: i32, kt: i32, a: i32, b: i32, cc: i32, d: i32, e: i32, f: i32| -> wasmtime::Result<i64> {
            let (wp, wl, kt) = (wp as u32, wl as u32, kt as u32);
            if oob(&mut c, wp, wl)? {
                return Ok(rc::OUT_OF_BOUNDS);
            }
            if wl < 34 {
                return Ok(rc::TOO_SMALL);
            }
            let rules = c.data().tx.rules;
            let mem = mem_of(&mut c)?;
            let out = keylet::util_keylet(mem.data(&c), kt, a as u32, b as u32, cc as u32, d as u32, e as u32, f as u32, &rules);
            match out {
                KeyletOut::Keylet(k) => write_and_return(&mut c, wp, 34, &k),
                KeyletOut::Code(code) => Ok(code),
                KeyletOut::NotModeled(t) => not_modeled(
                    &mut c,
                    format!("xahc sim does not model keylet type {t} ({}) yet — run `xahc verify` for the full xahaud VM", keylet::keylet_name(t)),
                ),
            }
        },
    )?;

    // util_sha512h — applyHook.cpp:2996-3021; HookAPI.cpp:62-66
    linker.func_wrap("env", "util_sha512h", |mut c: Caller<'_, Ctx>, wp: i32, wl: i32, rp: i32, rl: i32| -> wasmtime::Result<i64> {
        let (wp, wl, rp, rl) = (wp as u32, wl as u32, rp as u32, rl as u32);
        if wl < 32 {
            return Ok(rc::TOO_SMALL);
        }
        if oob(&mut c, wp, wl)? || oob(&mut c, rp, rl)? {
            return Ok(rc::OUT_OF_BOUNDS);
        }
        let data = read_mem(&mut c, rp, rl)?;
        let h = keylet::sha512_half(&[&data]);
        write_and_return(&mut c, wp, 32, &h)
    })?;

    // util_verify — applyHook.cpp:3349-3380; HookAPI.cpp:42-60
    linker.func_wrap(
        "env",
        "util_verify",
        |mut c: Caller<'_, Ctx>, dp: i32, dl: i32, sp: i32, sl: i32, kp: i32, kl: i32| -> wasmtime::Result<i64> {
            let (dp, dl, sp, sl, kp, kl) = (dp as u32, dl as u32, sp as u32, sl as u32, kp as u32, kl as u32);
            if oob(&mut c, dp, dl)? || oob(&mut c, sp, sl)? || oob(&mut c, kp, kl)? {
                return Ok(rc::OUT_OF_BOUNDS);
            }
            if kl != 33 {
                return Ok(rc::INVALID_KEY);
            }
            if dl == 0 {
                return Ok(rc::TOO_SMALL);
            }
            if sl < 30 {
                return Ok(rc::TOO_SMALL);
            }
            let key = read_mem(&mut c, kp, kl)?;
            // publicKeyType (PublicKey.cpp:206-219)
            if !matches!(key[0], 0xED | 0x02 | 0x03) {
                return Ok(rc::INVALID_KEY);
            }
            let data = read_mem(&mut c, dp, dl)?;
            let sig = read_mem(&mut c, sp, sl)?;
            Ok(verify_sig(&data, &sig, &key) as i64)
        },
    )?;
    Ok(())
}

fn hex32(k: &[u8; 32]) -> String {
    k.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit_outcome(func: &str, ptr: i32, len: i32) -> Outcome {
        let wat = format!(r#"(module
            (import "env" "{func}" (func $exit (param i32 i32 i64) (result i64)))
            (memory (export "memory") 1)
            (func (export "hook") (param i32) (result i64)
              (call $exit (i32.const {ptr}) (i32.const {len}) (i64.const 42))))"#);
        let dir = std::env::temp_dir().join(format!("xahc-sim-exit-{}-{func}-{ptr}-{len}", std::process::id()));
        std::fs::write(&dir, wat::parse_str(&wat).expect("valid wat")).unwrap();
        let r = run(&dir, TxFixture::default()).expect("sim runs").0;
        let _ = std::fs::remove_file(&dir);
        r
    }

    #[test]
    fn exit_reason_out_of_bounds_is_rollback_minus_one() {
        assert_eq!(exit_outcome("accept", 70_000, 4), Outcome::Rollback(-1));
        assert_eq!(exit_outcome("accept", 65_534, 4), Outcome::Rollback(-1));
        assert_eq!(exit_outcome("rollback", 70_000, 4), Outcome::Rollback(-1));
    }

    #[test]
    fn exit_reason_in_bounds_or_null_keeps_the_code() {
        assert_eq!(exit_outcome("accept", 65_532, 4), Outcome::Accept(42));
        assert_eq!(exit_outcome("accept", 0, 9_999), Outcome::Accept(42));
        assert_eq!(exit_outcome("rollback", 0, 0), Outcome::Rollback(42));
    }

    // ---- xahaud-port host functions -------------------------------------------------------

    const IMPORTS: &str = r#"
      (import "env" "accept" (func $accept (param i32 i32 i64) (result i64)))
      (import "env" "otxn_id" (func $otxn_id (param i32 i32 i32) (result i64)))
      (import "env" "otxn_param" (func $otxn_param (param i32 i32 i32 i32) (result i64)))
      (import "env" "slot" (func $slot (param i32 i32 i32) (result i64)))
      (import "env" "slot_set" (func $slot_set (param i32 i32 i32) (result i64)))
      (import "env" "slot_clear" (func $slot_clear (param i32) (result i64)))
      (import "env" "slot_count" (func $slot_count (param i32) (result i64)))
      (import "env" "slot_subfield" (func $slot_subfield (param i32 i32 i32) (result i64)))
      (import "env" "slot_subarray" (func $slot_subarray (param i32 i32 i32) (result i64)))
      (import "env" "slot_type" (func $slot_type (param i32 i32) (result i64)))
      (import "env" "meta_slot" (func $meta_slot (param i32) (result i64)))
      (import "env" "sto_subfield" (func $sto_subfield (param i32 i32 i32) (result i64)))
      (import "env" "sto_subarray" (func $sto_subarray (param i32 i32 i32) (result i64)))
      (import "env" "util_keylet" (func $util_keylet (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i64)))
      (import "env" "util_sha512h" (func $util_sha512h (param i32 i32 i32 i32) (result i64)))
      (import "env" "util_verify" (func $util_verify (param i32 i32 i32 i32 i32 i32) (result i64)))"#;

    fn wat_bytes(b: &[u8]) -> String {
        b.iter().map(|x| format!("\\{x:02x}")).collect()
    }

    /// Run a hook whose body is one i64 expression; the hook accepts with that value as code.
    /// `data` = (offset, bytes) segments placed in memory.
    fn run_expr(data: &[(u32, Vec<u8>)], expr: &str, tx: TxFixture) -> Result<Outcome> {
        let segs: String = data.iter().map(|(o, b)| format!("(data (i32.const {o}) \"{}\")\n", wat_bytes(b))).collect();
        let wat = format!(
            r#"(module {IMPORTS}
              (memory (export "memory") 1)
              {segs}
              (func (export "hook") (param i32) (result i64)
                (drop (call $accept (i32.const 0) (i32.const 0) {expr}))
                (i64.const 0)))"#
        );
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("xahc-sim-port-{}-{n}.wasm", std::process::id()));
        std::fs::write(&path, wat::parse_str(&wat).expect("valid wat")).unwrap();
        let r = run(&path, tx).map(|r| r.0);
        let _ = std::fs::remove_file(&path);
        r
    }

    fn code(data: &[(u32, Vec<u8>)], expr: &str, tx: TxFixture) -> i64 {
        match run_expr(data, expr, tx).expect("sim runs") {
            Outcome::Accept(c) => c,
            o => panic!("expected accept, got {o:?}"),
        }
    }

    fn h(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn payment() -> Vec<u8> {
        let mut v = h("120000228000000024000000016140000000000F424068400000000000000A7321ED");
        v.extend([0x11u8; 32]);
        v.extend(h("8114"));
        v.extend([0xAAu8; 20]);
        v.extend(h("8314"));
        v.extend([0xBBu8; 20]);
        v
    }

    #[test]
    fn sto_subfield_on_payment() {
        let p = payment();
        let d = [(1024, p.clone())];
        let len = p.len();
        // Amount payload at 14, 8 bytes → (14 << 32) | 8
        assert_eq!(code(&d, &format!("(call $sto_subfield (i32.const 1024) (i32.const {len}) (i32.const 0x60001))"), TxFixture::default()), (14 << 32) | 8);
        // Account payload excludes header and VL prefix
        assert_eq!(code(&d, &format!("(call $sto_subfield (i32.const 1024) (i32.const {len}) (i32.const 0x80001))"), TxFixture::default()), (68 << 32) | 20);
        assert_eq!(code(&d, &format!("(call $sto_subfield (i32.const 1024) (i32.const {len}) (i32.const 0x2000e))"), TxFixture::default()), rc::DOESNT_EXIST);
        assert_eq!(code(&d, "(call $sto_subfield (i32.const 65500) (i32.const 100) (i32.const 0x60001))", TxFixture::default()), rc::OUT_OF_BOUNDS);
        // truncated buffer → PARSE_ERROR (fix20260929 validates first)
        assert_eq!(code(&d, "(call $sto_subfield (i32.const 1024) (i32.const 20) (i32.const 0x60001))", TxFixture::default()), rc::PARSE_ERROR);
    }

    #[test]
    fn sto_subarray_on_memos_style_array() {
        // Memos (ARRAY 9 → F9) [ Memo (OBJECT 10 → EA) { MemoData (VL 13 → 7D) 01 AB } E1 ] F1
        let arr = h("F9EA7D01ABE1F1");
        let d = [(512, arr)];
        assert_eq!(code(&d, "(call $sto_subarray (i32.const 512) (i32.const 7) (i32.const 0))", TxFixture::default()), (1 << 32) | 5);
        assert_eq!(code(&d, "(call $sto_subarray (i32.const 512) (i32.const 7) (i32.const 1))", TxFixture::default()), rc::DOESNT_EXIST);
    }

    #[test]
    fn util_sha512h_known_vector() {
        // SHA-512("abc") = ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a …
        let d = [(100, b"abc".to_vec())];
        let first8 = u64::from_le_bytes([0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba]) as i64;
        let last8 = u64::from_le_bytes([0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a]) as i64;
        assert_eq!(code(&d, "(call $util_sha512h (i32.const 2048) (i32.const 32) (i32.const 100) (i32.const 3))", TxFixture::default()), 32);
        assert_eq!(code(&d, "(block (result i64) (drop (call $util_sha512h (i32.const 2048) (i32.const 32) (i32.const 100) (i32.const 3))) (i64.load (i32.const 2048)))", TxFixture::default()), first8);
        assert_eq!(code(&d, "(block (result i64) (drop (call $util_sha512h (i32.const 2048) (i32.const 64) (i32.const 100) (i32.const 3))) (i64.load (i32.const 2072)))", TxFixture::default()), last8);
        // only 32 bytes are written even with a 64-byte buffer
        assert_eq!(code(&d, "(block (result i64) (drop (call $util_sha512h (i32.const 2048) (i32.const 64) (i32.const 100) (i32.const 3))) (i64.load (i32.const 2080)))", TxFixture::default()), 0);
        assert_eq!(code(&d, "(call $util_sha512h (i32.const 2048) (i32.const 31) (i32.const 100) (i32.const 3))", TxFixture::default()), rc::TOO_SMALL);
        assert_eq!(code(&d, "(call $util_sha512h (i32.const 65530) (i32.const 32) (i32.const 100) (i32.const 3))", TxFixture::default()), rc::OUT_OF_BOUNDS);
    }

    fn verify_expr(msg_len: usize, sig_len: usize, key_len: usize) -> String {
        format!("(call $util_verify (i32.const 100) (i32.const {msg_len}) (i32.const 300) (i32.const {sig_len}) (i32.const 500) (i32.const {key_len}))")
    }

    #[test]
    fn util_verify_ed25519_accept_and_reject() {
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let msg = b"xahc sim util_verify".to_vec();
        let sig = sk.sign(&msg).to_bytes().to_vec();
        let mut key = vec![0xED];
        key.extend(sk.verifying_key().to_bytes());
        let mut bad = msg.clone();
        bad[0] ^= 1;
        let ok = [(100, msg.clone()), (300, sig.clone()), (500, key.clone())];
        let tampered = [(100, bad), (300, sig.clone()), (500, key.clone())];
        assert_eq!(code(&ok, &verify_expr(msg.len(), 64, 33), TxFixture::default()), 1);
        assert_eq!(code(&tampered, &verify_expr(msg.len(), 64, 33), TxFixture::default()), 0);
        // key must be 33 bytes; sig at least 30; data non-empty
        assert_eq!(code(&ok, &verify_expr(msg.len(), 64, 32), TxFixture::default()), rc::INVALID_KEY);
        assert_eq!(code(&ok, &verify_expr(msg.len(), 29, 33), TxFixture::default()), rc::TOO_SMALL);
        assert_eq!(code(&ok, &verify_expr(0, 64, 33), TxFixture::default()), rc::TOO_SMALL);
        // unknown key prefix
        let mut k2 = key.clone();
        k2[0] = 0x04;
        assert_eq!(code(&[(100, msg.clone()), (300, sig), (500, k2)], &verify_expr(msg.len(), 64, 33), TxFixture::default()), rc::INVALID_KEY);
    }

    #[test]
    fn util_verify_secp256k1_hashes_with_sha512half() {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let sk = k256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let msg = b"xahc sim secp256k1".to_vec();
        let digest = keylet::sha512_half(&[&msg]);
        let sig: k256::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
        let der = sig.to_der().as_bytes().to_vec();
        let key = sk.verifying_key().to_encoded_point(true).as_bytes().to_vec();
        assert_eq!(key.len(), 33);
        let run_with = |m: &[u8], s: &[u8]| code(&[(100, m.to_vec()), (300, s.to_vec()), (500, key.clone())], &verify_expr(m.len(), s.len(), 33), TxFixture::default());
        assert_eq!(run_with(&msg, &der), 1);
        let mut bad = msg.clone();
        bad[0] ^= 1;
        assert_eq!(run_with(&bad, &der), 0);
        // a high-S (canonical, not fully canonical) signature is normalized and accepted
        let high_s = k256::ecdsa::Signature::from_scalars(sig.r().to_bytes(), (-*sig.s()).to_bytes()).unwrap();
        assert_eq!(run_with(&msg, high_s.to_der().as_bytes()), 1);
        // signing the raw SHA-256 instead of SHA-512Half must NOT verify
        use sha2::Digest as _;
        let wrong: [u8; 32] = sha2::Sha256::digest(&msg).into();
        let sig2: k256::ecdsa::Signature = sk.sign_prehash(&wrong).unwrap();
        assert_eq!(run_with(&msg, sig2.to_der().as_bytes()), 0);
    }

    #[test]
    fn otxn_param_found_missing_too_small() {
        let tx = || TxFixture { otxn_params: vec![(b"AMT".to_vec(), vec![1, 2, 3]), (b"NIL".to_vec(), vec![])], ..Default::default() };
        let d = [(100, b"AMT".to_vec()), (110, b"XYZ".to_vec()), (120, b"NIL".to_vec())];
        assert_eq!(code(&d, "(call $otxn_param (i32.const 200) (i32.const 8) (i32.const 100) (i32.const 3))", tx()), 3);
        assert_eq!(code(&d, "(block (result i64) (drop (call $otxn_param (i32.const 200) (i32.const 8) (i32.const 100) (i32.const 3))) (i64.load8_u (i32.const 202)))", tx()), 3);
        assert_eq!(code(&d, "(call $otxn_param (i32.const 200) (i32.const 8) (i32.const 110) (i32.const 3))", tx()), rc::DOESNT_EXIST);
        assert_eq!(code(&d, "(call $otxn_param (i32.const 200) (i32.const 8) (i32.const 120) (i32.const 3))", tx()), rc::DOESNT_EXIST);
        assert_eq!(code(&d, "(call $otxn_param (i32.const 200) (i32.const 2) (i32.const 100) (i32.const 3))", tx()), rc::TOO_SMALL);
        assert_eq!(code(&d, "(call $otxn_param (i32.const 200) (i32.const 8) (i32.const 100) (i32.const 0))", tx()), rc::TOO_SMALL);
        assert_eq!(code(&d, "(call $otxn_param (i32.const 200) (i32.const 8) (i32.const 100) (i32.const 33))", tx()), rc::TOO_BIG);
        assert_eq!(code(&d, "(call $otxn_param (i32.const 200) (i32.const 8) (i32.const 100) (i32.const 3))", TxFixture::default()), rc::DOESNT_EXIST);
    }

    #[test]
    fn otxn_id_explicit_and_default() {
        let id = [0x5Au8; 32];
        let tx = TxFixture { otxn_id: Some(id), ..Default::default() };
        assert_eq!(code(&[], "(call $otxn_id (i32.const 64) (i32.const 32) (i32.const 0))", tx.clone()), 32);
        assert_eq!(code(&[], "(block (result i64) (drop (call $otxn_id (i32.const 64) (i32.const 32) (i32.const 0))) (i64.load (i32.const 88)))", tx.clone()), 0x5A5A5A5A5A5A5A5A);
        assert_eq!(code(&[], "(call $otxn_id (i32.const 64) (i32.const 31) (i32.const 0))", tx), rc::TOO_SMALL);
        let def = default_otxn_id(&TxFixture::default());
        let want = i64::from_le_bytes(def[..8].try_into().unwrap());
        assert_eq!(code(&[], "(block (result i64) (drop (call $otxn_id (i32.const 64) (i32.const 32) (i32.const 0))) (i64.load (i32.const 64)))", TxFixture::default()), want);
    }

    /// An AccountRoot SLE: LedgerEntryType, Flags, Sequence=5, Balance=1 XRP, Account.
    fn account_root(acc: &[u8; 20]) -> Vec<u8> {
        let mut v = h("110061");
        v.extend(h("2200000000"));
        v.extend(h("2400000005"));
        v.extend(h("6240000000000F4240"));
        v.extend(h("8114"));
        v.extend(acc);
        v
    }

    fn ledger_fixture(acc: [u8; 20]) -> TxFixture {
        let key = keylet::index_hash(b'a' as u16, &[&acc]);
        let mut tx = TxFixture::default();
        tx.ledger_objects.insert(key, account_root(&acc));
        tx
    }

    /// keylet for the account at 100 into 200, slot it into slot 0 (auto), then `then`.
    fn with_account_slot(then: &str) -> String {
        format!(
            "(block (result i64)
               (drop (call $util_keylet (i32.const 200) (i32.const 34) (i32.const 3) (i32.const 100) (i32.const 20) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
               (drop (call $slot_set (i32.const 200) (i32.const 34) (i32.const 0)))
               {then})"
        )
    }

    #[test]
    fn slot_set_found_vs_doesnt_exist() {
        let acc = [0x42u8; 20];
        let d = [(100, acc.to_vec())];
        assert_eq!(code(&d, &with_account_slot("(i64.const 7)"), ledger_fixture(acc)), 7);
        assert_eq!(code(&d, "(block (result i64) (drop (call $util_keylet (i32.const 200) (i32.const 34) (i32.const 3) (i32.const 100) (i32.const 20) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))) (call $slot_set (i32.const 200) (i32.const 34) (i32.const 0)))", ledger_fixture(acc)), 1);
        // object not in the fixture
        assert_eq!(code(&d, "(block (result i64) (drop (call $util_keylet (i32.const 200) (i32.const 34) (i32.const 3) (i32.const 100) (i32.const 20) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))) (call $slot_set (i32.const 200) (i32.const 34) (i32.const 0)))", TxFixture::default()), rc::DOESNT_EXIST);
        // right key, wrong keylet type (OWNER_DIR type 0x0064 vs AccountRoot) → Keylet::check fails
        assert_eq!(code(&d, "(block (result i64) (drop (call $util_keylet (i32.const 200) (i32.const 34) (i32.const 3) (i32.const 100) (i32.const 20) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))) (i32.store8 (i32.const 201) (i32.const 0x64)) (call $slot_set (i32.const 200) (i32.const 34) (i32.const 0)))", ledger_fixture(acc)), rc::DOESNT_EXIST);
        // ltANY (UNCHECKED) matches any type
        assert_eq!(code(&d, "(block (result i64) (drop (call $util_keylet (i32.const 200) (i32.const 34) (i32.const 3) (i32.const 100) (i32.const 20) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))) (i32.store8 (i32.const 201) (i32.const 0)) (call $slot_set (i32.const 200) (i32.const 34) (i32.const 0)))", ledger_fixture(acc)), 1);
        // 32-byte txn id under fix20261005 → INVALID_ARGUMENT; bad length → INVALID_ARGUMENT
        assert_eq!(code(&d, "(call $slot_set (i32.const 300) (i32.const 32) (i32.const 0))", ledger_fixture(acc)), rc::INVALID_ARGUMENT);
        assert_eq!(code(&d, "(call $slot_set (i32.const 300) (i32.const 33) (i32.const 0))", ledger_fixture(acc)), rc::INVALID_ARGUMENT);
        assert_eq!(code(&d, "(call $slot_set (i32.const 300) (i32.const 34) (i32.const 256))", ledger_fixture(acc)), rc::INVALID_ARGUMENT);
        // all-zero key → DOESNT_EXIST
        assert_eq!(code(&d, "(call $slot_set (i32.const 300) (i32.const 34) (i32.const 0))", ledger_fixture(acc)), rc::DOESNT_EXIST);
    }

    #[test]
    fn slot_subfield_and_slot_read_back() {
        let acc = [0x42u8; 20];
        let d = [(100, acc.to_vec())];
        let tx = || ledger_fixture(acc);
        // Balance (6.2) into a new slot → slot 2; read back 8 bytes
        assert_eq!(code(&d, &with_account_slot("(call $slot_subfield (i32.const 1) (i32.const 0x60002) (i32.const 0))"), tx()), 2);
        assert_eq!(code(&d, &with_account_slot("(drop (call $slot_subfield (i32.const 1) (i32.const 0x60002) (i32.const 0))) (call $slot (i32.const 400) (i32.const 8) (i32.const 2))"), tx()), 8);
        // amount bytes 40 00 00 00 00 0F 42 40 read as big-endian i64 via write_ptr=0 mode → 0x40000000000F4240
        assert_eq!(code(&d, &with_account_slot("(drop (call $slot_subfield (i32.const 1) (i32.const 0x60002) (i32.const 0))) (call $slot (i32.const 0) (i32.const 0) (i32.const 2))"), tx()), 0x4000_0000_000F_4240);
        // Sequence (2.4) in int64 mode → 5
        assert_eq!(code(&d, &with_account_slot("(drop (call $slot_subfield (i32.const 1) (i32.const 0x20004) (i32.const 9))) (call $slot (i32.const 0) (i32.const 0) (i32.const 9))"), tx()), 5);
        // Account (8.1): the VL prefix is stripped → 20 bytes
        assert_eq!(code(&d, &with_account_slot("(drop (call $slot_subfield (i32.const 1) (i32.const 0x80001) (i32.const 0))) (call $slot (i32.const 400) (i32.const 20) (i32.const 2))"), tx()), 20);
        assert_eq!(code(&d, &with_account_slot("(drop (call $slot_subfield (i32.const 1) (i32.const 0x80001) (i32.const 0))) (call $slot (i32.const 400) (i32.const 19) (i32.const 2))"), tx()), rc::TOO_SMALL);
        // the whole SLE: 3+5+5+9+22 = 44 bytes; int64 mode is TOO_BIG
        assert_eq!(code(&d, &with_account_slot("(call $slot (i32.const 400) (i32.const 100) (i32.const 1))"), tx()), 44);
        assert_eq!(code(&d, &with_account_slot("(call $slot (i32.const 0) (i32.const 0) (i32.const 1))"), tx()), rc::TOO_BIG);
        assert_eq!(code(&d, &with_account_slot("(call $slot (i32.const 0) (i32.const 1) (i32.const 1))"), tx()), rc::INVALID_ARGUMENT);
        // slot_type: field code, and native flag
        assert_eq!(code(&d, &with_account_slot("(drop (call $slot_subfield (i32.const 1) (i32.const 0x60002) (i32.const 0))) (call $slot_type (i32.const 2) (i32.const 1))"), tx()), 1);
        assert_eq!(code(&d, &with_account_slot("(drop (call $slot_subfield (i32.const 1) (i32.const 0x60002) (i32.const 0))) (call $slot_type (i32.const 2) (i32.const 0))"), tx()), 0x60002);
        assert_eq!(code(&d, &with_account_slot("(call $slot_type (i32.const 1) (i32.const 0))"), tx()), ((10002i64 << 16) | 257));
        assert_eq!(code(&d, &with_account_slot("(call $slot_type (i32.const 1) (i32.const 1))"), tx()), rc::NOT_AN_AMOUNT);
        assert_eq!(code(&d, &with_account_slot("(call $slot_type (i32.const 1) (i32.const 2))"), tx()), rc::INVALID_ARGUMENT);
        // errors: missing field, unknown field code, non-object parent, missing slot
        assert_eq!(code(&d, &with_account_slot("(call $slot_subfield (i32.const 1) (i32.const 0x2000e) (i32.const 0))"), tx()), rc::DOESNT_EXIST);
        assert_eq!(code(&d, &with_account_slot("(call $slot_subfield (i32.const 1) (i32.const 0x600c8) (i32.const 0))"), tx()), rc::INVALID_FIELD);
        assert_eq!(code(&d, &with_account_slot("(drop (call $slot_subfield (i32.const 1) (i32.const 0x60002) (i32.const 0))) (call $slot_subfield (i32.const 2) (i32.const 0x60002) (i32.const 0))"), tx()), rc::NOT_AN_OBJECT);
        assert_eq!(code(&d, "(call $slot_subfield (i32.const 7) (i32.const 0x60002) (i32.const 0))", tx()), rc::DOESNT_EXIST);
        assert_eq!(code(&d, "(call $slot (i32.const 400) (i32.const 8) (i32.const 7))", tx()), rc::DOESNT_EXIST);
        assert_eq!(code(&d, &with_account_slot("(call $slot_count (i32.const 1))"), tx()), rc::NOT_AN_ARRAY);
    }

    #[test]
    fn slot_numbering_reuses_cleared_slots() {
        let acc = [0x42u8; 20];
        let d = [(100, acc.to_vec())];
        // slot 1 = SLE, subfield → 2, clear 1, next allocation reuses 1 (FIFO free list)
        assert_eq!(code(&d, &with_account_slot("(drop (call $slot_subfield (i32.const 1) (i32.const 0x60002) (i32.const 0))) (drop (call $slot_clear (i32.const 1))) (call $slot_set (i32.const 200) (i32.const 34) (i32.const 0))"), ledger_fixture(acc)), 1);
        assert_eq!(code(&d, "(call $slot_clear (i32.const 3))", ledger_fixture(acc)), rc::DOESNT_EXIST);
        // fill all 255 slots explicitly: auto-allocation then fails, explicit numbers still work
        let fill: String = (1..=255).map(|n| format!("(drop (call $slot_set (i32.const 200) (i32.const 34) (i32.const {n})))")).collect();
        assert_eq!(code(&d, &with_account_slot(&format!("{fill} (call $slot_set (i32.const 200) (i32.const 34) (i32.const 0))")), ledger_fixture(acc)), rc::NO_FREE_SLOTS);
        assert_eq!(code(&d, &with_account_slot(&format!("{fill} (call $slot_subfield (i32.const 1) (i32.const 0x60002) (i32.const 0))")), ledger_fixture(acc)), rc::NO_FREE_SLOTS);
        assert_eq!(code(&d, &with_account_slot(&format!("{fill} (call $slot_set (i32.const 200) (i32.const 34) (i32.const 9))")), ledger_fixture(acc)), 9);
    }

    #[test]
    fn meta_slot_requires_callback() {
        assert_eq!(code(&[], "(call $meta_slot (i32.const 0))", TxFixture::default()), rc::PREREQUISITE_NOT_MET);
        let cb = || TxFixture { callback: true, ..Default::default() };
        assert_eq!(code(&[], "(call $meta_slot (i32.const 0))", cb()), 1);
        assert_eq!(code(&[], "(call $meta_slot (i32.const 256))", cb()), rc::INVALID_ARGUMENT);
        assert_eq!(code(&[], "(block (result i64) (drop (call $meta_slot (i32.const 4))) (call $slot_type (i32.const 4) (i32.const 0)))", cb()), (14 << 16) | 2);
        // default meta: TransactionResult (16.3) = tesSUCCESS, AffectedNodes is an empty array
        assert_eq!(code(&[], "(block (result i64) (drop (call $meta_slot (i32.const 1))) (drop (call $slot_subfield (i32.const 1) (i32.const 0x100003) (i32.const 2))) (call $slot (i32.const 0) (i32.const 0) (i32.const 2)))", cb()), 0);
        assert_eq!(code(&[], "(block (result i64) (drop (call $meta_slot (i32.const 1))) (drop (call $slot_subfield (i32.const 1) (i32.const 0xf0008) (i32.const 2))) (call $slot_count (i32.const 2)))", cb()), 0);
    }

    #[test]
    fn util_keylet_unmodelled_type_is_a_clear_error() {
        let d = [(100, vec![0x42u8; 20])];
        let err = run_expr(&d, "(call $util_keylet (i32.const 200) (i32.const 34) (i32.const 32) (i32.const 100) (i32.const 20) (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 0))", TxFixture::default()).unwrap_err();
        assert!(err.to_string().contains("does not model keylet type 32 (ORACLE)"), "{err}");
        // common checks still come first
        assert_eq!(code(&d, "(call $util_keylet (i32.const 200) (i32.const 33) (i32.const 32) (i32.const 100) (i32.const 20) (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 0))", TxFixture::default()), rc::TOO_SMALL);
        assert_eq!(code(&d, "(call $util_keylet (i32.const 200) (i32.const 34) (i32.const 3) (i32.const 100) (i32.const 20) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))", TxFixture::default()), 34);
    }
}
