//! sim — run a hook .wasm locally with mocked Hook API host functions.
//!
//! The differentiator: unit-test a hook's accept/rollback decision against a
//! synthetic transaction WITHOUT deploying to testnet. This is an MVP host:
//! it implements the subset of the Hook API needed to drive transaction-
//! validation hooks (otxn_type, otxn_field for Amount, accept/rollback, _g,
//! in-memory state). Unknown imports trap if called, so you find out exactly
//! which host fn a hook needs next.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::path::Path;
use wasmtime::*;

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
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Accept(i64),
    Rollback(i64),
    /// hook() returned without calling accept/rollback (unusual)
    Returned(i64),
}

struct Ctx {
    tx: TxFixture,
    state: HashMap<Vec<u8>, Vec<u8>>,
    emitted: Vec<Vec<u8>>,
    outcome: Option<Outcome>,
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

fn mem_of(caller: &mut Caller<'_, Ctx>) -> Result<Memory> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| anyhow!("hook exports no memory"))
}

pub fn run(path: &Path, tx: TxFixture) -> Result<(Outcome, Vec<Vec<u8>>, HashMap<Vec<u8>, Vec<u8>>)> {
    let engine = Engine::default();
    let module = Module::from_file(&engine, path).with_context(|| format!("load {}", path.display()))?;
    let mut store = Store::new(&engine, Ctx { tx, state: HashMap::new(), emitted: vec![], outcome: None });
    let mut linker: Linker<Ctx> = Linker::new(&engine);

    // Guard: always succeeds in sim (budget enforcement is a later feature).
    linker.func_wrap("env", "_g", |_c: Caller<'_, Ctx>, _id: i32, _max: i32| -> i32 { 1 })?;

    // Terminal calls: record outcome, then trap to stop execution (mirrors on-chain).
    linker.func_wrap("env", "accept", |mut c: Caller<'_, Ctx>, _p: i32, _l: i32, code: i64| -> Result<i64> {
        c.data_mut().outcome = Some(Outcome::Accept(code));
        Err(Halt.into())
    })?;
    linker.func_wrap("env", "rollback", |mut c: Caller<'_, Ctx>, _p: i32, _l: i32, code: i64| -> Result<i64> {
        c.data_mut().outcome = Some(Outcome::Rollback(code));
        Err(Halt.into())
    })?;

    // Originating-transaction reads.
    linker.func_wrap("env", "otxn_type", |c: Caller<'_, Ctx>| -> i64 { c.data().tx.tt })?;
    linker.func_wrap("env", "otxn_field", |mut c: Caller<'_, Ctx>, wptr: i32, wlen: i32, fid: i32| -> Result<i64> {
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
                for i in 1..8 { b[i] = (d >> (56 - 8 * i)) as u8; }
                b.to_vec()
            }
            SF_ACCOUNT => c.data().tx.account.to_vec(),
            SF_DESTINATION => c.data().tx.destination.to_vec(),
            _ => return Ok(-29), // DOESNT_EXIST
        };
        if (wlen as usize) < bytes.len() { return Ok(-4); } // TOO_SMALL
        let mem = mem_of(&mut c)?;
        mem.write(&mut c, wptr as usize, &bytes)?;
        Ok(bytes.len() as i64)
    })?;

    // Hook account + ledger basics (stubs sufficient for emit builders).
    linker.func_wrap("env", "hook_account", |mut c: Caller<'_, Ctx>, wptr: i32, wlen: i32| -> Result<i64> {
        if (wlen as usize) < 20 { return Ok(-4); }
        let acc = [0xAAu8; 20];
        let mem = mem_of(&mut c)?;
        mem.write(&mut c, wptr as usize, &acc)?;
        Ok(20)
    })?;
    linker.func_wrap("env", "ledger_seq", |_c: Caller<'_, Ctx>| -> i64 { 1_000_000 })?;

    // In-memory hook state.
    linker.func_wrap("env", "state_set", |mut c: Caller<'_, Ctx>, rptr: i32, rlen: i32, kptr: i32, klen: i32| -> Result<i64> {
        let mem = mem_of(&mut c)?;
        let mut val = vec![0u8; rlen as usize];
        let mut key = vec![0u8; klen as usize];
        mem.read(&c, rptr as usize, &mut val)?;
        mem.read(&c, kptr as usize, &mut key)?;
        c.data_mut().state.insert(key, val);
        Ok(rlen as i64)
    })?;
    linker.func_wrap("env", "state", |mut c: Caller<'_, Ctx>, wptr: i32, wlen: i32, kptr: i32, klen: i32| -> Result<i64> {
        let mem = mem_of(&mut c)?;
        let mut key = vec![0u8; klen as usize];
        mem.read(&c, kptr as usize, &mut key)?;
        let val = match c.data().state.get(&key) { Some(v) => v.clone(), None => return Ok(-29) };
        if (wlen as usize) < val.len() { return Ok(-4); }
        mem.write(&mut c, wptr as usize, &val)?;
        Ok(val.len() as i64)
    })?;

    // Emit: capture the serialized txn blob.
    linker.func_wrap("env", "emit", |mut c: Caller<'_, Ctx>, _wp: i32, _wl: i32, rptr: i32, rlen: i32| -> Result<i64> {
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
    linker.func_wrap("env", "etxn_details", |mut c: Caller<'_, Ctx>, ptr: i32, len: i32| -> Result<i64> {
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

    // Anything else the hook imports → trap with a clear message if invoked.
    linker.define_unknown_imports_as_traps(&module)?;

    let instance = linker.instantiate(&mut store, &module)?;
    let hook = instance.get_typed_func::<i32, i64>(&mut store, "hook").context("hook export missing")?;

    let call = hook.call(&mut store, 0);
    let outcome = match store.data().outcome.clone() {
        Some(o) => o,
        None => match call {
            Ok(rc) => Outcome::Returned(rc),
            Err(e) => return Err(e).context("hook trapped without accept/rollback"),
        },
    };
    let emitted = store.data().emitted.clone();
    let state = store.data().state.clone();
    Ok((outcome, emitted, state))
}
