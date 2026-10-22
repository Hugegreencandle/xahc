//! sto — serialized-object (STObject/STArray) support for the local hook sim.
//!
//! Two parsers live here, on purpose:
//!
//! * [`get_stobject_length`] / [`sto_subfield`] / [`sto_subarray`] are a line-by-line port of
//!   xahaud's *light-weight* walker (`HookAPI::get_stobject_length`, HookAPI.cpp:3124-3448, and
//!   its callers HookAPI.cpp:72-263). The host functions `sto_subfield` / `sto_subarray` must
//!   reproduce its quirks exactly (offsets, header handling, which inputs are PARSE_ERROR), so
//!   it is ported, not re-imagined.
//! * [`parse_fields`] is a plain XRPL binary-codec field walker used to model *slot* contents.
//!   On chain a slot holds a fully parsed `STObject`, not bytes run through the light walker, so
//!   it must accept everything a real ledger object/transaction/metadata can contain.
//!
//! Ground truth: xahaud `rc-c63ee8c` (src/xrpld/app/hook/detail/HookAPI.cpp). Line numbers
//! below refer to that checkout.

/// Hook API return codes (include/xrpl/hook/Enum.h:325ff, mirrored in hook/error.h).
pub mod rc {
    pub const OUT_OF_BOUNDS: i64 = -1;
    pub const INTERNAL_ERROR: i64 = -2;
    pub const TOO_BIG: i64 = -3;
    pub const TOO_SMALL: i64 = -4;
    pub const DOESNT_EXIST: i64 = -5;
    pub const NO_FREE_SLOTS: i64 = -6;
    pub const INVALID_ARGUMENT: i64 = -7;
    pub const PREREQUISITE_NOT_MET: i64 = -9;
    pub const INVALID_FIELD: i64 = -17;
    pub const PARSE_ERROR: i64 = -18;
    pub const NOT_AN_ARRAY: i64 = -22;
    pub const NOT_AN_OBJECT: i64 = -23;
    pub const NOT_AN_AMOUNT: i64 = -32;
    pub const INVALID_KEY: i64 = -41;
}

// Serialized type ids (include/xrpl/protocol/SField.h:63-99).
pub const STI_UINT16: i32 = 1;
pub const STI_UINT32: i32 = 2;
pub const STI_UINT64: i32 = 3;
pub const STI_UINT128: i32 = 4;
pub const STI_UINT256: i32 = 5;
pub const STI_AMOUNT: i32 = 6;
pub const STI_VL: i32 = 7;
pub const STI_ACCOUNT: i32 = 8;
pub const STI_NUMBER: i32 = 9;
pub const STI_OBJECT: i32 = 14;
pub const STI_ARRAY: i32 = 15;
pub const STI_UINT8: i32 = 16;
pub const STI_UINT160: i32 = 17;
pub const STI_PATHSET: i32 = 18;
pub const STI_VECTOR256: i32 = 19;
pub const STI_UINT96: i32 = 20;
pub const STI_UINT192: i32 = 21;
pub const STI_UINT384: i32 = 22;
pub const STI_UINT512: i32 = 23;
pub const STI_ISSUE: i32 = 24;
pub const STI_XCHAIN_BRIDGE: i32 = 25;
pub const STI_CURRENCY: i32 = 26;

/// The amendment switches that change hook-API behaviour modelled by the sim.
/// Defaults describe Xahau mainnet as far as xahc knows it (see each field); override per run
/// through `TxFixture::rules` when testing the other side of an amendment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    /// fix20260929 — live on Xahau mainnet from ledger 26655745 (also assumed by sim's
    /// accept/rollback OUT_OF_BOUNDS handling). Default: on.
    pub fix20260929: bool,
    /// fixHookAPI20251128 (sto_subarray 2-byte array header unwrap). Default: on.
    pub fix_hookapi_20251128: bool,
    /// featureHookAPISerializedType240 (STI types above Vector256 in the light walker,
    /// PathSet parsed natively). Default: off (not enabled on mainnet as of 2026-10).
    pub hookapi_serialized_type240: bool,
    /// fix20261005 (slot_set refuses 32-byte txn-id lookups). Default: on — active on mainnet
    /// since 2026-10-19/20 per CHANGELOG 1.12.1; set false to model a ledger without it.
    pub fix20261005: bool,
    /// featureHooksUpdate1 (gates util_keylet HOOK_STATE_DIR). Default: on.
    pub hooks_update1: bool,
    /// featureCron (gates util_keylet CRON). Default: on.
    pub cron: bool,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            fix20260929: true,
            fix_hookapi_20251128: true,
            hookapi_serialized_type240: false,
            fix20261005: true,
            hooks_update1: true,
            cron: true,
        }
    }
}

/// Every field code xahaud registers in `SField::knownCodeToField` (sorted): sfGeneric (0),
/// sfHash/sfIndex (SField.cpp:76-77) and every entry of
/// include/xrpl/protocol/detail/sfields.macro (xahaud rc-c63ee8c, 339 entries).
/// Generated from that macro file; `SField::getField` returns sfInvalid for anything else
/// (SField.cpp:118-128).
pub const KNOWN_FIELD_CODES: [i32; 342] = [
    0, 65537, 65538, 65539, 65540, 65541, 65542, 65552, 65553, 65554, 65555, 65556, 65557,
    65558, 65635, 65636, 131073, 131074, 131075, 131076, 131077, 131078, 131079, 131080, 131081,
    131082, 131083, 131084, 131085, 131086, 131087, 131088, 131089, 131090, 131091, 131092,
    131093, 131094, 131095, 131096, 131097, 131098, 131099, 131100, 131101, 131102, 131103,
    131104, 131105, 131106, 131107, 131108, 131109, 131110, 131111, 131112, 131113, 131114,
    131115, 131116, 131117, 131118, 131120, 131121, 131122, 131123, 131165, 131166, 131167,
    131168, 131169, 131170, 131171, 131172, 131173, 196609, 196610, 196611, 196612, 196613,
    196614, 196615, 196616, 196617, 196618, 196619, 196620, 196621, 196625, 196626, 196627,
    196628, 196629, 196630, 196631, 196632, 196633, 196634, 196635, 196636, 196705, 196706,
    196707, 196708, 262145, 327681, 327682, 327683, 327684, 327685, 327686, 327687, 327688,
    327689, 327690, 327691, 327692, 327693, 327694, 327695, 327696, 327697, 327698, 327699,
    327700, 327701, 327702, 327703, 327704, 327705, 327706, 327707, 327708, 327709, 327710,
    327711, 327712, 327713, 327714, 327715, 327716, 327717, 327769, 327770, 327771, 327773,
    327774, 327775, 327776, 327777, 327778, 327779, 327937, 327938, 393217, 393218, 393219,
    393220, 393221, 393222, 393223, 393224, 393225, 393226, 393227, 393228, 393229, 393232,
    393233, 393234, 393235, 393236, 393237, 393238, 393239, 393240, 393241, 393242, 393243,
    393244, 393245, 393246, 393247, 393315, 458753, 458754, 458755, 458756, 458757, 458758,
    458759, 458760, 458761, 458762, 458763, 458764, 458765, 458766, 458768, 458769, 458770,
    458771, 458772, 458773, 458774, 458775, 458776, 458777, 458778, 458779, 458780, 458781,
    458782, 458783, 458784, 458848, 458849, 458850, 458851, 524289, 524290, 524291, 524292,
    524293, 524294, 524296, 524297, 524298, 524299, 524304, 524306, 524307, 524308, 524309,
    524310, 524311, 524312, 524387, 589825, 917506, 917507, 917508, 917509, 917510, 917511,
    917512, 917513, 917514, 917515, 917516, 917517, 917518, 917520, 917522, 917523, 917524,
    917525, 917527, 917528, 917529, 917530, 917531, 917532, 917533, 917534, 917535, 917536,
    917537, 917592, 917594, 917595, 917596, 917597, 917598, 917599, 917600, 917601, 917602,
    917603, 983043, 983044, 983045, 983046, 983047, 983048, 983049, 983050, 983051, 983052,
    983056, 983057, 983058, 983059, 983060, 983061, 983062, 983064, 983065, 983066, 983067,
    983068, 983131, 983132, 983133, 983134, 983135, 983136, 983137, 1048577, 1048578, 1048579,
    1048580, 1048581, 1048592, 1048593, 1048594, 1048595, 1114113, 1114114, 1114115, 1114116,
    1179649, 1245185, 1245186, 1245187, 1245188, 1245189, 1245190, 1245283, 1376257, 1572865,
    1572866, 1572867, 1572868, 1572869, 1638401, 1703937, 1703938, 655425793, 655491329,
    655556865, 655622401,
];

/// `SField::getField(code) != sfInvalid` (SField.cpp:118-128). `code` is the `uint32_t`
/// field_id reinterpreted as `int`, exactly as the C++ call does.
pub fn is_known_field(field_id: u32) -> bool {
    KNOWN_FIELD_CODES.binary_search(&(field_id as i32)).is_ok()
}

/// One field found by the light walker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Light {
    /// total bytes incl. header (and the end marker for objects/arrays)
    pub len: usize,
    pub ty: i32,
    pub field: i32,
    /// payload offset relative to the field start (after header and any VL prefix)
    pub payload_start: usize,
    pub payload_len: usize,
}

/// Port of `HookAPI::get_stobject_length` (HookAPI.cpp:3124-3448). `Err(())` is any of its
/// `STOParseErrorCode`s — every caller maps them to the same result. Reads past the end of
/// `d` (undefined behaviour in the C++ when an amendment fix is off) are reported as `Err`.
pub fn get_stobject_length(d: &[u8], start: usize, end: usize, rules: &Rules, depth: u32) -> Result<Light, ()> {
    // HookAPI.cpp:3137
    if depth > 10 {
        return Err(());
    }
    let ser240 = rules.hookapi_serialized_type240;
    let max_sti_type = if ser240 { STI_CURRENCY } else { STI_VECTOR256 }; // :3140-3142
    let at = |i: usize| d.get(i).copied().ok_or(());

    let mut upto = start;
    let b0 = at(upto)?;
    let high = (b0 >> 4) as i32;
    let low = (b0 & 0xF) as i32;
    upto += 1;
    if upto >= end {
        return Err(());
    }
    let (ty, field);
    if high > 0 && low > 0 {
        ty = high;
        field = low;
    } else if high > 0 {
        ty = high;
        field = at(upto)? as i32;
        upto += 1;
    } else if low > 0 {
        field = low;
        ty = at(upto)? as i32;
        upto += 1;
    } else {
        ty = at(upto)? as i32;
        upto += 1;
        if upto >= end {
            return Err(());
        }
        field = at(upto)? as i32;
        upto += 1;
    }
    if upto >= end {
        return Err(());
    }
    // :3198-3205 reserved / unsupported types
    if ty < 1 || max_sti_type < ty || (10..=13).contains(&ty) {
        return Err(());
    }
    if ty == STI_NUMBER || ty == STI_UINT96 || ty == STI_UINT192 || ty == STI_UINT384 || ty == STI_UINT512 {
        return Err(());
    }
    // :3207-3211
    let is_vl = ty == STI_ACCOUNT || ty == STI_VL || (ty == STI_PATHSET && !ser240) || ty == STI_VECTOR256;

    let mut length: i64 = -1;
    if is_vl {
        // :3213-3245 VL length prefix
        length = at(upto)? as i64;
        upto += 1;
        if upto >= end {
            return Err(());
        }
        if length < 193 {
        } else if length < 241 {
            length -= 193;
            length *= 256;
            length += at(upto)? as i64 + 193;
            upto += 1;
            if upto > end {
                return Err(());
            }
        } else {
            let b2 = at(upto)? as i64;
            upto += 1;
            if upto >= end {
                return Err(());
            }
            length -= 241;
            length *= 65536;
            length += 12481 + (b2 * 256) + at(upto)? as i64;
            upto += 1;
            if upto >= end {
                return Err(());
            }
        }
    } else if (STI_UINT16..=STI_UINT256).contains(&ty) || ty == STI_UINT8 || ty == STI_UINT160 || ty == STI_CURRENCY {
        length = match ty {
            STI_UINT16 => 2,
            STI_UINT32 => 4,
            STI_UINT64 => 8,
            STI_UINT128 => 16,
            STI_UINT256 => 32,
            STI_UINT8 => 1,
            STI_UINT160 => 20,
            _ => 20, // STI_CURRENCY
        };
    } else if ty == STI_AMOUNT {
        // :3278-3283 — native iff top two bits are 01
        length = if at(upto)? >> 6 == 1 { 8 } else { 48 };
    } else if ty == STI_PATHSET && ser240 {
        // :3284-3331
        let mut len: usize = 0;
        let mut terminated = false;
        while upto + len < end {
            while at(upto + len)? & 0x31 != 0 {
                let flag = at(upto + len)?;
                len += 1;
                if flag == 0 || flag & !0x31 != 0 {
                    return Err(());
                }
                if flag & 0x01 != 0 {
                    len += 20;
                }
                if flag & 0x10 != 0 {
                    len += 20;
                }
                if flag & 0x20 != 0 {
                    len += 20;
                }
                if rules.fix20260929 && upto + len >= end {
                    return Err(());
                }
                let next = at(upto + len)?;
                if next == 0x00 || next == 0xff {
                    break;
                }
            }
            let last = at(upto + len)?;
            len += 1;
            if last == 0xff {
                continue;
            } else if last == 0x00 {
                terminated = true;
                break;
            } else {
                return Err(());
            }
        }
        if upto >= end {
            return Err(());
        }
        if rules.fix20260929 && !terminated {
            return Err(());
        }
        length = len as i64;
    } else if ty == STI_ISSUE {
        // :3332-3349
        if rules.fix20260929 && end - upto < 20 {
            return Err(());
        }
        let first = d.get(upto..upto + 20).ok_or(())?;
        length = if first.iter().all(|&b| b == 0) { 20 } else { 40 };
    } else if ty == STI_XCHAIN_BRIDGE {
        // :3350-3382
        let fix = rules.fix20260929;
        let mut len: usize = 0;
        for _ in 0..2 {
            if !fix {
                len += 21;
            } else if end - upto <= len {
                return Err(());
            } else if at(upto + len)? == 0 {
                len += 1;
            } else if at(upto + len)? == 20 {
                len += 21;
            } else {
                return Err(());
            }
            if fix && end - upto < len + 20 {
                return Err(());
            }
            let cur = d.get(upto + len..upto + len + 20).ok_or(())?;
            len += if cur.iter().all(|&b| b == 0) { 20 } else { 40 };
        }
        length = len as i64;
    }

    // :3384-3403
    if length > -1 {
        let payload_start = upto - start;
        if rules.fix20260929 && length > (end - upto) as i64 {
            return Err(());
        }
        return Ok(Light { len: length as usize + payload_start, ty, field, payload_start, payload_len: length as usize });
    }

    // :3405-3445 objects / arrays: walk children until the matching end marker
    if ty == STI_OBJECT || ty == STI_ARRAY {
        let payload_start = upto - start;
        for _ in 0..1024 {
            let sub = get_stobject_length(d, upto, end, rules, depth + 1)?;
            upto += sub.len;
            if upto >= end {
                return Err(());
            }
            let m = at(upto)?;
            if (m == 0xE1 && ty == STI_OBJECT) || (m == 0xF1 && ty == STI_ARRAY) {
                let payload_len = upto - start - payload_start;
                upto += 1;
                return Ok(Light { len: upto - start, ty, field, payload_start, payload_len });
            }
        }
        return Err(());
    }
    Err(())
}

/// `HookAPI::sto_validate` (HookAPI.cpp:72-106): Ok(true/false) or Err(rc).
pub fn sto_validate(data: &[u8], rules: &Rules) -> Result<bool, i64> {
    if data.len() < 2 {
        // fix20261005: report invalid (0) rather than TOO_SMALL (:76-81)
        return if rules.fix20261005 { Ok(false) } else { Err(rc::TOO_SMALL) };
    }
    let end = data.len();
    let mut upto = 0usize;
    let mut i = 0;
    while i < 1024 && upto < end {
        match get_stobject_length(data, upto, end, rules, 0) {
            Ok(l) => upto += l.len,
            Err(()) => return Ok(false),
        }
        i += 1;
    }
    Ok(upto == end)
}

/// `HookAPI::sto_subfield` (HookAPI.cpp:108-174) → (offset, length).
/// Non-array fields return the PAYLOAD (header and VL prefix excluded, :151-152); arrays are
/// returned fully formed, header and 0xF1 marker included (:148-149).
pub fn sto_subfield(data: &[u8], field_id: u32, rules: &Rules) -> Result<(u32, u32), i64> {
    if data.len() < 2 {
        return Err(rc::TOO_SMALL);
    }
    if rules.fix20260929 {
        // :113-119 validate the whole buffer first
        match sto_validate(data, rules) {
            Ok(true) => {}
            _ => return Err(rc::PARSE_ERROR),
        }
    }
    let end = data.len();
    let mut upto = 0usize;
    let mut i = 0;
    while i < 1024 && upto < end {
        let l = get_stobject_length(data, upto, end, rules, 0).map_err(|_| rc::PARSE_ERROR)?;
        if ((l.ty as u32) << 16).wrapping_add(l.field as u32) == field_id {
            if l.ty == STI_ARRAY {
                return Ok((upto as u32, l.len as u32));
            }
            return Ok(((upto + l.payload_start) as u32, l.payload_len as u32));
        }
        upto += l.len;
        i += 1;
    }
    if upto != end {
        return Err(rc::PARSE_ERROR);
    }
    Err(rc::DOESNT_EXIST)
}

/// `HookAPI::sto_subarray` (HookAPI.cpp:176-263) → (offset, length) of element `index`,
/// offset relative to the start of `data` (i.e. including any array header the caller passed),
/// length including the element's header and 0xE1 marker.
pub fn sto_subarray(data: &[u8], index: u32, rules: &Rules) -> Result<(u32, u32), i64> {
    if data.len() < 2 {
        return Err(rc::TOO_SMALL);
    }
    let mut upto = 0usize;
    let mut end = data.len();
    if rules.fix20260929 {
        // :187-197 a wrapped array must end in 0xF1, and the buffer must validate
        if (data[upto] & 0xF0) == 0xF0 && data[end - 1] != 0xF1 {
            return Err(rc::PARSE_ERROR);
        }
        match sto_validate(data, rules) {
            Ok(true) => {}
            _ => return Err(rc::PARSE_ERROR),
        }
    }
    // :199-220 unwrap an array header: 1 byte (field <= 15) or, under fixHookAPI20251128,
    // 2 bytes when the first byte is exactly 0xF0 (field > 15)
    if (data[upto] & 0xF0) == 0xF0 {
        if rules.fix_hookapi_20251128 && data[upto] == 0xF0 {
            upto += 2;
            end -= 1;
        } else {
            upto += 1;
            end -= 1;
        }
    }
    if upto >= end {
        return Err(rc::PARSE_ERROR);
    }
    let mut i: u32 = 0;
    while i < 1024 && upto < end {
        let l = get_stobject_length(data, upto, end, rules, 0).map_err(|_| rc::PARSE_ERROR)?;
        if i == index {
            return Ok((upto as u32, l.len as u32));
        }
        upto += l.len;
        i += 1;
    }
    if upto != end {
        return Err(rc::PARSE_ERROR);
    }
    Err(rc::DOESNT_EXIST)
}

// ---------------------------------------------------------------------------------------------
// Full field walker for slot contents.

/// A field inside a serialized object, located in its backing buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldRef {
    pub ty: i32,
    pub field: i32,
    /// offset of the field header
    pub start: usize,
    /// offset just past the header (where `STBase::add()` output begins)
    pub body: usize,
    /// offset just past the field (past the 0xE1/0xF1 marker for objects/arrays)
    pub end: usize,
}

impl FieldRef {
    /// `SField::fieldCode` = (type << 16) | field (SField.h:122-125).
    pub fn code(&self) -> u32 {
        ((self.ty as u32) << 16) | self.field as u32
    }
    /// The bytes `STBase::add()` would produce for this field: VL types keep their length
    /// prefix (STBlob.cpp:62, STAccount.cpp:93, STVector256.cpp:77); objects/arrays drop the
    /// header and end marker (STObject.cpp:864-887, STArray.cpp:175-183).
    pub fn content(&self) -> (usize, usize) {
        if self.ty == STI_OBJECT || self.ty == STI_ARRAY {
            (self.body, self.end - 1)
        } else {
            (self.body, self.end)
        }
    }
}

fn decode_header(d: &[u8], at: usize) -> Result<(i32, i32, usize), String> {
    let g = |i: usize| d.get(i).copied().ok_or_else(|| format!("truncated field header at byte {at}"));
    let b0 = g(at)?;
    let (hi, lo) = ((b0 >> 4) as i32, (b0 & 0xF) as i32);
    Ok(match (hi > 0, lo > 0) {
        (true, true) => (hi, lo, 1),
        (true, false) => (hi, g(at + 1)? as i32, 2),
        (false, true) => (g(at + 1)? as i32, lo, 2),
        (false, false) => (g(at + 1)? as i32, g(at + 2)? as i32, 3),
    })
}

fn vl_len(d: &[u8], at: usize) -> Result<(usize, usize), String> {
    let g = |i: usize| d.get(i).copied().map(|b| b as usize).ok_or_else(|| format!("truncated VL length at byte {at}"));
    let b1 = g(at)?;
    Ok(if b1 <= 192 {
        (b1, 1)
    } else if b1 <= 240 {
        (193 + (b1 - 193) * 256 + g(at + 1)?, 2)
    } else if b1 <= 254 {
        (12481 + (b1 - 241) * 65536 + g(at + 1)? * 256 + g(at + 2)?, 3)
    } else {
        return Err(format!("invalid VL length byte 0xFF at byte {at}"));
    })
}

/// Parse one field at `at`, never reading past `end`.
pub fn parse_field(d: &[u8], at: usize, end: usize) -> Result<FieldRef, String> {
    let (ty, field, hl) = decode_header(d, at)?;
    let body = at + hl;
    let fixed = |n: usize| -> Result<usize, String> { Ok(body + n) };
    let stop = match ty {
        STI_UINT16 => fixed(2)?,
        STI_UINT32 => fixed(4)?,
        STI_UINT64 => fixed(8)?,
        STI_UINT128 => fixed(16)?,
        STI_UINT256 => fixed(32)?,
        STI_UINT8 => fixed(1)?,
        STI_UINT160 | STI_CURRENCY => fixed(20)?,
        STI_UINT96 | STI_NUMBER => fixed(12)?,
        STI_UINT192 => fixed(24)?,
        STI_UINT384 => fixed(48)?,
        STI_UINT512 => fixed(64)?,
        STI_AMOUNT => {
            let b = *d.get(body).ok_or("truncated amount")?;
            if b & 0x80 == 0 { fixed(8)? } else { fixed(48)? }
        }
        STI_VL | STI_ACCOUNT | STI_VECTOR256 => {
            let (n, pl) = vl_len(d, body)?;
            body + pl + n
        }
        STI_ISSUE => {
            let cur = d.get(body..body + 20).ok_or("truncated issue")?;
            if cur.iter().all(|&b| b == 0) { body + 20 } else { body + 40 }
        }
        STI_PATHSET => {
            let mut p = body;
            loop {
                let t = *d.get(p).ok_or("unterminated pathset")?;
                p += 1;
                match t {
                    0x00 => break p,
                    0xFF => continue,
                    f if f & !0x31 == 0 => {
                        p += 20 * ((f & 0x01 != 0) as usize + (f & 0x10 != 0) as usize + (f & 0x20 != 0) as usize)
                    }
                    f => return Err(format!("bad pathset step flag 0x{f:02X}")),
                }
            }
        }
        STI_OBJECT | STI_ARRAY => {
            let marker = if ty == STI_OBJECT { 0xE1 } else { 0xF1 };
            let mut p = body;
            loop {
                if p >= end {
                    return Err(format!("unterminated {} at byte {at}", if ty == STI_OBJECT { "object" } else { "array" }));
                }
                if d[p] == marker {
                    break p + 1;
                }
                p = parse_field(d, p, end)?.end;
            }
        }
        _ => return Err(format!("unsupported serialized type {ty} at byte {at}")),
    };
    if stop > end {
        return Err(format!("field (type {ty}, field {field}) at byte {at} runs past the end"));
    }
    Ok(FieldRef { ty, field, start: at, body, end: stop })
}

/// All top-level fields in `d[start..end]`.
pub fn parse_fields(d: &[u8], start: usize, end: usize) -> Result<Vec<FieldRef>, String> {
    let mut out = vec![];
    let mut p = start;
    while p < end {
        let f = parse_field(d, p, end)?;
        p = f.end;
        out.push(f);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// A Payment: TransactionType, Flags, Sequence, Amount, Fee, SigningPubKey, Account, Destination.
    pub fn payment() -> Vec<u8> {
        let mut v = h("120000"); // [0..3)
        v.extend(h("2280000000")); // [3..8)
        v.extend(h("2400000001")); // [8..13)
        v.extend(h("6140000000000F4240")); // Amount header @13, payload [14..22)
        v.extend(h("68400000000000000A")); // Fee [22..31)
        v.push(0x73); // SigningPubKey header @31
        v.push(0x21); // VL 33
        v.push(0xED);
        v.extend([0x11u8; 32]); // [33..66)
        v.extend(h("8114")); // Account header @66, VL @67
        v.extend([0xAAu8; 20]); // [68..88)
        v.extend(h("8314")); // Destination @88
        v.extend([0xBBu8; 20]); // [90..110)
        v
    }

    #[test]
    fn known_fields() {
        assert!(is_known_field(0)); // sfGeneric
        assert!(is_known_field((6 << 16) + 1)); // sfAmount
        assert!(is_known_field((15 << 16) + 19)); // sfHookParameters
        assert!(!is_known_field((6 << 16) + 200));
        assert!(!is_known_field(u32::MAX)); // -1 = sfInvalid
    }

    #[test]
    fn subfield_payment() {
        let p = payment();
        let r = Rules::default();
        assert_eq!(sto_subfield(&p, (6 << 16) + 1, &r), Ok((14, 8)));
        assert_eq!(sto_subfield(&p, (8 << 16) + 1, &r), Ok((68, 20))); // VL prefix excluded
        assert_eq!(sto_subfield(&p, (8 << 16) + 3, &r), Ok((90, 20)));
        assert_eq!(sto_subfield(&p, (7 << 16) + 3, &r), Ok((33, 33)));
        assert_eq!(sto_subfield(&p, (2 << 16) + 14, &r), Err(rc::DOESNT_EXIST));
        assert_eq!(sto_subfield(&p[..1], 1, &r), Err(rc::TOO_SMALL));
        assert_eq!(sto_subfield(&p[..20], (6 << 16) + 1, &r), Err(rc::PARSE_ERROR));
    }

    #[test]
    fn subfield_and_subarray_hook_parameters() {
        // HookParameters (ARRAY 19 → header F0 13) with two HookParameter objects (OBJECT 23 → E0 17)
        let mut arr = h("F013");
        for (n, v) in [(b"A", 1u8), (b"B", 2u8)] {
            arr.extend(h("E017"));
            arr.extend(h("7018")); // HookParameterName VL 24 → 70 18
            arr.push(1);
            arr.extend(n);
            arr.extend(h("7019")); // HookParameterValue VL 25
            arr.push(1);
            arr.push(v);
            arr.push(0xE1);
        }
        arr.push(0xF1);
        let mut obj = h("120000");
        let off = obj.len() as u32;
        obj.extend(&arr);
        let r = Rules::default();
        // arrays come back fully formed (header + F1 included)
        assert_eq!(sto_subfield(&obj, (15 << 16) + 19, &r), Ok((off, arr.len() as u32)));
        // element 1 of the wrapped array: offsets relative to the passed buffer
        let e0_len = 2 + (2 + 1 + 1) + (2 + 1 + 1) + 1;
        assert_eq!(sto_subarray(&arr, 0, &r), Ok((2, e0_len as u32)));
        assert_eq!(sto_subarray(&arr, 1, &r), Ok((2 + e0_len as u32, e0_len as u32)));
        assert_eq!(sto_subarray(&arr, 2, &r), Err(rc::DOESNT_EXIST));
        // without fixHookAPI20251128 only one header byte is stripped, so the 0x13 field-code
        // byte is mis-read as a UInt16 header (type 1, field 3): element 0 = (1, 3)
        let old = Rules { fix_hookapi_20251128: false, ..r };
        assert_eq!(sto_subarray(&arr, 0, &old), Ok((1, 3)));
    }

    #[test]
    fn full_parser_walks_payment_and_trailing_empty_vl() {
        let p = payment();
        let f = parse_fields(&p, 0, p.len()).unwrap();
        assert_eq!(f.len(), 8);
        assert_eq!(f[6].code(), (8 << 16) + 1);
        assert_eq!(f[6].content(), (67, 88)); // add() keeps the VL prefix
        // a trailing empty VL is legal in a real object (the light walker rejects it)
        let v = h("120000").into_iter().chain(h("7D00")).collect::<Vec<_>>();
        assert_eq!(parse_fields(&v, 0, v.len()).unwrap().len(), 2);
        assert!(sto_validate(&v, &Rules::default()) == Ok(false));
    }
}
