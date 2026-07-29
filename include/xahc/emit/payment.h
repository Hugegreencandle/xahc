/**
 * xahc/emit/payment.h — typed XAH payment builder with compile-time sizing.
 *
 * The footguns this removes:
 *   - Hand-computed buffer sizes (PREPARE_PAYMENT_SIMPLE_SIZE 248). Declare the
 *     wrong size -> malformed emit or stack smash. Here the size is a named
 *     constant the builder asserts against.
 *   - Manual canonical field ordering in ENCODE_* calls. Here ordering is fixed
 *     inside the builder; you can't misorder it.
 *
 * Two builders:
 *   - XAHC_EMIT_PAYMENT      — native XAH (drops). Serialization codec-verified.
 *   - XAHC_EMIT_PAYMENT_IOU  — issued (trustline) amount. Uses the float_sto host
 *     fn so the 48-byte STAmount (XFL value + currency + issuer) is encoded by
 *     xahaud itself — correct by construction, no hand XFL math.
 */
#ifndef XAHC_EMIT_PAYMENT_H
#define XAHC_EMIT_PAYMENT_H 1

#include <stdint.h>
#include "../check.h"
#include "../sfcodes.h"

extern int64_t hook_account(uint32_t write_ptr, uint32_t write_len);
extern int64_t ledger_seq(void);
extern int64_t etxn_details(uint32_t write_ptr, uint32_t write_len);
extern int64_t etxn_fee_base(uint32_t read_ptr, uint32_t read_len);
extern int64_t etxn_reserve(uint32_t count);
extern int64_t emit(uint32_t write_ptr, uint32_t write_len, uint32_t read_ptr, uint32_t read_len);

/* XFL (issued-amount) host fns. */
extern int64_t float_set(int32_t exponent, int64_t mantissa);
extern int64_t float_sto(uint32_t write_ptr, uint32_t write_len,
                         uint32_t cread_ptr, uint32_t cread_len,
                         uint32_t iread_ptr, uint32_t iread_len,
                         int64_t float1, uint32_t field_code);

/* Worst-case serialized size of a simple XAH payment with emit details.
 *
 * The builder writes 132 bytes before etxn_details (TransactionType 3 + Flags 5 + SourceTag 5 +
 * Sequence 5 + DestinationTag 5 + FirstLedgerSequence 6 + LastLedgerSequence 6 + Amount 9 +
 * Fee 9 + SigningPubKey 35 + Account 22 + Destination 22).
 *
 * xahaud requires (applyHook.cpp, etxn_details):
 *     expected_size = 138; if (!hasCallback) expected_size -= 22;   // 116 without, 138 with
 *
 * 248 gave etxn_details exactly 116 — correct for a hook with NO callback, and 22 SHORT for one
 * that exports `cbak`. The result was silent: TOO_SMALL, then a rollback deep inside
 * xahc_build_payment at the etxn_details line, so EVERY emit from a cbak-exporting hook failed and
 * pointed the developer at the wrong call. Confirmed on testnet 2026-07-29: the same hook emits
 * with cbak removed and rolls back with it present.
 *
 * Now sized for the WORST case (with callback): 132 + 138 = 270. Costs 22 bytes of stack and makes
 * the macro correct for both shapes instead of only one, undocumented, at deploy time. */
#define XAHC_PAYMENT_SIZE 270U

/* Build a simple XAH payment into a caller-provided buffer.
 * `buf` MUST be at least XAHC_PAYMENT_SIZE bytes — checked at compile time when
 * `buf` is a fixed-size array via XAHC_EMIT_PAYMENT().
 *
 * to20      : 20-byte destination account id
 * drops     : amount in drops (uint64)
 * dtag/stag : destination / source tags (0 if unused)
 * returns the serialized length.
 */
/* always_inline is REQUIRED, not a hint. xahaud (Guard.h:495-509) rejects a hook that calls a
 * function it defines itself. At -Oz clang declines to inline a function this size across more
 * than one call site, so `static inline` alone left a real function behind and EVERY hook that
 * emits more than once was temMALFORMED at SetHook. Verified on revenue_split_ok (2 emits) and
 * revenue_split3_ok (3). Single-emit hooks were unaffected, which is why this went unnoticed. */
static inline __attribute__((always_inline)) uint32_t xahc_build_payment(
    uint8_t* buf, const uint8_t* to20, uint64_t drops, uint32_t dtag, uint32_t stag)
{
    uint8_t* p = buf;
    uint8_t acc[20];
    hook_account((uint32_t)acc, 20);
    uint32_t cls = (uint32_t)ledger_seq();

    /* canonical order: TT, Flags, SrcTag, Seq, DstTag, FLS, LLS, Amount, Fee, Pk, Acc, Dst */
    *p++ = 0x12; *p++ = 0x00; *p++ = 0x00;                          /* TransactionType = Payment */
    *p++ = 0x22; *p++ = 0x80; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;/* Flags = tfCanonical */
    *p++ = 0x23; *p++ = (stag>>24); *p++ = (stag>>16); *p++ = (stag>>8); *p++ = stag; /* SourceTag */
    *p++ = 0x24; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;            /* Sequence = 0 (emitted) */
    *p++ = 0x2E; *p++ = (dtag>>24); *p++ = (dtag>>16); *p++ = (dtag>>8); *p++ = dtag; /* DestinationTag */
    *p++ = 0x20; *p++ = 0x1A; *p++ = (cls+1)>>24; *p++ = (cls+1)>>16; *p++ = (cls+1)>>8; *p++ = (cls+1); /* FirstLedgerSequence */
    *p++ = 0x20; *p++ = 0x1B; *p++ = (cls+5)>>24; *p++ = (cls+5)>>16; *p++ = (cls+5)>>8; *p++ = (cls+5); /* LastLedgerSequence */
    /* Amount (native drops): 0x61 + 8 bytes, high bit of byte1 set = positive native */
    *p++ = 0x61;
    *p++ = 0x40 | ((drops>>56)&0x3F);
    *p++ = drops>>48; *p++ = drops>>40; *p++ = drops>>32; *p++ = drops>>24;
    *p++ = drops>>16; *p++ = drops>>8; *p++ = drops;
    uint8_t* fee_ptr = p;                                           /* Fee patched after sizing */
    *p++ = 0x68; *p++ = 0x40; for (int i=0;i<7;++i) *p++ = 0;
    *p++ = 0x73; *p++ = 0x21; for (int i=0;i<33;++i) *p++ = 0;      /* SigningPubKey = null */
    *p++ = 0x81; *p++ = 0x14; for (int i=0;i<20;++i) *p++ = acc[i]; /* Account (source) */
    *p++ = 0x83; *p++ = 0x14; for (int i=0;i<20;++i) *p++ = to20[i];/* Destination */

    int64_t edlen = etxn_details((uint32_t)p, XAHC_PAYMENT_SIZE - (uint32_t)(p - buf));
    if (edlen < 0) rollback(0, 0, (int64_t)__LINE__);   /* host error -> stop, don't corrupt the buffer */
    p += edlen;

    uint32_t len = (uint32_t)(p - buf);
    int64_t fee = etxn_fee_base((uint32_t)buf, len);
    if (fee < 0) rollback(0, 0, (int64_t)__LINE__);
    fee_ptr[1] = 0x40 | ((fee>>56)&0x3F);
    fee_ptr[2] = fee>>48; fee_ptr[3] = fee>>40; fee_ptr[4] = fee>>32; fee_ptr[5] = fee>>24;
    fee_ptr[6] = fee>>16; fee_ptr[7] = fee>>8; fee_ptr[8] = fee;
    return len;
}

/* Convenience: declare a correctly-sized buffer, build, and emit.
 * The _Static_assert guarantees the named-size buffer can't drift. */
#define XAHC_EMIT_PAYMENT(to20, drops, dtag, stag)                          \
    do {                                                                    \
        uint8_t _xahc_tx[XAHC_PAYMENT_SIZE];                                \
        _Static_assert(sizeof(_xahc_tx) >= XAHC_PAYMENT_SIZE, "tx buf too small"); \
        /* CHECK THE RESERVE. Calling it bare swallowed the failure: the builder below calls    \
         * etxn_details, which needs the reservation, so a failed reserve resurfaced later as a \
         * rollback at the etxn_details line — pointing at the wrong call and sending you        \
         * debugging the builder instead of the reservation. Found 2026-07-29 chasing a          \
         * tecHOOK_REJECTED on a minimal emitting hook. */                                       \
        XAHC_TRY(etxn_reserve(1));                                          \
        uint32_t _xahc_len = xahc_build_payment(_xahc_tx, (to20), (drops), (dtag), (stag)); \
        /* emit() REQUIRES a >= 32 byte write buffer for the emitted txn hash:                 \
         * applyHook.cpp `if (write_len < 32) return TOO_SMALL;`. Passing emit(0, 0, ...) made  \
         * EVERY emit through this macro fail with TOO_SMALL, and XAHC_TRY rolled back with a   \
         * line number instead of the errno, so it looked like a builder problem. Confirmed on  \
         * testnet 2026-07-29: identical hook emits with a real buffer, fails with 0,0.         \
         * The hash is genuinely useful too — it identifies the emitted txn for a cbak. */      \
        uint8_t _xahc_emithash[32];                                         \
        XAHC_TRY(emit((uint32_t)_xahc_emithash, 32, (uint32_t)_xahc_tx, _xahc_len)); \
    } while (0)

/* ---- Issued (IOU / trustline) payment -------------------------------------
 * Without a callback (mirrors XAHC_PAYMENT_SIZE). The builder writes 172 bytes before
 * etxn_details (header 35 + issued Amount 49 + Fee 9 + SigningPubKey 35 + Account 22 +
 * Destination 22), and xahaud requires etxn_details write_len >= 116 for a no-callback emit
 * (SetHook_test.cpp:4285 `etxn_details(115)==TOO_SMALL`, :4290 `(116)==116`). So the buffer
 * must be >= 172 + 116 = 288. (Was 287 -> etxn_details got only 115 -> TOO_SMALL -> every IOU
 * emit rolled back on-chain. Off-by-one fixed 2026-07-18, caught by xahc-prover.)
 * 2026-07-29: sized for the WORST case instead. A hook that exports `cbak` needs
 * etxn_details >= 138 (+22B sfEmitCallback), so the buffer must be 172 + 138 = 310. At 288 such a
 * hook got 116 and rolled back silently — the same defect the native path had, and the reason this
 * note existed without being acted on. Enforcing it by SIZE is better than documenting a
 * restriction the compiler cannot check. */
#define XAHC_PAYMENT_IOU_SIZE 310U

/* Build an issued-amount payment. The Amount field is serialized by the
 * float_sto host fn from (xfl, currency20, issuer20) — xahaud does the STAmount
 * encoding, so there is no hand XFL/currency math to get wrong.
 *
 * xfl        : XFL value, e.g. from float_set(exponent, mantissa)
 * currency20 : 20-byte currency code (160-bit)
 * issuer20   : 20-byte issuer account id
 */
static inline __attribute__((always_inline)) uint32_t xahc_build_payment_iou(
    uint8_t* buf, const uint8_t* to20,
    int64_t xfl, const uint8_t* currency20, const uint8_t* issuer20,
    uint32_t dtag, uint32_t stag)
{
    uint8_t* p = buf;
    uint8_t acc[20];
    hook_account((uint32_t)acc, 20);
    uint32_t cls = (uint32_t)ledger_seq();

    *p++ = 0x12; *p++ = 0x00; *p++ = 0x00;                          /* Payment */
    *p++ = 0x22; *p++ = 0x80; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;/* tfCanonical */
    *p++ = 0x23; *p++ = (stag>>24); *p++ = (stag>>16); *p++ = (stag>>8); *p++ = stag;
    *p++ = 0x24; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;            /* Sequence 0 */
    *p++ = 0x2E; *p++ = (dtag>>24); *p++ = (dtag>>16); *p++ = (dtag>>8); *p++ = dtag;
    *p++ = 0x20; *p++ = 0x1A; *p++ = (cls+1)>>24; *p++ = (cls+1)>>16; *p++ = (cls+1)>>8; *p++ = (cls+1);
    *p++ = 0x20; *p++ = 0x1B; *p++ = (cls+5)>>24; *p++ = (cls+5)>>16; *p++ = (cls+5)>>8; *p++ = (cls+5);

    /* Amount (issued, 49 bytes incl. 0x61 prefix) — host-serialized. */
    int64_t alen = float_sto((uint32_t)p, XAHC_PAYMENT_IOU_SIZE - (uint32_t)(p - buf),
                             (uint32_t)currency20, 20, (uint32_t)issuer20, 20,
                             xfl, sfAmount);
    if (alen < 0) rollback(0, 0, (int64_t)__LINE__);   /* bad XFL/currency/issuer -> stop */
    p += alen;

    uint8_t* fee_ptr = p;
    *p++ = 0x68; *p++ = 0x40; for (int i=0;i<7;++i) *p++ = 0;       /* Fee */
    *p++ = 0x73; *p++ = 0x21; for (int i=0;i<33;++i) *p++ = 0;      /* SigningPubKey null */
    *p++ = 0x81; *p++ = 0x14; for (int i=0;i<20;++i) *p++ = acc[i]; /* Account */
    *p++ = 0x83; *p++ = 0x14; for (int i=0;i<20;++i) *p++ = to20[i];/* Destination */

    int64_t edlen = etxn_details((uint32_t)p, XAHC_PAYMENT_IOU_SIZE - (uint32_t)(p - buf));
    if (edlen < 0) rollback(0, 0, (int64_t)__LINE__);
    p += edlen;

    uint32_t len = (uint32_t)(p - buf);
    int64_t fee = etxn_fee_base((uint32_t)buf, len);
    if (fee < 0) rollback(0, 0, (int64_t)__LINE__);
    fee_ptr[1] = 0x40 | ((fee>>56)&0x3F);
    fee_ptr[2] = fee>>48; fee_ptr[3] = fee>>40; fee_ptr[4] = fee>>32; fee_ptr[5] = fee>>24;
    fee_ptr[6] = fee>>16; fee_ptr[7] = fee>>8; fee_ptr[8] = fee;
    return len;
}

#define XAHC_EMIT_PAYMENT_IOU(to20, xfl, currency20, issuer20, dtag, stag)  \
    do {                                                                    \
        uint8_t _xahc_tx[XAHC_PAYMENT_IOU_SIZE];                            \
        _Static_assert(sizeof(_xahc_tx) >= XAHC_PAYMENT_IOU_SIZE, "tx buf too small"); \
        /* CHECK THE RESERVE. Calling it bare swallowed the failure: the builder below calls    \
         * etxn_details, which needs the reservation, so a failed reserve resurfaced later as a \
         * rollback at the etxn_details line — pointing at the wrong call and sending you        \
         * debugging the builder instead of the reservation. Found 2026-07-29 chasing a          \
         * tecHOOK_REJECTED on a minimal emitting hook. */                                       \
        XAHC_TRY(etxn_reserve(1));                                          \
        uint32_t _xahc_len = xahc_build_payment_iou(                        \
            _xahc_tx, (to20), (xfl), (currency20), (issuer20), (dtag), (stag)); \
        /* emit() REQUIRES a >= 32 byte write buffer for the emitted txn hash:                 \
         * applyHook.cpp `if (write_len < 32) return TOO_SMALL;`. Passing emit(0, 0, ...) made  \
         * EVERY emit through this macro fail with TOO_SMALL, and XAHC_TRY rolled back with a   \
         * line number instead of the errno, so it looked like a builder problem. Confirmed on  \
         * testnet 2026-07-29: identical hook emits with a real buffer, fails with 0,0.         \
         * The hash is genuinely useful too — it identifies the emitted txn for a cbak. */      \
        uint8_t _xahc_emithash[32];                                         \
        XAHC_TRY(emit((uint32_t)_xahc_emithash, 32, (uint32_t)_xahc_tx, _xahc_len)); \
    } while (0)

#endif /* XAHC_EMIT_PAYMENT_H */
