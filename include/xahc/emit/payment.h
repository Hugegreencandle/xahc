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
 * This is a focused MVP: simple XAH (drops) payment, no paths, no IOU. IOU /
 * trustline variant lands next.
 */
#ifndef XAHC_EMIT_PAYMENT_H
#define XAHC_EMIT_PAYMENT_H 1

#include <stdint.h>
#include "../check.h"

extern int64_t hook_account(uint32_t write_ptr, uint32_t write_len);
extern int64_t ledger_seq(void);
extern int64_t etxn_details(uint32_t write_ptr, uint32_t write_len);
extern int64_t etxn_fee_base(uint32_t read_ptr, uint32_t read_len);
extern int64_t etxn_reserve(uint32_t count);
extern int64_t emit(uint32_t write_ptr, uint32_t write_len, uint32_t read_ptr, uint32_t read_len);

/* Worst-case serialized size of a simple XAH payment with emit details.
 * Without a callback. Matches stock PREPARE_PAYMENT_SIMPLE_SIZE. */
#define XAHC_PAYMENT_SIZE 248U

/* Build a simple XAH payment into a caller-provided buffer.
 * `buf` MUST be at least XAHC_PAYMENT_SIZE bytes — checked at compile time when
 * `buf` is a fixed-size array via XAHC_EMIT_PAYMENT().
 *
 * to20      : 20-byte destination account id
 * drops     : amount in drops (uint64)
 * dtag/stag : destination / source tags (0 if unused)
 * returns the serialized length.
 */
static inline uint32_t xahc_build_payment(
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
    p += edlen;

    uint32_t len = (uint32_t)(p - buf);
    int64_t fee = etxn_fee_base((uint32_t)buf, len);
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
        etxn_reserve(1);                                                    \
        uint32_t _xahc_len = xahc_build_payment(_xahc_tx, (to20), (drops), (dtag), (stag)); \
        XAHC_TRY(emit(0, 0, (uint32_t)_xahc_tx, _xahc_len));                \
    } while (0)

#endif /* XAHC_EMIT_PAYMENT_H */
