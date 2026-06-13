/**
 * xahc/otxn.h — typed originating-transaction field access.
 *
 * Thin, checked wrappers over otxn_field. Field codes come from sfcodes.h
 * (authoritative, generated from Xahau). Stop juggling raw sfcodes + unchecked
 * lengths.
 */
#ifndef XAHC_OTXN_H
#define XAHC_OTXN_H 1

#include <stdint.h>
#include "check.h"
#include "sfcodes.h"

extern int64_t otxn_field(uint32_t write_ptr, uint32_t write_len, uint32_t field_id);
extern int64_t otxn_type(void);
extern int64_t otxn_id(uint32_t write_ptr, uint32_t write_len, uint32_t flags);

/* Transaction types (subset — extend as needed). */
#define XAHC_ttPAYMENT       0
#define XAHC_ttESCROW_CREATE 1
#define XAHC_ttESCROW_FINISH 2
#define XAHC_ttTRUST_SET     20
#define XAHC_ttURITOKEN_MINT 45
#define XAHC_ttINVOKE        99

/* Read the originating (source) account, 20 bytes, into `acc20`, or rollback. */
#define XAHC_OTXN_ACCOUNT(acc20) \
    XAHC_REQUIRE(otxn_field(XAHC_SBUF(acc20), sfAccount) == 20, "otxn account read")

/* Read the destination account, 20 bytes, into `acc20`, or rollback. */
#define XAHC_OTXN_DESTINATION(acc20) \
    XAHC_REQUIRE(otxn_field(XAHC_SBUF(acc20), sfDestination) == 20, "otxn dest read")

/* Read the originating transaction's native XAH Amount as drops.
 * Returns drops (>= 0), or:
 *   -1  field missing / not 8 bytes
 *   -2  issued (non-native) amount — use the XFL/slot path instead
 * Encapsulates the 8-byte STAmount native decode that every payment-policing
 * hook would otherwise hand-roll. */
static inline int64_t xahc_otxn_drops(void)
{
    uint8_t amt[8];
    if (otxn_field((uint32_t)amt, 8, sfAmount) != 8) return -1;
    if (amt[0] & 0x80) return -2;   /* 0x80 = "not XRP" bit set => issued */
    uint64_t d = ((uint64_t)(amt[0] & 0x3F) << 56) |
                 ((uint64_t)amt[1] << 48) | ((uint64_t)amt[2] << 40) |
                 ((uint64_t)amt[3] << 32) | ((uint64_t)amt[4] << 24) |
                 ((uint64_t)amt[5] << 16) | ((uint64_t)amt[6] << 8) |
                 ((uint64_t)amt[7]);
    return (int64_t)d;
}

#endif /* XAHC_OTXN_H */
