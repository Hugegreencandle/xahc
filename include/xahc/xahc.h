/**
 * xahc.h — umbrella include for the xahc safe hook library.
 *
 * Include this, write `hook()` (and optionally `cbak()`), build with `xahc build`.
 *
 *   #include "xahc/xahc.h"
 *   int64_t hook(uint32_t reserved) {
 *       uint8_t acc[20];
 *       XAHC_OTXN_ACCOUNT(acc);
 *       XAHC_ACCEPT("ok");
 *       return 0;
 *   }
 */
#ifndef XAHC_H
#define XAHC_H 1

#include "guard.h"
#include "check.h"
#include "otxn.h"
#include "state.h"
#include "emit/payment.h"

#endif /* XAHC_H */
