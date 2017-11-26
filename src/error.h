#ifndef ERROR_H
#define ERROR_H

#include <stdint.h>

#define OTR4_ERROR_PREFIX "?OTR Error: "

// needed for comparing with DECAF_TRUE
typedef uint32_t
    otrv4_bool_t; /* "Boolean" type, will be set to all-zero or all-one */

static const otrv4_bool_t otrv4_true = 0;
static const otrv4_bool_t otrv4_false = 1;

typedef enum {
  OTR4_SUCCESS = 0,
  OTR4_ERROR = 1,
  OTR4_STATE_NOT_ENCRYPTED = 0x1001,
} otr4_err_t;

///** Return success if x is true */
// static otr4_err_t
// otr4_succeed_if(otr4_bool_t x) {
//    return (otr4_err_t)x;
//}
//
///** Return OTR4_TRUE iff x == OTR4_SUCCESS */
// static otr4_bool_t
// otr4_successful(otr4_err_t e) {
//    uint64_t w = ((uint32_t)e) ^  ((uint32_t)OTR4_SUCCESS);
//    return (w-1)>>32;
//}

#endif
