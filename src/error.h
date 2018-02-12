#ifndef OTRV4_ERROR_H
#define OTRV4_ERROR_H

#include <stdint.h>

#include "shared.h"

#define ERROR_PREFIX "?OTR Error: "
#define ERROR_CODE_1 "ERROR_1: "
#define ERROR_CODE_2 "ERROR_2: "

// needed for comparing with DECAF_TRUE
typedef uint32_t
    otrv4_bool_t; /* "Boolean" type, will be set to all-zero or all-one */

static const otrv4_bool_t otrv4_true = 0;
static const otrv4_bool_t otrv4_false = 1;

typedef enum {
  SUCCESS = 0,
  ERROR = 1,
  STATE_NOT_ENCRYPTED = 0x1001,
  MSG_NOT_VALID = 0x1011,
} otrv4_err_t;

typedef enum {
  ERR_NONE,
  ERR_MSG_NOT_PRIVATE,
  ERR_MSG_UNDECRYPTABLE,
} otrv4_err_code_t;

/// Return success if x is true
// static otrv4_err_t
// otr4_succeed_if(otr4_bool_t x) {
//    return (otrv4_err_t)x;
//}
//
// Return OTR4_TRUE iff x == SUCCESS
// static otr4_bool_t
// otr4_successful(otrv4_err_t e) {
//    uint64_t w = ((uint32_t)e) ^  ((uint32_t)SUCCESS);
//    return (w-1)>>32;
//}

#endif
