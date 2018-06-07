/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OTRNG_ERROR_H
#define OTRNG_ERROR_H

#include <stdint.h>

#include "shared.h"

// TODO: this probably does not have strlen
#define ERROR_PREFIX "?OTR Error: "
#define ERROR_CODE_1 "ERROR_1: "
#define ERROR_CODE_2 "ERROR_2: "
#define ERROR_CODE_3 "ERROR_3: "
#define ERROR_CODE_4 "ERROR_4: "

// needed for comparing with GOLDILOCKS_TRUE
typedef uint32_t
    otrng_bool; /* "Boolean" type, will be set to all-zero or all-one */

static const otrng_bool otrng_true = 1;
static const otrng_bool otrng_false = 0;

typedef enum {
  SUCCESS = 1,
  ERROR = 0,
} otrng_err;

typedef enum {
  ERR_NONE,
  ERR_MSG_NOT_PRIVATE,
  ERR_MSG_UNDECRYPTABLE,
  ERR_MSG_ENCRYPTION_ERROR,
  ERR_MSG_MALFORMED,
} otrng_err_code;

typedef enum {
  NOTIF_NONE = 0,
  NOTIF_STATE_NOT_ENCRYPTED = 0x1001,
  NOTIF_MALFORMED = 0x1002,
  NOTIF_MSG_NOT_VALID = 0x1011,
} otrng_notif;

/// Return success if x is true
// static otrng_err
// otrng_succeed_if(otrng_bool x) {
//    return (otrng_err)x;
//}
//
// Return OTRNG_TRUE iff x == SUCCESS
// static otrng_bool
// otrng_successful(otrng_err e) {
//    uint64_t w = ((uint32_t)e) ^  ((uint32_t)SUCCESS);
//    return (w-1)>>32;
//}

#endif
