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

#define ERROR_PREFIX "?OTR Error: "
#define ERROR_CODE_1 "ERROR_1: "
#define ERROR_CODE_2 "ERROR_2: "

// needed for comparing with GOLDILOCKS_TRUE
typedef uint32_t
    otrng_bool_t; /* "Boolean" type, will be set to all-zero or all-one */

static const otrng_bool_t otrng_true = 0;
static const otrng_bool_t otrng_false = 1;

typedef enum {
  SUCCESS = 0,
  ERROR = 1,
  STATE_NOT_ENCRYPTED = 0x1001,
  MSG_NOT_VALID = 0x1011,
} otrng_err_t;

typedef enum {
  ERR_NONE,
  ERR_MSG_NOT_PRIVATE,
  ERR_MSG_UNDECRYPTABLE,
} otrng_err_code_t;

/// Return success if x is true
// static otrng_err_t
// otrng_succeed_if(otrng_bool_t x) {
//    return (otrng_err_t)x;
//}
//
// Return OTRNG_TRUE iff x == SUCCESS
// static otrng_bool_t
// otrng_successful(otrng_err_t e) {
//    uint64_t w = ((uint32_t)e) ^  ((uint32_t)SUCCESS);
//    return (w-1)>>32;
//}

#endif
