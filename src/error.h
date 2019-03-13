/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
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

/**
 * The functions in this file only operate on their arguments, and doesn't touch
 * any global state. They are safe to use concurrently from different threads.
 */

#ifndef OTRNG_ERROR_H
#define OTRNG_ERROR_H

#include <stdint.h>

#include "shared.h"

#define ERROR_PREFIX "?OTR Error: "
#define ERROR_CODE_1 "ERROR_1: "
#define ERROR_CODE_2 "ERROR_2: "
#define ERROR_CODE_3 "ERROR_3: "

// needed for comparing with GOLDILOCKS_TRUE
typedef uint8_t
    otrng_bool; /* "Boolean" type, will be set to all-zero or all-one */

static const otrng_bool otrng_true = 1;
static const otrng_bool otrng_false = 0;

typedef enum {
  OTRNG_SUCCESS = 1,
  OTRNG_ERROR = 0,
} otrng_result;

/*@unused@*/ static inline int otrng_succeeded(otrng_result v) {
  return v == OTRNG_SUCCESS;
}

/*@unused@*/ static inline int otrng_failed(otrng_result v) {
  return v == OTRNG_ERROR;
}

/*@unused@*/ static inline otrng_bool otrng_result_to_bool(otrng_result v) {
  if (v == OTRNG_SUCCESS) {
    return otrng_true;
  }
  return otrng_false;
}

/*@unused@*/ static inline int otrng_bool_is_true(otrng_bool v) {
  if (v == OTRNG_SUCCESS) {
    return 1;
  }
  return 0;
}

/*@unused@*/ static inline otrng_bool c_bool_to_otrng_bool(int v) {
  if (v) {
    return otrng_true;
  }
  return otrng_false;
}

// TODO[OB]: do we really need this too?
typedef enum {
  OTRNG_ERR_MSG_NONE,
  OTRNG_ERR_MSG_UNREADABLE,
  OTRNG_ERR_MSG_NOT_PRIVATE,
  OTRNG_ERR_MSG_MALFORMED,
} otrng_err_code;

#endif
