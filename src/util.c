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

#define OTRNG_UTIL_PRIVATE

#include <stddef.h>

#include "util.h"

/* This function tests whether the array is empty. It is NOT constant time. */
INTERNAL otrng_bool otrng_is_empty_array(const uint8_t *buf, const size_t buf_len) {
  size_t i;
  for (i = 0; i < buf_len; i++) {
    if (buf[i] != 0) {
      return otrng_false;
    }
  }
  return otrng_true;
}
