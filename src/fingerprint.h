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

#ifndef OTRNG_FINGERPRINT_H
#define OTRNG_FINGERPRINT_H

#include <stdint.h>
#include <stdio.h>

#include "keys.h"
#include "shared.h"

#define FPRINT_LEN_BYTES 56
#define OTRNG_FPRINT_HUMAN_LEN 126 // 56 / 4 * 9

typedef uint8_t otrng_fingerprint[FPRINT_LEN_BYTES];
typedef uint8_t otrng_fingerprint_v3[20];

API otrng_result otrng_fingerprint_hash_to_human(char *human,
                                                 const unsigned char *hash);

INTERNAL otrng_result otrng_serialize_fingerprint(otrng_fingerprint fp,
                                                  const otrng_public_key pub);

#ifdef OTRNG_FINGERPRINT_PRIVATE
#endif
#endif
