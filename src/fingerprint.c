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

#define OTRNG_FINGERPRINT_PRIVATE

#include "fingerprint.h"
#include "serialize.h"
#include "shake.h"

/* Convert a 56-byte hash value to a 126-byte human-readable value */
API otrng_result otrng_fingerprint_hash_to_human(char *human,
                                                 const unsigned char *hash) {
  int word, byte;
  char *p = human;

  for (word = 0; word < 14; ++word) {
    for (byte = 0; byte < 4; ++byte) {
      if (snprintf(p, OTRNG_FPRINT_HUMAN_LEN, "%02X", hash[word * 4 + byte]) <
          0) {
        return OTRNG_ERROR;
      }
      p += 2;
    }
    *(p++) = ' ';
  }

  /* Change that last ' ' to a '\0' */
  --p;
  *p = '\0';
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_serialize_fingerprint(otrng_fingerprint fp,
                                                  const otrng_public_key pub) {
  uint8_t ser[ED448_POINT_BYTES];
  uint8_t usage_fingerprint = 0x00;
  goldilocks_shake256_ctx_p hd;

  memset(ser, 0, ED448_POINT_BYTES);

  if (fp == NULL) { // TODO: unsure about this check. This is an array
    return OTRNG_ERROR;
  }

  if (otrng_serialize_ec_point(ser, pub) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  /* KDF_1(usage_fingerprint || byte(H), 56) */
  hash_init_with_usage(hd, usage_fingerprint);
  hash_update(hd, ser, ED448_POINT_BYTES);

  hash_final(hd, fp, FPRINT_LEN_BYTES);
  hash_destroy(hd);

  return OTRNG_SUCCESS;
}
