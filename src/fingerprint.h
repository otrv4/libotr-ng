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
 * any global state. It is safe to call these functions concurrently from
 * different threads, as long as arguments pointing to the same memory areas are
 * not used from different threads.
 */

#ifndef OTRNG_FINGERPRINT_H
#define OTRNG_FINGERPRINT_H

#include <stdint.h>
#include <stdio.h>

#include "keys.h"
#include "list.h"
#include "shared.h"

#ifndef S_SPLINT_S
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <libotr/context.h>
#pragma clang diagnostic pop
#endif

#define FPRINT_LEN_BYTES 56
#define OTRNG_FPRINT_HUMAN_LEN 126 // 56 / 4 * 9

typedef uint8_t otrng_fingerprint[FPRINT_LEN_BYTES];
typedef uint8_t otrng_fingerprint_v3[20];

typedef struct otrng_known_fingerprint_s {
  char *username;
  otrng_fingerprint fp;
  otrng_bool trusted;
} otrng_known_fingerprint_s;

typedef struct otrng_known_fingerprint_v3_s {
  char *username;
  Fingerprint *fp;
} otrng_known_fingerprint_v3_s;

typedef struct otrng_known_fingerprints_s {
  list_element_s *fps;
} otrng_known_fingerprints_s;

API void otrng_known_fingerprints_free(otrng_known_fingerprints_s *kf);

API otrng_result otrng_fingerprint_hash_to_human(char *human,
                                                 const unsigned char *hash,
                                                 size_t hash_size);

INTERNAL otrng_result otrng_serialize_fingerprint(
    otrng_fingerprint fp, const otrng_public_key long_term_pub_key,
    const otrng_public_key long_term_forging_pub_key);

struct otrng_client_s;
struct otrng_s;

API /*@null@*/ otrng_known_fingerprint_s *
otrng_fingerprint_get_by_fp(const struct otrng_client_s *client,
                            const otrng_fingerprint fp);

API /*@null@*/ otrng_known_fingerprint_s *
otrng_fingerprint_get_by_username(const struct otrng_client_s *client,
                                  const char *username);

API otrng_known_fingerprint_s *
otrng_fingerprint_add(struct otrng_client_s *client, const otrng_fingerprint fp,
                      const char *peer, otrng_bool trusted);

API void otrng_fingerprints_do_all(const struct otrng_client_s *client,
                                   void (*fn)(const struct otrng_client_s *,
                                              otrng_known_fingerprint_s *,
                                              void *),
                                   void *context);

API void otrng_fingerprint_forget(const struct otrng_client_s *client,
                                  otrng_known_fingerprint_s *);

API /*@null@*/ otrng_known_fingerprint_s *
otrng_fingerprint_get_current(const struct otrng_s *conn);

#ifdef OTRNG_FINGERPRINT_PRIVATE
#endif
#endif
