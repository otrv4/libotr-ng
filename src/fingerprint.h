/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
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
#define FPRINT_V3_LEN_BYTES 20
#define OTRNG_FPRINT_HUMAN_LEN 126 // 56 / 4 * 9

/* the OTRv4 fingerprint of 56 len */
typedef uint8_t otrng_fingerprint[FPRINT_LEN_BYTES];
/* the OTRv3 fingerprint of 20 len */
typedef uint8_t otrng_fingerprint_v3[FPRINT_V3_LEN_BYTES];

/* the OTRv4 fingerprint, its associated username and its trust value */
typedef struct otrng_known_fingerprint_s {
  char *username;
  otrng_fingerprint fp;
  otrng_bool trusted;
} otrng_known_fingerprint_s;

/* the OTRv3 fingerprint, its associated username and its trust value */
typedef struct otrng_known_fingerprint_v3_s {
  char *username;
  Fingerprint *fp;
} otrng_known_fingerprint_v3_s;

/* a list of known fingerprints */
typedef struct otrng_known_fingerprints_s {
  list_element_s *fps;
} otrng_known_fingerprints_s;

/**
 * @brief Create the 126-byte human-readable value of the fingerprint (56-byte
 * hash).
 *
 * @param [human]           The human-readable value.
 * @param [hash]            The 56-byte hash.
 * @param [hash_size]       The size of the hash.
 *
 * @return [otrng_result]   A bool that defines if the operation was successful
 * or not.
 */
API otrng_result otrng_fingerprint_hash_to_human(char *human,
                                                 const unsigned char *hash,
                                                 size_t hash_size);

/**
 * @brief Create the fingerprint as HWC(usage_fingerprint || byte(H) || byte(F),
 * 56).
 *
 * @param [fp]                         The OTRv4 fingerprint of 56 len.
 * @param [long_term_pub_key]          The long-term public key.
 * @param [long_term_forging_pub_key]  The long-term forging key.
 *
 * @return [otrng_result]   A bool that defines if the operation was successful
 * or not.
 */
INTERNAL otrng_result otrng_serialize_fingerprint(
    otrng_fingerprint fp, const otrng_public_key long_term_pub_key,
    const otrng_public_key long_term_forging_pub_key);

/**
 * @brief Free a known fingerprints.
 *
 * @param [kf]     The known fingerprints to be freed.
 *
 */
API void otrng_known_fingerprints_free(otrng_known_fingerprints_s *kf);

// TODO: don't love this
struct otrng_client_s;
struct otrng_s;

/**
 * @brief Get the known fingerprint struct by fingerprint.
 *
 * @param [client]                         The client which has the known
 * fingerprints.
 * @param [fp]                             The fingerprint to search for.
 *
 * @return [otrng_known_fingerprint_s]     The known fingerprint struct if
 * found.
 */
API /*@null@*/ otrng_known_fingerprint_s *
otrng_fingerprint_get_by_fp(const struct otrng_client_s *client,
                            const otrng_fingerprint fp);

/**
 * @brief Get the known fingerprint struct by username.
 *
 * @param [client]                         The client which has the known
 * fingerprints.
 * @param [username]                       The username to search for.
 *
 * @return [otrng_known_fingerprint_s]     The known fingerprint struct if
 * found.
 */
API /*@null@*/ otrng_known_fingerprint_s *
otrng_fingerprint_get_by_username(const struct otrng_client_s *client,
                                  const char *username);

/**
 * @brief Add a fingerprint as a known fingerprint.
 *
 * @param [client]                       The client which will have the known
 * fingerprints.
 * @param [fp]                           The fingerprint to add.
 * @param [peer]                         The peer associated with the
 * fingerprint.
 * @param [trusted]                      The trust level of the fingerprint.
 *
 * @return [otrng_known_fingerprint_s]   The known fingerprint struct.
 */
API otrng_known_fingerprint_s *
otrng_fingerprint_add(struct otrng_client_s *client, const otrng_fingerprint fp,
                      const char *peer, otrng_bool trusted);

/**
 * @brief Execute a function on all fingerprints.
 *
 * @param [client]        The client which has the fingerprints.
 * @param [fn]            The function to execute.
 * @param [context]       The context.
 *
 */
API void otrng_fingerprints_do_all(const struct otrng_client_s *client,
                                   void (*fn)(const struct otrng_client_s *,
                                              otrng_known_fingerprint_s *,
                                              void *),
                                   void *context);

/**
 * @brief Forget a known fingerprint.
 *
 * @param [client]        The client which has the fingerprints.
 * @param [fp]            The fingerprint to forget.
 *
 */
API void otrng_fingerprint_forget(const struct otrng_client_s *client,
                                  otrng_known_fingerprint_s *fp);

/**
 * @brief Get the known fingerprint of the current peer.
 *
 * @param [conn]        The otrng struct.
 *
 */
API /*@null@*/ otrng_known_fingerprint_s *
otrng_fingerprint_get_current_peer(const struct otrng_s *conn);

#ifdef OTRNG_FINGERPRINT_PRIVATE
#endif
#endif
