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

#include "prekey_ensemble.h"
#include "alloc.h"

INTERNAL prekey_ensemble_s *otrng_prekey_ensemble_new() {
  prekey_ensemble_s *ensemble;

  ensemble = otrng_xmalloc_z(sizeof(prekey_ensemble_s));
  ensemble->prekey_profile = otrng_xmalloc_z(sizeof(otrng_prekey_profile_s));
  ensemble->client_profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));

  return ensemble;
}

INTERNAL otrng_result
otrng_prekey_ensemble_validate(const prekey_ensemble_s *dst) {
  /* Check that all the instance tags on the Prekey Ensemble's values are the
   * same. */
  char *versions;
  otrng_bool found;
  uint32_t instance = dst->client_profile->sender_instance_tag;
  if (instance != dst->prekey_profile->instance_tag) {
    return OTRNG_ERROR;
  }

  if (instance != dst->message->sender_instance_tag) {
    return OTRNG_ERROR;
  }

  if (!otrng_client_profile_valid(dst->client_profile,
                                  dst->message->sender_instance_tag)) {
    return OTRNG_ERROR;
  }

  if (!otrng_prekey_profile_valid(dst->prekey_profile,
                                  dst->message->sender_instance_tag,
                                  dst->client_profile->long_term_pub_key)) {
    return OTRNG_ERROR;
  }

  /* Verify the prekey message values */
  /* Verify that the point their_ecdh received is on curve 448. */
  if (!otrng_ec_point_valid(dst->message->Y)) {
    return OTRNG_ERROR;
  }

  /* Verify that the DH public key their_dh is from the correct group. */
  if (!otrng_dh_mpi_valid(dst->message->B)) {
    return OTRNG_ERROR;
  }

  /* Check that the OTR version of the prekey message matches one of the
  versions signed in the Client Profile contained in the Prekey Ensemble. */
  versions = dst->client_profile->versions;
  found = otrng_false;
  while (*versions && !found) {
    found = (*versions == '4');
    versions++;
  }

  if (!found) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_prekey_ensemble_deserialize(prekey_ensemble_s *dst,
                                                        const uint8_t *src,
                                                        size_t src_len,
                                                        size_t *nread) {
  size_t w = 0;
  size_t read = 0;

  if (!otrng_client_profile_deserialize(dst->client_profile, src, src_len,
                                        &w)) {
    return OTRNG_ERROR;
  }

  if (!otrng_prekey_profile_deserialize(dst->prekey_profile, src + w,
                                        src_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  dst->message = otrng_xmalloc_z(sizeof(prekey_message_s));

  if (!otrng_prekey_message_deserialize(dst->message, src + w, src_len - w,
                                        &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_prekey_ensemble_destroy(prekey_ensemble_s *dst) {
  otrng_client_profile_destroy(dst->client_profile);
  free(dst->client_profile);
  dst->client_profile = NULL;

  otrng_prekey_profile_free(dst->prekey_profile);

  otrng_prekey_message_free(dst->message);
  dst->message = NULL;
}

INTERNAL void otrng_prekey_ensemble_free(prekey_ensemble_s *dst) {
  if (!dst) {
    return;
  }

  otrng_prekey_ensemble_destroy(dst);
  free(dst);
}
