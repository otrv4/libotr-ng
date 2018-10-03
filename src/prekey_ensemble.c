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
  prekey_ensemble_s *pe;

  pe = otrng_xmalloc_z(sizeof(prekey_ensemble_s));
  pe->prekey_profile = otrng_xmalloc_z(sizeof(otrng_prekey_profile_s));
  pe->client_profile = otrng_xmalloc_z(sizeof(client_profile_s));

  return pe;
}

INTERNAL otrng_result
otrng_prekey_ensemble_validate(const prekey_ensemble_s *destination) {
  /* Check that all the instance tags on the Prekey Ensemble's values are the
   * same. */
  char *versions;
  otrng_bool found;
  uint32_t instance = destination->client_profile->sender_instance_tag;
  if (instance != destination->prekey_profile->instance_tag) {
    return OTRNG_ERROR;
  }

  if (instance != destination->message->sender_instance_tag) {
    return OTRNG_ERROR;
  }

  if (!otrng_client_profile_valid(destination->client_profile,
                                  destination->message->sender_instance_tag)) {
    return OTRNG_ERROR;
  }

  if (!otrng_prekey_profile_valid(
          destination->prekey_profile,
          destination->message->sender_instance_tag,
          destination->client_profile->long_term_pub_key)) {
    return OTRNG_ERROR;
  }

  /* Verify the prekey message values */
  /* Verify that the point their_ecdh received is on curve 448. */
  if (!otrng_ec_point_valid(destination->message->Y)) {
    return OTRNG_ERROR;
  }

  /* Verify that the DH public key their_dh is from the correct group. */
  if (!otrng_dh_mpi_valid(destination->message->B)) {
    return OTRNG_ERROR;
  }

  /* Check that the OTR version of the prekey message matches one of the
  versions signed in the Client Profile contained in the Prekey Ensemble. */
  versions = destination->client_profile->versions;
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

INTERNAL otrng_result otrng_prekey_ensemble_deserialize(
    prekey_ensemble_s *destination, const uint8_t *src, size_t src_len,
    size_t *nread) {
  size_t w = 0;
  size_t read = 0;

  if (!otrng_client_profile_deserialize(destination->client_profile, src,
                                        src_len, &w)) {
    return OTRNG_ERROR;
  }

  if (!otrng_prekey_profile_deserialize(destination->prekey_profile, src + w,
                                        src_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  destination->message = otrng_xmalloc_z(sizeof(dake_prekey_message_s));

  if (!otrng_dake_prekey_message_deserialize(destination->message, src + w,
                                             src_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_prekey_ensemble_destroy(prekey_ensemble_s *destination) {
  otrng_client_profile_destroy(destination->client_profile);
  free(destination->client_profile);
  destination->client_profile = NULL;

  otrng_prekey_profile_free(destination->prekey_profile);

  otrng_dake_prekey_message_free(destination->message);
  destination->message = NULL;
}

INTERNAL void otrng_prekey_ensemble_free(prekey_ensemble_s *destination) {
  if (!destination) {
    return;
  }

  otrng_prekey_ensemble_destroy(destination);
  free(destination);
}
