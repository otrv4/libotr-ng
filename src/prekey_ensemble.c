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

#include "prekey_ensemble.h"

INTERNAL otrng_err
otrng_prekey_ensemble_validate(const prekey_ensemble_s *dst) {
  // Check that all the instance tags on the Prekey Ensemble's values are the
  // same.
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
                                  dst->message->sender_instance_tag)) {
    return OTRNG_ERROR;
  }

  if (!otrng_ec_point_eq(dst->client_profile->long_term_pub_key,
                         dst->prekey_profile->pub)) {
    return OTRNG_ERROR;
  }

  /* Verify that the point their_ecdh received is on curve 448. */
  if (!otrng_ec_point_valid(dst->message->Y)) {
    return OTRNG_ERROR;
  }

  /* Verify that the DH public key their_dh is from the correct group. */
  if (!otrng_dh_mpi_valid(dst->message->B)) {
    return OTRNG_ERROR;
  }

  // At the moment, prekey_ensemble_s->message can only have VERSION = 4
  // (we don't know how to deserialize prekey messages form another
  // version). We only need to check if the profile has 4 in its "versions"
  // fields to satisfy:
  //"Check that the OTR version of the prekey message matches one of the
  // versions signed in the Client Profile contained in the Prekey Ensemble."
  char *versions = dst->client_profile->versions;
  otrng_bool found = otrng_false;
  while (*versions && !found) {
    found = (*versions == '4');
    versions++;
  }

  if (!found) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_prekey_ensemble_destroy(prekey_ensemble_s *dst) {
  otrng_client_profile_destroy(dst->client_profile);
  otrng_prekey_profile_destroy(dst->prekey_profile);
  otrng_dake_prekey_message_free(dst->message);
  dst->message = NULL;
}

INTERNAL void otrng_prekey_ensemble_free(prekey_ensemble_s *dst) {
  if (!dst) {
    return;
  }

  otrng_prekey_ensemble_destroy(dst);
  free(dst);
}
