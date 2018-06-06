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

#include "../prekey_ensemble.h"

void test_prekey_ensemble_validate(void) {
  uint8_t sym[ED448_PRIVATE_BYTES] = {0xA0};
  otrng_keypair_s *keypair = otrng_keypair_new();
  otrng_keypair_generate(keypair, sym);

  uint8_t sym2[ED448_PRIVATE_BYTES] = {0xA1};
  otrng_keypair_s *keypair2 = otrng_keypair_new();
  otrng_keypair_generate(keypair2, sym2);

  prekey_ensemble_s *ensemble = malloc(sizeof(prekey_ensemble_s));
  otrng_assert(ensemble);

  ensemble->client_profile->id = 1;
  ensemble->client_profile->versions = otrng_strdup("4");
  ensemble->client_profile->sender_instance_tag = 1;
  ensemble->client_profile->expires = time(NULL) + 60 * 60 * 24; // one day
  otrng_mpi_init(ensemble->client_profile->transitional_signature);
  otrng_assert(SUCCESS ==
               client_profile_sign(ensemble->client_profile, keypair));

  ensemble->prekey_profile->id = 1;
  ensemble->prekey_profile->instance_tag = 1;
  ensemble->prekey_profile->expires = time(NULL) + 60 * 60 * 24; // one day
  otrng_ec_point_copy(ensemble->prekey_profile->shared_prekey, keypair->pub);
  otrng_assert(SUCCESS ==
               prekey_profile_sign(ensemble->prekey_profile, keypair));

  ensemble->num_messages = 2;
  ensemble->messages = malloc(2 * sizeof(dake_prekey_message_s *));
  ensemble->messages[0] = otrng_dake_prekey_message_new();
  ensemble->messages[1] = otrng_dake_prekey_message_new();
  ensemble->messages[0]->sender_instance_tag = 1;
  ensemble->messages[1]->sender_instance_tag = 1;
  otrng_ec_point_copy(ensemble->messages[0]->Y, keypair2->pub);
  otrng_ec_point_copy(ensemble->messages[1]->Y, keypair2->pub);
  ensemble->messages[0]->B = gcry_mpi_set_ui(NULL, 3);
  ensemble->messages[1]->B = gcry_mpi_set_ui(NULL, 3);

  otrng_assert(SUCCESS == otrng_prekey_ensemble_validate(ensemble));

  // Should fail if instance tags do not match
  ensemble->client_profile->sender_instance_tag = 2;
  otrng_assert(ERROR == otrng_prekey_ensemble_validate(ensemble));
  ensemble->client_profile->sender_instance_tag = 1;

  ensemble->prekey_profile->instance_tag = 2;
  otrng_assert(ERROR == otrng_prekey_ensemble_validate(ensemble));
  ensemble->prekey_profile->instance_tag = 1;

  ensemble->messages[0]->sender_instance_tag = 2;
  otrng_assert(ERROR == otrng_prekey_ensemble_validate(ensemble));
  ensemble->messages[0]->sender_instance_tag = 1;

  ensemble->messages[1]->sender_instance_tag = 2;
  otrng_assert(ERROR == otrng_prekey_ensemble_validate(ensemble));
  ensemble->messages[1]->sender_instance_tag = 1;

  // Should fail if client profile is not valid
  ensemble->client_profile->id = 2; // Messes up with the signature
  otrng_assert(ERROR == otrng_prekey_ensemble_validate(ensemble));
  ensemble->client_profile->id = 1;

  // Should fail if prekey profile is not valid
  ensemble->prekey_profile->id = 2; // Messes up with the signature
  otrng_assert(ERROR == otrng_prekey_ensemble_validate(ensemble));
  ensemble->prekey_profile->id = 1;

  // Should fail if profiles are signed with a different key
  otrng_assert(SUCCESS ==
               prekey_profile_sign(ensemble->prekey_profile, keypair2));
  otrng_assert(ERROR == otrng_prekey_ensemble_validate(ensemble));
  otrng_assert(SUCCESS ==
               prekey_profile_sign(ensemble->prekey_profile, keypair));

  // Should fail if prekey message is not valid
  otrng_dh_mpi_release(ensemble->messages[0]->B);
  ensemble->messages[0]->B = NULL;
  otrng_assert(ERROR == otrng_prekey_ensemble_validate(ensemble));
  ensemble->messages[0]->B = gcry_mpi_set_ui(NULL, 3);

  // Should fail if the prekey profile does not contain the prekey messages
  // version.
  char *old = ensemble->client_profile->versions;
  ensemble->client_profile->versions = otrng_strdup("3");
  otrng_assert(ERROR == otrng_prekey_ensemble_validate(ensemble));
  free(ensemble->client_profile->versions);
  ensemble->client_profile->versions = old;

  otrng_keypair_free(keypair);
  otrng_keypair_free(keypair2);
  otrng_prekey_ensemble_free(ensemble);
}
