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

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../serialize.h"
#include "../user_profile.h"

void test_user_profile_create() {
  user_profile_s *profile = user_profile_new("4");
  otrng_assert(profile != NULL);
  otrng_user_profile_free(profile);
}

void test_user_profile_serializes_body() {
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  user_profile_s *profile = user_profile_new("4");

  otrng_shared_prekey_pair_p shared_prekey;
  otrng_shared_prekey_pair_generate(shared_prekey, sym);
  memcpy(profile->shared_prekey, shared_prekey->pub,
         sizeof(otrng_shared_prekey_pub_p));

  otrng_assert(profile != NULL);
  profile->expires = 15;
  otrng_assert(user_profile_sign(profile, keypair) == SUCCESS);

  const uint8_t transitional_signature[40] = {0};
  otrng_mpi_set(profile->transitional_signature, transitional_signature,
                sizeof(transitional_signature));

  uint8_t expected_pubkey[ED448_PUBKEY_BYTES] = {0};
  otrng_serialize_otrng_public_key(expected_pubkey, keypair->pub);

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrng_assert(user_profile_body_asprintf(&serialized, &written, profile) ==
               SUCCESS);
  g_assert_cmpint(132, ==, written);

  otrng_assert_cmpmem(expected_pubkey, serialized, ED448_PUBKEY_BYTES);

  char expected[] = {
      0x0,  0x0, 0x0, 0x2,                      // versions len
      0x34, 0x0,                                // versions data
      0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0F, // expires
  };

  otrng_assert_cmpmem(expected, serialized + ED448_PUBKEY_BYTES,
                      sizeof(expected));

  uint8_t expected_shared_prekey[ED448_SHARED_PREKEY_BYTES] = {0};
  otrng_serialize_otrng_shared_prekey(expected_shared_prekey,
                                      profile->shared_prekey);

  otrng_assert_cmpmem(expected_shared_prekey,
                      serialized + ED448_PUBKEY_BYTES + 14,
                      ED448_SHARED_PREKEY_BYTES);

  free(serialized);
  serialized = NULL;
  otrng_user_profile_free(profile);
}

void test_user_profile_serializes() {
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  user_profile_s *profile = user_profile_new("4");

  otrng_shared_prekey_pair_p shared_prekey;
  otrng_shared_prekey_pair_generate(shared_prekey, sym);
  memcpy(profile->shared_prekey, shared_prekey->pub,
         sizeof(otrng_shared_prekey_pair_s));

  otrng_assert(profile != NULL);
  profile->expires = 15;

  user_profile_sign(profile, keypair);
  const uint8_t transitional_signature[40] = {0};
  otrng_mpi_set(profile->transitional_signature, transitional_signature,
                sizeof(transitional_signature));

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrng_assert(otrng_user_profile_asprintf(&serialized, &written, profile) ==
               SUCCESS);
  g_assert_cmpint(written, ==, 290);

  // check "body"
  size_t body_len = 0;
  uint8_t *body = NULL;
  otrng_assert(user_profile_body_asprintf(&body, &body_len, profile) ==
               SUCCESS);
  otrng_assert_cmpmem(body, serialized, body_len);

  char expected_transitional_signature[] = {
      0x0, 0x0, 0x0, 0x28,                     // len
      0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, // transitional signature
      0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

  // transitional signature
  otrng_assert_cmpmem(expected_transitional_signature,
                      serialized + body_len + sizeof(eddsa_signature_p),
                      sizeof(expected_transitional_signature));

  free(body);
  body = NULL;
  free(serialized);
  serialized = NULL;
  otrng_user_profile_free(profile);
}

void test_otrng_user_profile_deserializes() {
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  user_profile_s *profile = user_profile_new("4");

  otrng_shared_prekey_pair_p shared_prekey;
  otrng_shared_prekey_pair_generate(shared_prekey, sym);
  memcpy(profile->shared_prekey, shared_prekey->pub,
         sizeof(otrng_shared_prekey_pub_p));

  otrng_assert(profile != NULL);
  user_profile_sign(profile, keypair);

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrng_user_profile_asprintf(&serialized, &written, profile);

  user_profile_s *deserialized = malloc(sizeof(user_profile_s));
  otrng_assert(otrng_user_profile_deserialize(deserialized, serialized, written,
                                              NULL) == SUCCESS);
  otrng_assert_user_profile_eq(deserialized, profile);

  free(serialized);
  serialized = NULL;
  otrng_user_profile_free(profile);
  otrng_user_profile_free(deserialized);
}

void test_user_profile_signs_and_verify() {
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  user_profile_s *profile = user_profile_new("4");

  otrng_shared_prekey_pair_p shared_prekey;
  otrng_shared_prekey_pair_generate(shared_prekey, sym);
  memcpy(profile->shared_prekey, shared_prekey->pub,
         sizeof(otrng_shared_prekey_pair_s));

  otrng_assert(profile != NULL);
  user_profile_sign(profile, keypair);

  otrng_assert(otrng_user_profile_verify_signature(profile) == otrng_true);

  memset(profile->signature, 0, sizeof(profile->signature));

  otrng_assert(otrng_user_profile_verify_signature(profile) == otrng_false);

  otrng_user_profile_free(profile);
}

void test_otrng_user_profile_build() {
  user_profile_s *profile = otrng_user_profile_build(NULL, NULL, NULL);
  otrng_assert(!profile);

  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  otrng_shared_prekey_pair_p shared_prekey;
  otrng_shared_prekey_pair_generate(shared_prekey, sym);

  profile = otrng_user_profile_build("3", keypair, shared_prekey);
  g_assert_cmpstr(profile->versions, ==, "3");
  otrng_assert(otrng_ec_point_valid(profile->shared_prekey) == otrng_true);

  otrng_user_profile_free(profile);
}
