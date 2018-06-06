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

#include "../client_profile.h"
#include "../serialize.h"

void test_client_profile_create() {
  client_profile_s *profile = client_profile_new("4");
  otrng_assert(profile != NULL);
  otrng_client_profile_free(profile);
}

void test_client_profile_serializes_body() {
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  client_profile_s *profile = client_profile_new("4");
  profile->id = 3;
  profile->sender_instance_tag = 4;

  otrng_assert(profile != NULL);
  profile->expires = 15;

  otrng_ec_point_copy(profile->long_term_pub_key, keypair->pub);

  uint8_t expected_pubkey[ED448_PUBKEY_BYTES] = {0};
  otrng_serialize_otrng_public_key(expected_pubkey, keypair->pub);

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrng_assert(client_profile_body_asprintf(&serialized, &written, profile) ==
               SUCCESS);
  g_assert_cmpint(written, ==, 81);

  char expected_header[] = {
      0x0, 0x0, 0x0, 0x3, // ID
      0x0, 0x0, 0x0, 0x4, // sender instance tag
  };

  otrng_assert_cmpmem(expected_header, serialized, sizeof(expected_header));

  uint8_t *pos = serialized + sizeof(expected_header);

  otrng_assert_cmpmem(expected_pubkey, pos, ED448_PUBKEY_BYTES);
  pos += ED448_PUBKEY_BYTES;

  char expected[] = {
      0x0,  0x0, 0x0, 0x2,                      // versions len
      0x34, 0x0,                                // versions data
      0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0F, // expires
  };

  otrng_assert_cmpmem(expected, pos, sizeof(expected));

  free(serialized);
  otrng_client_profile_free(profile);
}

void test_client_profile_serializes() {
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  client_profile_s *profile = client_profile_new("4");

  otrng_assert(profile != NULL);
  profile->expires = 15;

  client_profile_sign(profile, keypair);
  const uint8_t transitional_signature[40] = {0};
  otrng_mpi_set(profile->transitional_signature, transitional_signature,
                sizeof(transitional_signature));

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrng_assert(otrng_client_profile_asprintf(&serialized, &written, profile) ==
               SUCCESS);
  g_assert_cmpint(written, ==, 239);

  // check "body"
  size_t body_len = 0;
  uint8_t *body = NULL;
  otrng_assert(client_profile_body_asprintf(&body, &body_len, profile) ==
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
  free(serialized);
  otrng_client_profile_free(profile);
}

void test_otrng_client_profile_deserializes() {
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  client_profile_s *profile = client_profile_new("4");

  otrng_assert(profile != NULL);

  profile->id = 3;
  profile->sender_instance_tag = 4;
  client_profile_sign(profile, keypair);

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrng_client_profile_asprintf(&serialized, &written, profile);

  client_profile_s *deserialized = malloc(sizeof(client_profile_s));
  otrng_assert(otrng_client_profile_deserialize(deserialized, serialized,
                                                written, NULL) == SUCCESS);
  otrng_assert_client_profile_eq(deserialized, profile);

  free(serialized);
  serialized = NULL;
  otrng_client_profile_free(profile);
  otrng_client_profile_free(deserialized);
}

void test_client_profile_signs_and_verify() {
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  client_profile_s *profile = client_profile_new("4");

  otrng_assert(profile != NULL);
  client_profile_sign(profile, keypair);

  otrng_assert(otrng_client_profile_verify_signature(profile));

  memset(profile->signature, 0, sizeof(profile->signature));

  otrng_assert(!otrng_client_profile_verify_signature(profile));

  otrng_client_profile_free(profile);
}

void test_otrng_client_profile_build() {
  client_profile_s *profile = otrng_client_profile_build(0, 0, NULL, NULL);
  otrng_assert(!profile);

  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  profile = otrng_client_profile_build(1, 0, "3", keypair);
  g_assert_cmpint(profile->id, ==, 1);
  g_assert_cmpstr(profile->versions, ==, "3");

  otrng_client_profile_free(profile);
}
