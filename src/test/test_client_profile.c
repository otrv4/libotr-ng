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
  profile->sender_instance_tag = 4;

  otrng_assert(profile != NULL);
  profile->expires = 15;

  otrng_ec_point_copy(profile->long_term_pub_key, keypair->pub);

  uint8_t expected_pubkey[ED448_PUBKEY_BYTES] = {0};
  otrng_serialize_otrng_public_key(expected_pubkey, keypair->pub);

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrng_assert_is_success(
      client_profile_body_asprintf(&serialized, &written, profile));
  g_assert_cmpint(written, ==, 89);

  char expected_header[] = {
      0x00, 0x00, 0x00, 0x04, // Num fields
      0x00, 0x01,             // Instance tag field type
      0x00, 0x00, 0x00, 0x04, // sender instance tag
      0x0,  0x2,              // Pubke field type
  };

  otrng_assert_cmpmem(expected_header, serialized, sizeof(expected_header));

  uint8_t *pos = serialized + sizeof(expected_header);

  otrng_assert_cmpmem(expected_pubkey, pos, ED448_PUBKEY_BYTES);
  pos += ED448_PUBKEY_BYTES;

  char expected[] = {
      0x0,  0x4,                                // Versions field type
      0x0,  0x0, 0x0, 0x2,                      // versions len
      0x34, 0x0,                                // versions data
      0x0,  0x5,                                // Expire field type
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
  profile->transitional_signature = malloc(OTRv3_DSA_SIG_BYTES);
  memset(profile->transitional_signature, 0, OTRv3_DSA_SIG_BYTES);

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrng_assert_is_success(
      client_profile_body_asprintf(&serialized, &written, profile));
  g_assert_cmpint(written, ==, 131);

  char expected_transitional_signature[] = {
      0x0, 0x8, // Transitional signature field type
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // transitional signature
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

  // transitional signature
  otrng_assert_cmpmem(expected_transitional_signature,
                      serialized +
                          (written - sizeof(expected_transitional_signature)),
                      sizeof(expected_transitional_signature));

  free(serialized);
  otrng_client_profile_free(profile);
}

void test_otrng_client_profile_deserializes() {
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  client_profile_s *profile = client_profile_new("4");

  otrng_assert(profile != NULL);

  profile->sender_instance_tag = 4;
  client_profile_sign(profile, keypair);

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrng_client_profile_asprintf(&serialized, &written, profile);

  client_profile_p deserialized;

  otrng_assert_is_success(otrng_client_profile_deserialize(
      deserialized, serialized, written, NULL));
  otrng_assert_client_profile_eq(deserialized, profile);

  free(serialized);
  otrng_client_profile_free(profile);
  otrng_client_profile_destroy(deserialized);
}

void test_client_profile_signs_and_verify() {
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  client_profile_s *profile = client_profile_new("4");

  otrng_assert(profile != NULL);
  client_profile_sign(profile, keypair);

  otrng_assert(otrng_client_profile_verify_signature(profile));

  memset(profile->signature, 0, sizeof(eddsa_signature_p));

  otrng_assert(!otrng_client_profile_verify_signature(profile));

  otrng_client_profile_free(profile);
}

void test_otrng_client_profile_build() {
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  otrng_assert(
      !otrng_client_profile_build(OTRNG_MIN_VALID_INSTAG + 1, "3", NULL));
  otrng_assert(
      !otrng_client_profile_build(OTRNG_MIN_VALID_INSTAG + 1, NULL, keypair));
  otrng_assert(
      !otrng_client_profile_build(OTRNG_MIN_VALID_INSTAG, "3", keypair));

  client_profile_s *profile =
      otrng_client_profile_build(OTRNG_MIN_VALID_INSTAG + 1, "3", keypair);
  g_assert_cmpstr(profile->versions, ==, "3");

  otrng_client_profile_free(profile);
}

void test_otrng_client_profile_transitional_signature(void) {
  otrng_client_state_s *client = otrng_client_state_new(ALICE_IDENTITY);
  client->user_state = otrl_userstate_create();
  client->callbacks = test_callbacks;

  // Generate DSA key
  FILE *tmpFILEp = tmpfile();
  otrng_assert(
      !otrng_client_state_private_key_v3_write_FILEp(client, tmpFILEp));
  fclose(tmpFILEp);

  OtrlPrivKey *dsa_key = otrng_client_state_get_private_key_v3(client);

  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  client_profile_s *profile =
      otrng_client_profile_build(OTRNG_MIN_VALID_INSTAG + 1234, "43", keypair);
  otrng_assert_is_success(
      otrng_client_profile_transitional_sign(profile, dsa_key));
  otrng_assert_is_success(
      otrng_client_profile_verify_transitional_signature(profile));

  otrl_userstate_free(client->user_state);
  otrng_client_profile_free(profile);
  otrng_client_state_free(client);
}
