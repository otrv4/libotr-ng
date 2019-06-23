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

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "test_helpers.h"

#include "test_fixtures.h"

#include "client_profile.h"
#include "instance_tag.h"
#include "serialize.h"

static void test_client_profile_create() {
  otrng_client_profile_s *profile = client_profile_new("4");
  otrng_assert(profile != NULL);
  otrng_client_profile_free(profile);
}

static void test_client_profile_serializes_body() {
  otrng_keypair_s keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_assert_is_success(otrng_keypair_generate(&keypair, sym));

  otrng_client_profile_s *profile = client_profile_new("4");
  profile->sender_instance_tag = 4;

  otrng_assert(profile != NULL);
  profile->expires = 15;

  otrng_ec_point_copy(profile->long_term_pub_key, keypair.pub);
  const uint8_t forging_sym[ED448_PRIVATE_BYTES] = {3};
  otrng_public_key *forging_key = create_forging_key_from(forging_sym);
  otrng_ec_point_copy(profile->forging_pub_key, *forging_key);
  otrng_free(forging_key);

  uint8_t expected_pubkey[ED448_PUBKEY_BYTES] = {0};
  otrng_serialize_public_key(expected_pubkey, keypair.pub);

  size_t written = 0;
  uint8_t *ser = NULL;
  otrng_assert_is_success(
      client_profile_body_serialize_into(&ser, &written, profile));
  g_assert_cmpint(written, ==, 149);

  char expected_header[] = {
      0x00, 0x00, 0x00, 0x05, /* Num fields */
      0x00, 0x01,             /* Instance tag field type */
      0x00, 0x00, 0x00, 0x04, /* sender instance tag */
      0x0,  0x2,              /* Pubke field type */
  };

  otrng_assert_cmpmem(expected_header, ser, sizeof(expected_header));

  uint8_t *pos = ser + sizeof(expected_header);

  otrng_assert_cmpmem(expected_pubkey, pos, ED448_PUBKEY_BYTES);
  pos += ED448_PUBKEY_BYTES;

  pos += ED448_PUBKEY_BYTES + 2;

  char expected[] = {
      0x0,  0x4,                                /* Versions field type */
      0x0,  0x0, 0x0, 0x1,                      /* Versions len */
      0x34,                                     /* Versions Data */
      0x0,  0x5,                                /* Expire field type */
      0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0F, /* Expires */
  };

  otrng_assert_cmpmem(expected, pos, sizeof(expected));

  otrng_free(ser);
  otrng_client_profile_free(profile);
}

static void test_client_profile_serializes() {
  otrng_keypair_s keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_assert_is_success(otrng_keypair_generate(&keypair, sym));

  otrng_client_profile_s *profile = client_profile_new("4");

  otrng_assert(profile != NULL);
  profile->expires = 15;

  const uint8_t forging_sym[ED448_PRIVATE_BYTES] = {3};
  otrng_public_key *forging_key = create_forging_key_from(forging_sym);
  otrng_ec_point_copy(profile->forging_pub_key, *forging_key);
  otrng_free(forging_key);

  client_profile_sign(profile, &keypair);
  profile->transitional_signature = otrng_xmalloc_z(OTRv3_DSA_SIG_BYTES);

  size_t written = 0;
  uint8_t *ser = NULL;
  otrng_assert_is_success(
      client_profile_body_serialize_into(&ser, &written, profile));
  g_assert_cmpint(written, ==, 191);

  char expected_transitional_signature[] = {
      0x0, 0x7, /* Transitional signature field type */
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, /* Transitional signature */
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

  otrng_assert_cmpmem(expected_transitional_signature,
                      ser + (written - sizeof(expected_transitional_signature)),
                      sizeof(expected_transitional_signature));

  otrng_free(ser);
  otrng_client_profile_free(profile);
}

static void test_otrng_client_profile_deserializes() {
  otrng_keypair_s keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_assert_is_success(otrng_keypair_generate(&keypair, sym));

  otrng_client_profile_s *profile = client_profile_new("4");
  otrng_assert(profile != NULL);

  const uint8_t forging_sym[ED448_PRIVATE_BYTES] = {3};
  otrng_public_key *forging_key = create_forging_key_from(forging_sym);
  otrng_ec_point_copy(profile->forging_pub_key, *forging_key);
  otrng_free(forging_key);

  profile->sender_instance_tag = 4;
  client_profile_sign(profile, &keypair);

  size_t written = 0;
  uint8_t *ser = NULL;
  otrng_assert_is_success(
      otrng_client_profile_serialize(&ser, &written, profile));

  otrng_client_profile_s deser;

  otrng_assert_is_success(
      otrng_client_profile_deserialize(&deser, ser, written, NULL));
  otrng_assert_client_profile_eq(&deser, profile);

  otrng_free(ser);
  otrng_client_profile_free(profile);
  otrng_client_profile_destroy(&deser);
}

static void test_client_profile_signs_and_verify() {
  otrng_keypair_s keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_assert_is_success(otrng_keypair_generate(&keypair, sym));

  otrng_client_profile_s *profile = client_profile_new("4");

  const uint8_t forging_sym[ED448_PRIVATE_BYTES] = {3};
  otrng_public_key *forging_key = create_forging_key_from(forging_sym);
  otrng_ec_point_copy(profile->forging_pub_key, *forging_key);
  otrng_free(forging_key);

  otrng_assert(profile != NULL);
  client_profile_sign(profile, &keypair);

  otrng_assert(client_profile_verify_signature(profile));

  memset(profile->signature, 0, sizeof(eddsa_signature));

  otrng_assert(!client_profile_verify_signature(profile));

  otrng_client_profile_free(profile);
}

static void test_otrng_client_profile_build() {
  otrng_keypair_s keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_assert_is_success(otrng_keypair_generate(&keypair, sym));

  otrng_keypair_s keypair2;
  uint8_t sym2[ED448_PRIVATE_BYTES] = {2};
  otrng_assert_is_success(otrng_keypair_generate(&keypair2, sym2));

  uint64_t expiration = 1000;

  otrng_assert(!otrng_client_profile_build(OTRNG_MIN_VALID_INSTAG + 1, "3",
                                           NULL, NULL, expiration));
  otrng_assert(!otrng_client_profile_build(OTRNG_MIN_VALID_INSTAG + 1, NULL,
                                           &keypair, keypair2.pub, expiration));
  otrng_assert(!otrng_client_profile_build(OTRNG_MIN_VALID_INSTAG - 1, "3",
                                           &keypair, keypair2.pub, expiration));

  otrng_client_profile_s *profile = otrng_client_profile_build(
      OTRNG_MIN_VALID_INSTAG + 1, "3", &keypair, keypair2.pub, expiration);

  otrng_assert(profile);
  g_assert_cmpstr(profile->versions, ==, "3");

  otrng_client_profile_free(profile);
}

static void test_otrng_client_profile_transitional_signature(void) {
  otrng_client_s *client = otrng_client_new(ALICE_IDENTITY);
  client->global_state = otrng_global_state_new(test_callbacks, otrng_false);

  otrng_assert_is_success(otrng_v3_create_private_key(client));

  OtrlPrivKey *dsa_key = otrng_client_get_private_key_v3(client);

  otrng_keypair_s keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_assert_is_success(otrng_keypair_generate(&keypair, sym));

  otrng_keypair_s keypair2;
  uint8_t sym2[ED448_PRIVATE_BYTES] = {2};
  otrng_assert_is_success(otrng_keypair_generate(&keypair2, sym2));

  otrng_client_profile_s *profile = otrng_client_profile_build(
      OTRNG_MIN_VALID_INSTAG + 1234, "43", &keypair, keypair2.pub,
      otrng_client_get_client_profile_exp_time(client));
  otrng_assert_is_success(
      otrng_client_profile_transitional_sign(profile, dsa_key));
  otrng_assert_is_success(
      client_profile_verify_transitional_signature(profile));

  otrng_client_profile_free(profile);
  otrng_global_state_free(client->global_state);
  otrng_client_free(client);
}

void units_client_profile_add_tests(void) {
  g_test_add_func("/client_profile/build_client_profile",
                  test_otrng_client_profile_build);
  g_test_add_func("/client_profile/create", test_client_profile_create);
  g_test_add_func("/client_profile/serialize_body",
                  test_client_profile_serializes_body);
  g_test_add_func("/client_profile/serialize", test_client_profile_serializes);
  g_test_add_func("/client_profile/deserializes",
                  test_otrng_client_profile_deserializes);
  g_test_add_func("/client_profile/sign_and_verifies",
                  test_client_profile_signs_and_verify);
  g_test_add_func("/client_profile/transitional_signature",
                  test_otrng_client_profile_transitional_signature);
}
