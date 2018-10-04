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

#include "test_helpers.h"

#include "test_fixtures.h"

#include "constants.h"
#include "dake.h"
#include "keys.h"
#include "serialize.h"

static void test_prekey_message_serializes() {
  ecdh_keypair_s ecdh;
  dh_keypair_s dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {0};
  otrng_ecdh_keypair_generate(&ecdh, sym);
  otrng_assert_is_success(otrng_dh_keypair_generate(&dh));

  prekey_message_s *prekey_msg = otrng_prekey_message_new();
  prekey_msg->id = 2;
  prekey_msg->sender_instance_tag = 1;
  otrng_ec_point_copy(prekey_msg->Y, ecdh.pub);
  prekey_msg->B = otrng_dh_mpi_copy(dh.pub);

  uint8_t *ser = NULL;
  otrng_assert_is_success(
      otrng_prekey_message_serialize_into(&ser, NULL, prekey_msg));

  uint8_t expected[] = {
      0x0,
      0x04, // version

      PRE_KEY_MSG_TYPE, // message type

      0x0,
      0x0,
      0x0,
      0x2, // id

      0x0,
      0x0,
      0x0,
      0x1, // sender instance tag
  };

  uint8_t *cursor = ser;
  otrng_assert_cmpmem(cursor, expected, sizeof(expected));
  cursor += sizeof(expected);

  uint8_t ser_y[PUB_KEY_SER_BYTES];
  int ser_len = otrng_serialize_ec_point(ser_y, prekey_msg->Y);
  otrng_assert_cmpmem(cursor, ser_y, ser_len);

  cursor += ser_len;

  uint8_t ser_b[DH3072_MOD_LEN_BYTES];
  size_t mpi_len = 0;
  otrng_assert_is_success(otrng_dh_mpi_serialize(ser_b, DH3072_MOD_LEN_BYTES,
                                                 &mpi_len, prekey_msg->B));

  /* Skip first 4 because they are the size (mpi_len) */
  otrng_assert_cmpmem(cursor + 4, ser_b, mpi_len);

  free(ser);
  otrng_dh_keypair_destroy(&dh);
  otrng_ecdh_keypair_destroy(&ecdh);
  otrng_prekey_message_free(prekey_msg);
}

static void test_otrng_prekey_message_deserializes() {
  ecdh_keypair_s ecdh;
  dh_keypair_s dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_ecdh_keypair_generate(&ecdh, sym);
  otrng_assert_is_success(otrng_dh_keypair_generate(&dh));

  prekey_message_s *prekey_msg = otrng_prekey_message_new();
  otrng_ec_point_copy(prekey_msg->Y, ecdh.pub);
  prekey_msg->B = otrng_dh_mpi_copy(dh.pub);
  prekey_msg->id = 2;

  size_t ser_len = 0;
  uint8_t *ser = NULL;
  otrng_assert_is_success(otrng_prekey_message_serialize_into(
      &ser, &ser_len, prekey_msg));

  prekey_message_s *deser = otrng_xmalloc_z(sizeof(prekey_message_s));
  otrng_assert_is_success(otrng_prekey_message_deserialize(
      deser, ser, ser_len, NULL));

  g_assert_cmpuint(deser->sender_instance_tag, ==,
                   prekey_msg->sender_instance_tag);
  otrng_assert_ec_public_key_eq(deser->Y, prekey_msg->Y);
  otrng_assert_dh_public_key_eq(deser->B, prekey_msg->B);

  free(ser);
  otrng_dh_keypair_destroy(&dh);
  otrng_ecdh_keypair_destroy(&ecdh);
  otrng_prekey_message_free(prekey_msg);
  otrng_prekey_message_free(deser);
}

static void test_prekey_message_valid(dake_fixture_s *f, gconstpointer d) {
  ecdh_keypair_s ecdh;
  dh_keypair_s dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  (void)d;
  otrng_ecdh_keypair_generate(&ecdh, sym);
  otrng_assert_is_success(otrng_dh_keypair_generate(&dh));

  prekey_message_s *prekey_msg = otrng_prekey_message_new();
  otrng_assert(prekey_msg != NULL);

  otrng_ec_point_copy(prekey_msg->Y, ecdh.pub);
  prekey_msg->B = otrng_dh_mpi_copy(dh.pub);

  otrng_assert(otrng_valid_received_values(prekey_msg->sender_instance_tag,
                                           prekey_msg->Y, prekey_msg->B,
                                           f->profile) == otrng_true);

  otrng_prekey_message_free(prekey_msg);

  prekey_message_s *invalid_prekey_msg = otrng_prekey_message_new();

  // Invalid point
  otrng_ec_point_destroy(invalid_prekey_msg->Y);
  invalid_prekey_msg->B = otrng_dh_mpi_copy(dh.pub);

  otrng_assert(
      otrng_valid_received_values(invalid_prekey_msg->sender_instance_tag,
                                  invalid_prekey_msg->Y, invalid_prekey_msg->B,
                                  f->profile) == otrng_false);

  otrng_ecdh_keypair_destroy(&ecdh);
  otrng_dh_keypair_destroy(&dh);
  otrng_prekey_message_free(invalid_prekey_msg);
}

static uint8_t mac_tag[HASH_BYTES] = {0xFD};

static void
setup_non_interactive_auth_message(dake_non_interactive_auth_message_s *msg,
                                   const dake_fixture_s *f) {
  ecdh_keypair_s ecdh;
  dh_keypair_s dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {0};
  otrng_ecdh_keypair_generate(&ecdh, sym);
  otrng_assert_is_success(otrng_dh_keypair_generate(&dh));

  msg->sender_instance_tag = 1;
  msg->receiver_instance_tag = 1;
  otrng_client_profile_copy(msg->profile, f->profile);
  otrng_ec_point_copy(msg->X, ecdh.pub);
  msg->A = otrng_dh_mpi_copy(dh.pub);
  memcpy(msg->auth_mac, mac_tag, HASH_BYTES);

  msg->prekey_message_id = 0x0A00000D;

  otrng_dh_keypair_destroy(&dh);
  otrng_ecdh_keypair_destroy(&ecdh);
}

static void
test_dake_non_interactive_auth_message_serializes(dake_fixture_s *f,
                                                  gconstpointer data) {
  dake_non_interactive_auth_message_s msg;
  otrng_dake_non_interactive_auth_message_init(&msg);
  setup_non_interactive_auth_message(&msg, f);

  uint8_t *ser = NULL;
  size_t len = 0;
  (void)data;
  otrng_assert_is_success(
      otrng_dake_non_interactive_auth_message_serialize(&ser, &len, &msg));

  uint8_t expected_header[] = {
      0x00,
      0x04,                  // version
      NON_INT_AUTH_MSG_TYPE, // message type
      0x00,
      0x00,
      0x00,
      0x1, // sender instance tag
      0x00,
      0x00,
      0x00,
      0x1, // receiver instance tag
  };

  uint8_t *cursor = ser;
  otrng_assert_cmpmem(cursor, expected_header, 11); /* size of expected */
  cursor += 11;

  size_t client_profile_len = 0;
  uint8_t *client_profile_ser = NULL;
  otrng_assert_is_success(otrng_client_profile_serialize(
      &client_profile_ser, &client_profile_len, msg.profile));
  otrng_assert_cmpmem(cursor, client_profile_ser, client_profile_len);
  free(client_profile_ser);
  cursor += client_profile_len;

  uint8_t ser_x[PUB_KEY_SER_BYTES];
  size_t ser_len = otrng_serialize_ec_point(ser_x, msg.X);
  otrng_assert_cmpmem(cursor, ser_x, ser_len);
  cursor += ser_len;

  uint8_t ser_a[DH3072_MOD_LEN_BYTES];
  otrng_assert_is_success(
      otrng_dh_mpi_serialize(ser_a, DH3072_MOD_LEN_BYTES, &ser_len, msg.A));

  /* Skip first 4 because they are the size */
  cursor += 4;
  otrng_assert_cmpmem(cursor, ser_a, ser_len);
  cursor += ser_len;

  uint8_t ser_ring_sig[RING_SIG_BYTES];
  otrng_serialize_ring_sig(ser_ring_sig, msg.sigma);

  otrng_assert_cmpmem(cursor, ser_ring_sig, RING_SIG_BYTES);
  cursor += RING_SIG_BYTES;

  // Prekey Message Identifier
  otrng_assert(*(cursor++) == 0x0A);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x0D);

  otrng_assert_cmpmem(cursor, mac_tag, HASH_BYTES);

  free(ser);
  otrng_dake_non_interactive_auth_message_destroy(&msg);
}

static void
test_otrng_dake_non_interactive_auth_message_deserializes(dake_fixture_s *f,
                                                          gconstpointer data) {
  (void)data;
  dake_non_interactive_auth_message_s expected;
  otrng_dake_non_interactive_auth_message_init(&expected);
  setup_non_interactive_auth_message(&expected, f);

  uint8_t *ser = NULL;
  size_t len = 0;
  otrng_assert_is_success(
      otrng_dake_non_interactive_auth_message_serialize(&ser, &len, &expected));

  dake_non_interactive_auth_message_s deser;
  otrng_dake_non_interactive_auth_message_init(&deser);
  otrng_assert_is_success(
      otrng_dake_non_interactive_auth_message_deserialize(&deser, ser, len));
  free(ser);

  g_assert_cmpuint(deser.sender_instance_tag, ==, expected.sender_instance_tag);
  g_assert_cmpuint(deser.receiver_instance_tag, ==,
                   expected.receiver_instance_tag);
  otrng_assert_client_profile_eq(deser.profile, expected.profile);
  otrng_assert_ec_public_key_eq(deser.X, expected.X);
  otrng_assert_dh_public_key_eq(deser.A, expected.A);
  otrng_assert_cmpmem(deser.auth_mac, expected.auth_mac, HASH_BYTES);

  otrng_assert(otrng_ec_scalar_eq(deser.sigma->c1, expected.sigma->c1));
  otrng_assert(otrng_ec_scalar_eq(deser.sigma->r1, expected.sigma->r1));
  otrng_assert(otrng_ec_scalar_eq(deser.sigma->c2, expected.sigma->c2));
  otrng_assert(otrng_ec_scalar_eq(deser.sigma->r2, expected.sigma->r2));
  otrng_assert(otrng_ec_scalar_eq(deser.sigma->c3, expected.sigma->c3));
  otrng_assert(otrng_ec_scalar_eq(deser.sigma->r3, expected.sigma->r3));

  otrng_assert(deser.prekey_message_id == expected.prekey_message_id);

  otrng_dake_non_interactive_auth_message_destroy(&expected);
  otrng_dake_non_interactive_auth_message_destroy(&deser);
}

void units_non_interactive_messages_add_tests(void) {
  WITH_DAKE_FIXTURE("/dake/non_interactive_auth_message/serialize",
                    test_dake_non_interactive_auth_message_serializes);
  WITH_DAKE_FIXTURE("/dake/non_interactive_auth_message/deserialize",
                    test_otrng_dake_non_interactive_auth_message_deserializes);
  WITH_DAKE_FIXTURE("/dake/prekey_message/valid", test_prekey_message_valid);
  g_test_add_func("/dake/prekey_message/deserializes",
                  test_otrng_prekey_message_deserializes);
  g_test_add_func("/dake/prekey_message/serializes",
                  test_prekey_message_serializes);
}
