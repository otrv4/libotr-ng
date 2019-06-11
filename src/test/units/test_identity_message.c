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

static void test_dake_identity_message_serializes(dake_fixture_s *f,
                                                  gconstpointer data) {
  ecdh_keypair_s ecdh;
  dh_keypair_s dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {0};
  (void)data;
  otrng_assert_is_success(otrng_ecdh_keypair_generate(&ecdh, sym));
  otrng_assert_is_success(otrng_dh_keypair_generate(&dh));

  dake_identity_message_s *identity_msg =
      otrng_dake_identity_message_new(f->profile);
  identity_msg->sender_instance_tag = 1;
  otrng_ec_point_copy(identity_msg->Y, ecdh.pub);
  identity_msg->B = otrng_dh_mpi_copy(dh.pub);
  otrng_ec_point_copy(identity_msg->our_ecdh_first, ecdh.pub);
  identity_msg->our_dh_first = otrng_dh_mpi_copy(dh.pub);

  uint8_t *ser = NULL;
  otrng_assert_is_success(
      otrng_dake_identity_message_serialize(&ser, NULL, identity_msg));

  char expected[] = {
      0x0,
      0x04,              // version
      IDENTITY_MSG_TYPE, // message type
      0x0,
      0x0,
      0x0,
      0x1, // sender instance tag
      0x0,
      0x0,
      0x0,
      0x0, // receiver instance tag
  };

  uint8_t *cursor = ser;
  otrng_assert_cmpmem(cursor, expected, 11); // 11 is the sizeof(expected));
  cursor += 11;

  size_t client_profile_len = 0;
  uint8_t *client_profile_ser = NULL;
  otrng_assert_is_success(otrng_client_profile_serialize(
      &client_profile_ser, &client_profile_len, identity_msg->profile));
  otrng_assert_cmpmem(cursor, client_profile_ser, client_profile_len);
  otrng_free(client_profile_ser);
  cursor += client_profile_len;

  uint8_t ser_y[PUB_KEY_SER_BYTES] = {0};
  int ser_y_len = otrng_serialize_ec_point(ser_y, identity_msg->Y);
  otrng_assert_cmpmem(cursor, ser_y, ser_y_len);

  cursor += ser_y_len;

  uint8_t ser_b[DH3072_MOD_LEN_BYTES] = {0};
  size_t ser_b_len = 0;
  otrng_assert(otrng_dh_mpi_serialize(ser_b, DH3072_MOD_LEN_BYTES, &ser_b_len,
                                      identity_msg->B));
  // Skip first 4 because they are the size (mpi_len)
  otrng_assert_cmpmem(cursor + 4, ser_b, ser_b_len);

  // The size plus the 4 bytes of the size
  cursor += ser_b_len + 4;

  uint8_t ser_our_ecdh_first[PUB_KEY_SER_BYTES] = {0};
  int ser_our_ecdh_first_len = otrng_serialize_ec_point(
      ser_our_ecdh_first, identity_msg->our_ecdh_first);
  otrng_assert_cmpmem(cursor, ser_our_ecdh_first, ser_our_ecdh_first_len);

  cursor += ser_our_ecdh_first_len;

  uint8_t ser_our_dh_first[DH3072_MOD_LEN_BYTES] = {0};
  size_t ser_our_dh_first_len = 0;
  otrng_assert(otrng_dh_mpi_serialize(ser_our_dh_first, DH3072_MOD_LEN_BYTES,
                                      &ser_our_dh_first_len,
                                      identity_msg->our_dh_first));
  // Skip first 4 because they are the size (mpi_len)
  otrng_assert_cmpmem(cursor + 4, ser_our_dh_first, ser_our_dh_first_len);

  otrng_dh_keypair_destroy(&dh);
  otrng_ecdh_keypair_destroy(&ecdh);
  otrng_dake_identity_message_free(identity_msg);
  otrng_free(ser);
}

static void test_otrng_dake_identity_message_deserializes(dake_fixture_s *f,
                                                          gconstpointer data) {
  ecdh_keypair_s ecdh;
  dh_keypair_s dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  (void)data;
  otrng_assert_is_success(otrng_ecdh_keypair_generate(&ecdh, sym));
  otrng_assert_is_success(otrng_dh_keypair_generate(&dh));

  dake_identity_message_s *identity_msg =
      otrng_dake_identity_message_new(f->profile);

  otrng_ec_point_copy(identity_msg->Y, ecdh.pub);
  identity_msg->B = otrng_dh_mpi_copy(dh.pub);

  otrng_ec_point_copy(identity_msg->our_ecdh_first, ecdh.pub);
  identity_msg->our_dh_first = otrng_dh_mpi_copy(dh.pub);

  size_t ser_len = 0;
  uint8_t *ser = NULL;
  otrng_assert_is_success(
      otrng_dake_identity_message_serialize(&ser, &ser_len, identity_msg));

  dake_identity_message_s *deser =
      otrng_xmalloc_z(sizeof(dake_identity_message_s));
  deser->profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));

  otrng_assert_is_success(
      otrng_dake_identity_message_deserialize(deser, ser, ser_len));

  // assert prekey eq
  g_assert_cmpuint(deser->sender_instance_tag, ==,
                   identity_msg->sender_instance_tag);
  g_assert_cmpuint(deser->receiver_instance_tag, ==,
                   identity_msg->receiver_instance_tag);
  otrng_assert_client_profile_eq(deser->profile, identity_msg->profile);
  otrng_assert_ec_public_key_eq(deser->Y, identity_msg->Y);
  otrng_assert_dh_public_key_eq(deser->B, identity_msg->B);

  otrng_assert_ec_public_key_eq(deser->our_ecdh_first,
                                identity_msg->our_ecdh_first);
  otrng_assert_dh_public_key_eq(deser->our_dh_first,
                                identity_msg->our_dh_first);

  otrng_dh_keypair_destroy(&dh);
  otrng_ecdh_keypair_destroy(&ecdh);
  otrng_dake_identity_message_free(identity_msg);
  otrng_dake_identity_message_free(deser);
  otrng_free(ser);
}

// TODO: this test does not make any sense
static void test_dake_identity_message_valid(dake_fixture_s *f,
                                             gconstpointer data) {
  ecdh_keypair_s ecdh;
  dh_keypair_s dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  (void)data;
  otrng_assert_is_success(otrng_ecdh_keypair_generate(&ecdh, sym));
  otrng_assert_is_success(otrng_dh_keypair_generate(&dh));

  dake_identity_message_s *identity_msg =
      otrng_dake_identity_message_new(f->profile);
  otrng_assert(identity_msg != NULL);

  otrng_ec_point_copy(identity_msg->Y, ecdh.pub);
  identity_msg->B = otrng_dh_mpi_copy(dh.pub);

  otrng_ec_point_copy(identity_msg->our_ecdh_first, ecdh.pub);
  identity_msg->our_dh_first = otrng_dh_mpi_copy(dh.pub);

  otrng_assert(otrng_dake_valid_received_values(
      identity_msg->sender_instance_tag, identity_msg->Y, identity_msg->B,
      identity_msg->profile));

  otrng_ecdh_keypair_destroy(&ecdh);
  otrng_dh_keypair_destroy(&dh);
  otrng_dake_identity_message_free(identity_msg);

  ecdh_keypair_s invalid_ecdh;
  dh_keypair_s invalid_dh;

  uint8_t invalid_sym[ED448_PRIVATE_BYTES] = {1};
  otrng_assert_is_success(
      otrng_ecdh_keypair_generate(&invalid_ecdh, invalid_sym));
  otrng_assert_is_success(otrng_dh_keypair_generate(&invalid_dh));

  uint8_t zero_buff[ED448_SIGNATURE_BYTES] = {0};
  otrng_client_profile_s *invalid_profile = client_profile_new("2");
  memcpy(invalid_profile->signature, zero_buff, ED448_SIGNATURE_BYTES);

  otrng_shared_prekey_pair_s *shared_prekey = otrng_shared_prekey_pair_new();
  otrng_assert_is_success(
      otrng_shared_prekey_pair_generate(shared_prekey, invalid_sym));
  otrng_assert(otrng_ec_point_valid(shared_prekey->pub));

  otrng_ec_point_copy(invalid_profile->long_term_pub_key, invalid_ecdh.pub);

  dake_identity_message_s *invalid_identity_msg =
      otrng_dake_identity_message_new(invalid_profile);

  otrng_ec_point_copy(invalid_identity_msg->Y, invalid_ecdh.pub);
  invalid_identity_msg->B = otrng_dh_mpi_copy(invalid_dh.pub);

  otrng_assert(!otrng_dake_valid_received_values(
      invalid_identity_msg->sender_instance_tag, invalid_identity_msg->Y,
      invalid_identity_msg->B, invalid_identity_msg->profile));

  otrng_client_profile_free(invalid_profile);
  otrng_ecdh_keypair_destroy(&invalid_ecdh);
  otrng_dh_keypair_destroy(&invalid_dh);
  otrng_shared_prekey_pair_free(shared_prekey);
  otrng_dake_identity_message_free(invalid_identity_msg);
}

void units_identity_message_add_tests(void) {
  WITH_DAKE_FIXTURE("/dake/identity_message/serializes",
                    test_dake_identity_message_serializes);
  WITH_DAKE_FIXTURE("/dake/identity_message/deserializes",
                    test_otrng_dake_identity_message_deserializes);
  WITH_DAKE_FIXTURE("/dake/identity_message/valid",
                    test_dake_identity_message_valid);
}
