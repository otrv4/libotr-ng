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

#include "../constants.h"
#include "../dake.h"
#include "../keys.h"

void test_dake_identity_message_serializes(identity_message_fixture_t *f,
                                           gconstpointer data) {
  OTRNG_INIT;

  ecdh_keypair_t ecdh[1];
  dh_keypair_t dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {0};
  otrng_ecdh_keypair_generate(ecdh, sym);
  otrng_assert(otrng_dh_keypair_generate(dh) == SUCCESS);

  dake_identity_message_t *identity_message =
      otrng_dake_identity_message_new(f->profile);
  identity_message->sender_instance_tag = 1;
  otrng_ec_point_copy(identity_message->Y, ecdh->pub);
  identity_message->B = otrng_dh_mpi_copy(dh->pub);

  uint8_t *serialized = NULL;
  otrng_assert(otrng_dake_identity_message_asprintf(
                   &serialized, NULL, identity_message) == SUCCESS);

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

  uint8_t *cursor = serialized;
  otrng_assert_cmpmem(cursor, expected, 11); // sizeof(expected));
  cursor += 11;

  size_t user_profile_len = 0;
  uint8_t *user_profile_serialized = NULL;
  otrng_assert(
      otrng_user_profile_asprintf(&user_profile_serialized, &user_profile_len,
                                  identity_message->profile) == SUCCESS);
  otrng_assert_cmpmem(cursor, user_profile_serialized, user_profile_len);
  free(user_profile_serialized);
  cursor += user_profile_len;

  uint8_t serialized_y[ED448_POINT_BYTES + 2] = {0};
  otrng_ec_point_serialize(serialized_y, identity_message->Y);
  otrng_assert_cmpmem(cursor, serialized_y, sizeof(ec_public_key_t));
  cursor += sizeof(ec_public_key_t);

  uint8_t serialized_b[DH3072_MOD_LEN_BYTES] = {0};
  size_t mpi_len = 0;
  otrng_err_t err = otrng_dh_mpi_serialize(serialized_b, DH3072_MOD_LEN_BYTES,
                                           &mpi_len, identity_message->B);
  otrng_assert(!err);
  // Skip first 4 because they are the size (mpi_len)
  otrng_assert_cmpmem(cursor + 4, serialized_b, mpi_len);

  otrng_dh_keypair_destroy(dh);
  otrng_ecdh_keypair_destroy(ecdh);
  otrng_dake_identity_message_free(identity_message);
  free(serialized);

  OTRNG_FREE;
}

void test_otrng_dake_identity_message_deserializes(
    identity_message_fixture_t *f, gconstpointer data) {
  OTRNG_INIT;

  ecdh_keypair_t ecdh[1];
  dh_keypair_t dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_ecdh_keypair_generate(ecdh, sym);
  otrng_assert(otrng_dh_keypair_generate(dh) == SUCCESS);

  dake_identity_message_t *identity_message =
      otrng_dake_identity_message_new(f->profile);

  otrng_ec_point_copy(identity_message->Y, ecdh->pub);
  identity_message->B = otrng_dh_mpi_copy(dh->pub);

  size_t serialized_len = 0;
  uint8_t *serialized = NULL;
  otrng_assert(otrng_dake_identity_message_asprintf(
                   &serialized, &serialized_len, identity_message) == SUCCESS);

  dake_identity_message_t *deserialized =
      malloc(sizeof(dake_identity_message_t));

  otrng_assert(otrng_dake_identity_message_deserialize(
                   deserialized, serialized, serialized_len) == SUCCESS);

  // assert prekey eq
  g_assert_cmpuint(deserialized->sender_instance_tag, ==,
                   identity_message->sender_instance_tag);
  g_assert_cmpuint(deserialized->receiver_instance_tag, ==,
                   identity_message->receiver_instance_tag);
  otrng_assert_user_profile_eq(deserialized->profile,
                               identity_message->profile);
  otrng_assert_ec_public_key_eq(deserialized->Y, identity_message->Y);
  otrng_assert_dh_public_key_eq(deserialized->B, identity_message->B);

  otrng_dh_keypair_destroy(dh);
  otrng_ecdh_keypair_destroy(ecdh);
  otrng_dake_identity_message_free(identity_message);
  otrng_dake_identity_message_free(deserialized);
  free(serialized);

  OTRNG_FREE;
}

void test_dake_identity_message_valid(identity_message_fixture_t *f,
                                      gconstpointer data) {
  OTRNG_INIT;

  ecdh_keypair_t ecdh[1];
  dh_keypair_t dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_ecdh_keypair_generate(ecdh, sym);
  otrng_assert(otrng_dh_keypair_generate(dh) == SUCCESS);

  dake_identity_message_t *identity_message =
      otrng_dake_identity_message_new(f->profile);
  otrng_assert(identity_message != NULL);

  otrng_ec_point_copy(identity_message->Y, ecdh->pub);
  identity_message->B = otrng_dh_mpi_copy(dh->pub);

  otrng_assert(
      otrng_valid_received_values(identity_message->Y, identity_message->B,
                                  identity_message->profile) == otrng_true);

  otrng_ecdh_keypair_destroy(ecdh);
  otrng_dh_keypair_destroy(dh);
  otrng_dake_identity_message_free(identity_message);

  ecdh_keypair_t invalid_ecdh[1];
  dh_keypair_t invalid_dh;

  uint8_t invalid_sym[ED448_PRIVATE_BYTES] = {1};
  otrng_ecdh_keypair_generate(invalid_ecdh, invalid_sym);
  otrng_assert(otrng_dh_keypair_generate(invalid_dh) == SUCCESS);

  user_profile_t *invalid_profile = user_profile_new("2");

  otrng_shared_prekey_pair_t *shared_prekey = otrng_shared_prekey_pair_new();
  otrng_shared_prekey_pair_generate(shared_prekey, invalid_sym);
  otrng_assert(otrng_ec_point_valid(shared_prekey->pub) == SUCCESS);

  otrng_ec_point_copy(invalid_profile->pub_key, invalid_ecdh->pub);
  otrng_ec_point_copy(invalid_profile->shared_prekey, shared_prekey->pub);

  dake_identity_message_t *invalid_identity_message =
      otrng_dake_identity_message_new(invalid_profile);

  otrng_ec_point_copy(invalid_identity_message->Y, invalid_ecdh->pub);
  invalid_identity_message->B = otrng_dh_mpi_copy(invalid_dh->pub);

  otrng_assert(otrng_valid_received_values(
                   invalid_identity_message->Y, invalid_identity_message->B,
                   invalid_identity_message->profile) == otrng_false);

  otrng_user_profile_free(invalid_profile);
  otrng_ecdh_keypair_destroy(invalid_ecdh);
  otrng_dh_keypair_destroy(invalid_dh);
  otrng_shared_prekey_pair_free(shared_prekey);
  otrng_dake_identity_message_free(invalid_identity_message);

  OTRNG_FREE;
}
