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

void test_dake_prekey_message_serializes(prekey_message_fixture_s *f,
                                         gconstpointer data) {

  ecdh_keypair_p ecdh;
  dh_keypair_p dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {0};
  otrng_ecdh_keypair_generate(ecdh, sym);
  otrng_assert(otrng_dh_keypair_generate(dh) == SUCCESS);

  dake_prekey_message_s *prekey_message =
      otrng_dake_prekey_message_new(f->profile);
  prekey_message->sender_instance_tag = 1;
  otrng_ec_point_copy(prekey_message->Y, ecdh->pub);
  prekey_message->B = otrng_dh_mpi_copy(dh->pub);

  uint8_t *serialized = NULL;
  otrng_assert(otrng_dake_prekey_message_asprintf(&serialized, NULL,
                                                  prekey_message) == SUCCESS);

  char expected[] = {
      0x0,
      0x04,             /* version */
      PRE_KEY_MSG_TYPE, /* message type */
      0x0,
      0x0,
      0x0,
      0x1, /* sender instance tag */
      0x0,
      0x0,
      0x0,
      0x0, /* receiver instance tag */
  };

  uint8_t *cursor = serialized;
  otrng_assert_cmpmem(cursor, expected, 11); /* size of expected */
  ;
  cursor += 11;

  size_t user_profile_len = 0;
  uint8_t *user_profile_serialized = NULL;
  otrng_assert(otrng_user_profile_asprintf(&user_profile_serialized,
                                           &user_profile_len,
                                           prekey_message->profile) == SUCCESS);
  otrng_assert_cmpmem(cursor, user_profile_serialized, user_profile_len);
  free(user_profile_serialized);
  user_profile_serialized = NULL;

  cursor += user_profile_len;

  uint8_t serialized_y[PUB_KEY_SER_BYTES] = {};
  int ser_len = otrng_serialize_ec_point(serialized_y, prekey_message->Y);
  otrng_assert_cmpmem(cursor, serialized_y, ser_len);

  cursor += ser_len;

  uint8_t serialized_b[DH3072_MOD_LEN_BYTES] = {};
  size_t mpi_len = 0;
  otrng_err err = otrng_dh_mpi_serialize(serialized_b, DH3072_MOD_LEN_BYTES,
                                           &mpi_len, prekey_message->B);
  otrng_assert(!err);
  /* Skip first 4 because they are the size (mpi_len) */
  otrng_assert_cmpmem(cursor + 4, serialized_b, mpi_len);

  free(serialized);
  serialized = NULL;
  otrng_dh_keypair_destroy(dh);
  otrng_ecdh_keypair_destroy(ecdh);
  otrng_dake_prekey_message_free(prekey_message);
}

void test_otrng_dake_prekey_message_deserializes(prekey_message_fixture_s *f,
                                                 gconstpointer data) {

  ecdh_keypair_p ecdh;
  dh_keypair_p dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_ecdh_keypair_generate(ecdh, sym);
  otrng_assert(otrng_dh_keypair_generate(dh) == SUCCESS);

  dake_prekey_message_s *prekey_message =
      otrng_dake_prekey_message_new(f->profile);
  otrng_ec_point_copy(prekey_message->Y, ecdh->pub);
  prekey_message->B = otrng_dh_mpi_copy(dh->pub);

  size_t serialized_len = 0;
  uint8_t *serialized = NULL;
  otrng_assert(otrng_dake_prekey_message_asprintf(&serialized, &serialized_len,
                                                  prekey_message) == SUCCESS);

  dake_prekey_message_s *deserialized = malloc(sizeof(dake_prekey_message_s));
  otrng_assert(otrng_dake_prekey_message_deserialize(
                   deserialized, serialized, serialized_len) == SUCCESS);

  g_assert_cmpuint(deserialized->sender_instance_tag, ==,
                   prekey_message->sender_instance_tag);
  g_assert_cmpuint(deserialized->receiver_instance_tag, ==,
                   prekey_message->receiver_instance_tag);
  otrng_assert_user_profile_eq(deserialized->profile, prekey_message->profile);
  otrng_assert_ec_public_key_eq(deserialized->Y, prekey_message->Y);
  otrng_assert_dh_public_key_eq(deserialized->B, prekey_message->B);

  free(serialized);
  serialized = NULL;
  otrng_dh_keypair_destroy(dh);
  otrng_ecdh_keypair_destroy(ecdh);
  otrng_dake_prekey_message_free(prekey_message);
  otrng_dake_prekey_message_free(deserialized);
}

void test_dake_prekey_message_valid(prekey_message_fixture_s *f,
                                    gconstpointer data) {

  ecdh_keypair_p ecdh;
  dh_keypair_p dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_ecdh_keypair_generate(ecdh, sym);
  otrng_assert(otrng_dh_keypair_generate(dh) == SUCCESS);

  dake_prekey_message_s *prekey_message =
      otrng_dake_prekey_message_new(f->profile);
  otrng_assert(prekey_message != NULL);

  otrng_ec_point_copy(prekey_message->Y, ecdh->pub);
  prekey_message->B = otrng_dh_mpi_copy(dh->pub);

  otrng_assert(otrng_valid_received_values(prekey_message->Y, prekey_message->B,
                                           prekey_message->profile) ==
               otrng_true);

  otrng_ecdh_keypair_destroy(ecdh);
  otrng_dh_keypair_destroy(dh);
  otrng_dake_prekey_message_free(prekey_message);

  ecdh_keypair_p invalid_ecdh;
  dh_keypair_p invalid_dh;

  uint8_t invalid_sym[ED448_PRIVATE_BYTES] = {1};
  otrng_ecdh_keypair_generate(invalid_ecdh, invalid_sym);
  otrng_assert(otrng_dh_keypair_generate(invalid_dh) == SUCCESS);
  otrng_shared_prekey_pair_s *shared_prekey = otrng_shared_prekey_pair_new();
  otrng_shared_prekey_pair_generate(shared_prekey, invalid_sym);
  otrng_assert(otrng_ec_point_valid(shared_prekey->pub) == SUCCESS);

  user_profile_s *invalid_profile = user_profile_new("2");
  otrng_ec_point_copy(invalid_profile->long_term_pub_key, invalid_ecdh->pub);
  otrng_ec_point_copy(invalid_profile->shared_prekey, shared_prekey->pub);

  dake_prekey_message_s *invalid_prekey_message =
      otrng_dake_prekey_message_new(invalid_profile);

  otrng_ec_point_copy(invalid_prekey_message->Y, invalid_ecdh->pub);
  invalid_prekey_message->B = otrng_dh_mpi_copy(invalid_dh->pub);

  otrng_assert(otrng_valid_received_values(
                   invalid_prekey_message->Y, invalid_prekey_message->B,
                   invalid_prekey_message->profile) == otrng_false);

  otrng_user_profile_free(invalid_profile);
  otrng_ecdh_keypair_destroy(invalid_ecdh);
  otrng_dh_keypair_destroy(invalid_dh);
  otrng_shared_prekey_pair_free(shared_prekey);
  otrng_dake_prekey_message_free(invalid_prekey_message);
}

void test_dake_non_interactive_auth_message_serializes(
    non_interactive_auth_message_fixture_s *f, gconstpointer data) {

  ecdh_keypair_p ecdh;
  dh_keypair_p dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {0};
  otrng_ecdh_keypair_generate(ecdh, sym);
  otrng_assert(otrng_dh_keypair_generate(dh) == SUCCESS);

  dake_non_interactive_auth_message_p msg;

  msg->sender_instance_tag = 1;
  msg->receiver_instance_tag = 1;
  otrng_user_profile_copy(msg->profile, f->profile);
  otrng_ec_point_copy(msg->X, ecdh->pub);
  msg->A = otrng_dh_mpi_copy(dh->pub);
  memset(msg->nonce, 0, sizeof(msg->nonce));
  msg->enc_msg = NULL;
  msg->enc_msg_len = 0;
  memset(msg->auth_mac, 0, sizeof(msg->auth_mac));

  uint8_t secret[1] = {0x01};
  shake_256_hash(msg->auth_mac, HASH_BYTES, secret, 1);

  unsigned char *t = NULL;
  size_t t_len = 0;
  otrng_rsig_authenticate(msg->sigma, f->keypair, f->profile->long_term_pub_key,
                          msg->X, t, t_len);

  uint8_t *serialized = NULL;
  size_t len = 0;

  otrng_assert(otrng_dake_non_interactive_auth_message_asprintf(
                   &serialized, &len, msg) == SUCCESS);

  char expected[] = {
      0x0,
      0x04,                  /* version */
      NON_INT_AUTH_MSG_TYPE, /* message type */
      0x0,
      0x0,
      0x0,
      0x1, /* sender instance tag */
      0x0,
      0x0,
      0x0,
      0x1, /* receiver instance tag */
  };

  uint8_t *cursor = serialized;
  otrng_assert_cmpmem(cursor, expected, 11); /* size of expected */
  cursor += 11;

  size_t user_profile_len = 0;
  uint8_t *user_profile_serialized = NULL;
  otrng_assert(otrng_user_profile_asprintf(&user_profile_serialized,
                                           &user_profile_len,
                                           msg->profile) == SUCCESS);
  otrng_assert_cmpmem(cursor, user_profile_serialized, user_profile_len);
  free(user_profile_serialized);
  user_profile_serialized = NULL;

  cursor += user_profile_len;

  uint8_t serialized_x[PUB_KEY_SER_BYTES] = {};
  int ser_len = otrng_serialize_ec_point(serialized_x, msg->X);
  otrng_assert_cmpmem(cursor, serialized_x, ser_len);

  cursor += ser_len;

  uint8_t serialized_a[DH3072_MOD_LEN_BYTES] = {};
  size_t mpi_len = 0;
  otrng_err err = otrng_dh_mpi_serialize(serialized_a, DH3072_MOD_LEN_BYTES,
                                           &mpi_len, msg->A);
  otrng_assert(!err);

  /* Skip first 4 because they are the size (mpi_len) */
  otrng_assert_cmpmem(cursor + 4, serialized_a, mpi_len);

  cursor += 4 + mpi_len;

  uint8_t serialized_ring_sig[RING_SIG_BYTES] = {};
  otrng_serialize_ring_sig(serialized_ring_sig, msg->sigma);

  otrng_assert_cmpmem(cursor, serialized_ring_sig, RING_SIG_BYTES);

  cursor += RING_SIG_BYTES;

  uint8_t serialized_mac[HASH_BYTES] = {};
  cursor += otrng_serialize_bytes_array(cursor, msg->auth_mac, HASH_BYTES);

  otrng_assert_cmpmem(cursor, serialized_mac, HASH_BYTES);

  free(t);
  t = NULL;
  free(serialized);
  serialized = NULL;

  otrng_dh_keypair_destroy(dh);
  otrng_ecdh_keypair_destroy(ecdh);
  otrng_dake_non_interactive_auth_message_destroy(msg);
}

void test_otrng_dake_non_interactive_auth_message_deserializes(
    prekey_message_fixture_s *f, gconstpointer data) {

  ecdh_keypair_p ecdh;
  dh_keypair_p dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {0};
  otrng_ecdh_keypair_generate(ecdh, sym);
  otrng_assert(otrng_dh_keypair_generate(dh) == SUCCESS);

  dake_non_interactive_auth_message_p msg;

  msg->sender_instance_tag = 1;
  msg->receiver_instance_tag = 1;
  otrng_user_profile_copy(msg->profile, f->profile);
  otrng_ec_point_copy(msg->X, ecdh->pub);
  msg->A = otrng_dh_mpi_copy(dh->pub);
  memset(msg->nonce, 0, sizeof(msg->nonce));
  msg->enc_msg = NULL;
  msg->enc_msg_len = 0;
  memset(msg->auth_mac, 0, sizeof(msg->auth_mac));

  uint8_t secret[1] = {0x01};
  shake_256_hash(msg->auth_mac, HASH_BYTES, secret, 1);

  unsigned char *t = NULL;
  size_t t_len = 0;
  otrng_rsig_authenticate(msg->sigma, f->keypair, f->profile->long_term_pub_key,
                          msg->X, t, t_len);

  uint8_t *serialized = NULL;
  size_t len = 0;
  otrng_assert(otrng_dake_non_interactive_auth_message_asprintf(
                   &serialized, &len, msg) == SUCCESS);

  free(t);
  t = NULL;
  otrng_dh_keypair_destroy(dh);
  otrng_ecdh_keypair_destroy(ecdh);

  dake_non_interactive_auth_message_p deserialized;
  otrng_assert(otrng_dake_non_interactive_auth_message_deserialize(
                   deserialized, serialized, len) == SUCCESS);

  g_assert_cmpuint(deserialized->sender_instance_tag, ==,
                   msg->sender_instance_tag);
  g_assert_cmpuint(deserialized->receiver_instance_tag, ==,
                   msg->receiver_instance_tag);
  otrng_assert_user_profile_eq(deserialized->profile, msg->profile);
  otrng_assert_ec_public_key_eq(deserialized->X, msg->X);
  otrng_assert_dh_public_key_eq(deserialized->A, msg->A);
  otrng_assert(memcmp(deserialized->auth_mac, msg->auth_mac, HASH_BYTES));
  otrng_assert(memcmp(deserialized->sigma, msg->sigma, RING_SIG_BYTES));

  serialized = NULL;
  free(serialized);
  otrng_dake_non_interactive_auth_message_destroy(msg);
  otrng_dake_non_interactive_auth_message_destroy(deserialized);
}
