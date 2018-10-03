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

#include "data_message.h"
#include "serialize.h"

static data_message_s *set_up_data_message() {
  ecdh_keypair_s ecdh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_ecdh_keypair_generate(&ecdh, sym);

  data_message_s *data_message = otrng_data_message_new();
  otrng_assert(data_message);
  data_message->sender_instance_tag = 1;
  data_message->receiver_instance_tag = 2;
  data_message->flags = 0xA;
  data_message->previous_chain_n = 98;
  data_message->ratchet_id = 1;
  data_message->message_id = 99;
  otrng_ec_point_copy(data_message->ecdh, ecdh.pub);

  uint8_t dh_data[383] = {
      0x4c, 0x4e, 0x7b, 0xbd, 0x33, 0xd0, 0x9e, 0x63, 0xfd, 0xe4, 0x67, 0xee,
      0x6c, 0x65, 0x47, 0xc4, 0xe2, 0x1f, 0xaa, 0xb1, 0x90, 0x56, 0x8a, 0x7d,
      0x16, 0x7c, 0x3a, 0xc,  0xb5, 0xcf, 0xdf, 0xbc, 0x5,  0x44, 0xf0, 0x89,
      0x2d, 0xa4, 0x94, 0x97, 0x40, 0x13, 0x83, 0x2d, 0x74, 0x62, 0xfb, 0xee,
      0xec, 0x31, 0xac, 0xc2, 0x60, 0x5b, 0x45, 0x9b, 0xef, 0x10, 0x3d, 0xfb,
      0x49, 0xe6, 0xf,  0x8e, 0xfb, 0xba, 0x74, 0x53, 0xfe, 0x13, 0x3a, 0x45,
      0x63, 0xe8, 0x68, 0xa1, 0xd1, 0x1,  0x5c, 0x9,  0x48, 0x78, 0xf2, 0x48,
      0x77, 0x27, 0xde, 0xeb, 0x7,  0xfc, 0xe5, 0xe8, 0xe4, 0x7f, 0x4c, 0x9e,
      0x74, 0x4d, 0xe5, 0xcd, 0x93, 0xdc, 0x54, 0x15, 0xd7, 0xba, 0x13, 0xbf,
      0xa4, 0xfc, 0x7d, 0x7c, 0x2a, 0xcf, 0xf4, 0x84, 0xb9, 0x50, 0x74, 0xfe,
      0x4d, 0x8f, 0x85, 0x8e, 0x22, 0xd4, 0x35, 0x49, 0x1c, 0x7f, 0x71, 0x44,
      0xfe, 0x5,  0x72, 0x12, 0xc,  0x3d, 0x10, 0xeb, 0x60, 0x8c, 0xa6, 0x1,
      0xfb, 0x41, 0x88, 0xff, 0xdd, 0x77, 0xe4, 0x90, 0x23, 0xfd, 0xde, 0x1,
      0xc7, 0x43, 0x43, 0x56, 0x7d, 0x52, 0xfd, 0xeb, 0x79, 0x82, 0x34, 0x86,
      0x6b, 0x3f, 0xd9, 0x9d, 0x7b, 0x5b, 0xb8, 0xc6, 0x69, 0x1a, 0xd4, 0xdd,
      0x47, 0x60, 0x35, 0x5e, 0x66, 0x9c, 0xda, 0xc3, 0x33, 0x66, 0xa3, 0x8d,
      0x14, 0x9a, 0x2d, 0xeb, 0x19, 0x10, 0x1e, 0x69, 0xb7, 0x6,  0xdc, 0xef,
      0x2f, 0xf6, 0x55, 0x37, 0x4d, 0x3a, 0x87, 0x99, 0xd8, 0x55, 0xbb, 0x2c,
      0x1f, 0x5f, 0xa9, 0x1d, 0x87, 0x26, 0x49, 0xa,  0x27, 0xf4, 0xdc, 0x2f,
      0xf3, 0xd9, 0xb8, 0x5d, 0x84, 0xac, 0xb8, 0x39, 0x91, 0xeb, 0xcd, 0x27,
      0xcd, 0x23, 0x4b, 0xa7, 0x19, 0x77, 0xd1, 0x14, 0xae, 0x4,  0x15, 0x4,
      0xeb, 0x1c, 0x62, 0x48, 0x15, 0xde, 0x28, 0xc1, 0x42, 0x6f, 0x9b, 0xe7,
      0xb6, 0x70, 0xe1, 0xd1, 0x45, 0xb0, 0xb9, 0x6a, 0x1b, 0x5a, 0x21, 0xab,
      0x7e, 0xfe, 0x23, 0xfa, 0x11, 0xf8, 0x99, 0xaf, 0x24, 0xbf, 0xac, 0x24,
      0xcb, 0xa4, 0xd2, 0xef, 0xbb, 0xe8, 0xef, 0x3a, 0x73, 0x45, 0xe3, 0x4e,
      0x9d, 0xaf, 0xcc, 0xe0, 0xbd, 0x11, 0xad, 0x3b, 0xdc, 0xa5, 0xcd, 0x65,
      0x67, 0xd2, 0x66, 0xe9, 0x98, 0x85, 0xcc, 0xbc, 0x19, 0xb9, 0xbf, 0x7,
      0x60, 0xd7, 0x4,  0xa5, 0xc7, 0xff, 0xae, 0x37, 0x5c, 0x83, 0xe2, 0x23,
      0xdd, 0x52, 0x91, 0xf9, 0x20, 0x7b, 0xda, 0xb7, 0x4f, 0x86, 0x4e, 0x1e,
      0x4a, 0xf2, 0xc9, 0x83, 0xe1, 0xa6, 0x59, 0x56, 0xb4, 0xd,  0xf2, 0xda,
      0xa7, 0xf7, 0xd9, 0x90, 0xc8, 0xcf, 0x53, 0xf2, 0xb7, 0x8a, 0xa8, 0x54,
      0x8a, 0xac, 0xb1, 0xe0, 0x1,  0x8d, 0xc7, 0x3f, 0xac, 0x3,  0x73};

  gcry_error_t err =
      gcry_mpi_scan(&data_message->dh, GCRYMPI_FMT_USG, dh_data, 383, NULL);
  otrng_assert(!err);

  memset(data_message->nonce, 0xF, sizeof(data_message->nonce));
  data_message->enc_message = otrng_xmalloc_z(3);
  memset(data_message->enc_message, 0xE, 3);
  data_message->enc_message_len = 3;

  otrng_ecdh_keypair_destroy(&ecdh);
  return data_message;
}

static void test_data_message_serializes() {

  data_message_s *data_message = set_up_data_message();

  uint8_t *serialized = NULL;
  size_t serlen = 0;
  otrng_assert_is_success(
      otrng_data_message_body_serialize(&serialized, &serlen, data_message));

  const int OUR_DH_LEN = 4 + 383;
  const int MSG_AS_DATA = 4 + 3;
  g_assert_cmpint(DATA_MSG_MIN_BYTES + OUR_DH_LEN + MSG_AS_DATA, ==, serlen);

  char expected[] = {
      0x0,  0x04,           // version
      0x03,                 // message type
      0x0,  0x0,  0x0, 0x1, // sender instance tag
      0x0,  0x0,  0x0, 0x2, // receiver instance tag
      0xA,                  // flags
      0x0,  0x0,  0x0, 98,  // previous chain number
      0x0,  0x0,  0x0, 1,   // ratchet id
      0x0,  0x0,  0x0, 99,  // message id
  };

  uint8_t *cursor = serialized;
  otrng_assert_cmpmem(cursor, expected, 24);
  cursor += 24;

  uint8_t serialized_y[PUB_KEY_SER_BYTES] = {0};
  int ser_len = otrng_serialize_ec_point(serialized_y, data_message->ecdh);
  otrng_assert_cmpmem(cursor, serialized_y, ED448_POINT_BYTES);

  cursor += ser_len;

  uint8_t serialized_b[DH3072_MOD_LEN_BYTES] = {0};
  size_t mpi_len = 0;
  otrng_assert_is_success(otrng_dh_mpi_serialize(
      serialized_b, DH3072_MOD_LEN_BYTES, &mpi_len, data_message->dh));
  // Skip first 4 because they are the size (mpi_len)
  otrng_assert_cmpmem(cursor + 4, serialized_b, mpi_len);

  cursor += 4 + mpi_len;

  otrng_assert_cmpmem(cursor, data_message->nonce, DATA_MSG_NONCE_BYTES);
  cursor += DATA_MSG_NONCE_BYTES;

  uint8_t expected_enc[7] = {
      0x0, 0x0, 0x0, 0x3, 0xE, 0xE, 0xE,
  };
  otrng_assert_cmpmem(cursor, expected_enc, 7);

  otrng_data_message_free(data_message);
  free(serialized);
}

static void test_data_message_serializes_absent_dh() {
  data_message_s *data_message = set_up_data_message();

  // Serialize with an empty DH
  otrng_dh_mpi_release(data_message->dh);
  data_message->dh = NULL;

  uint8_t *serialized = NULL;
  size_t serlen = 0;
  otrng_assert_is_success(
      otrng_data_message_body_serialize(&serialized, &serlen, data_message));

  const int OUR_DH_LEN = 4 + 0; // Should be zero per spec.
  const int MSG_AS_DATA = 4 + 3;
  g_assert_cmpint(DATA_MSG_MIN_BYTES + OUR_DH_LEN + MSG_AS_DATA, ==, serlen);

  uint8_t *cursor = serialized;
  cursor += 24;                // Skip header
  cursor += ED448_POINT_BYTES; // Skip ECDH key
  cursor += 4;                 // Skip the DH's MPI header;

  // Make sure next field is deserialized as expected
  otrng_assert_cmpmem(cursor, data_message->nonce, DATA_MSG_NONCE_BYTES);

  otrng_data_message_free(data_message);
  free(serialized);
}

static void test_otrng_data_message_deserializes() {
  data_message_s *data_message = set_up_data_message();

  uint8_t *serialized = NULL;
  size_t serlen = 0;
  otrng_assert_is_success(
      otrng_data_message_body_serialize(&serialized, &serlen, data_message));

  const uint8_t mac_data[DATA_MSG_MAC_BYTES] = {
      0x14, 0x9a, 0xf0, 0x93, 0xcc, 0x3f, 0x44, 0xf5, 0x1b, 0x41, 0x11,
      0xc3, 0x84, 0x10, 0x88, 0xed, 0xd3, 0xff, 0x66, 0x7e, 0xfd, 0x3c,
      0x6e, 0x34, 0xf2, 0xbf, 0x92, 0x8a, 0x5e, 0xf6, 0x4b, 0x40, 0x39,
      0xfe, 0xc1, 0xe7, 0xde, 0x4c, 0x17, 0x84, 0x2b, 0xfa, 0x2a, 0x55,
      0x8c, 0xd6, 0x1a, 0x08, 0x26, 0x4f, 0x61, 0x32, 0xdb, 0xd2, 0x58,
      0x90, 0x7d, 0x1e, 0x97, 0x35, 0xd2, 0x38, 0x60, 0xa1};
  memcpy(data_message->mac, mac_data, DATA_MSG_MAC_BYTES);
  serialized = otrng_xrealloc(serialized, serlen + DATA_MSG_MAC_BYTES);
  memcpy(serialized + serlen, mac_data, DATA_MSG_MAC_BYTES);

  data_message_s *deserialized = otrng_data_message_new();
  otrng_assert_is_success(otrng_data_message_deserialize(
      deserialized, serialized, serlen + DATA_MSG_MAC_BYTES, NULL));

  otrng_assert(data_message->sender_instance_tag ==
               deserialized->sender_instance_tag);
  otrng_assert(data_message->receiver_instance_tag ==
               deserialized->receiver_instance_tag);
  otrng_assert(data_message->flags == deserialized->flags);
  otrng_assert(data_message->previous_chain_n ==
               deserialized->previous_chain_n);
  otrng_assert(data_message->ratchet_id == deserialized->ratchet_id);
  otrng_assert(data_message->message_id == deserialized->message_id);
  otrng_assert_cmpmem(data_message->ecdh, deserialized->ecdh,
                      ED448_POINT_BYTES);
  otrng_assert(dh_mpi_cmp(data_message->dh, deserialized->dh) == 0);
  otrng_assert_cmpmem(data_message->nonce, deserialized->nonce,
                      DATA_MSG_NONCE_BYTES);
  otrng_assert_cmpmem(data_message->enc_message, deserialized->enc_message,
                      data_message->enc_message_len);
  otrng_assert(data_message->enc_message_len == deserialized->enc_message_len);
  otrng_assert_cmpmem(data_message->mac, deserialized->mac, DATA_MSG_MAC_BYTES);

  otrng_data_message_free(data_message);
  otrng_data_message_free(deserialized);
  free(serialized);
}

static void test_data_message_valid() {
  data_message_s *data_message = set_up_data_message();

  // Should fail because data_message has a zeroed mac tag.
  message_mac_key_t mac_key = {0};
  otrng_assert(otrng_valid_data_message(mac_key, data_message) == otrng_false);

  // Overwrite the zeroed mac tag
  uint8_t *body = NULL;
  size_t bodylen = 0;

  otrng_assert_is_success(
      otrng_data_message_body_serialize(&body, &bodylen, data_message));

  otrng_assert_is_success(otrng_data_message_authenticator(
      data_message->mac, DATA_MSG_MAC_BYTES, mac_key, body, bodylen));

  free(body);

  otrng_assert(otrng_valid_data_message(mac_key, data_message) == otrng_true);

  // Overwrite DH with an invalid value
  gcry_mpi_set_ui(data_message->dh, 1);
  otrng_assert(otrng_valid_data_message(mac_key, data_message) == otrng_false);

  // A data message without a DH key is also valid.
  otrng_dh_mpi_release(data_message->dh);
  data_message->dh = NULL;

  otrng_assert_is_success(
      otrng_data_message_body_serialize(&body, &bodylen, data_message));

  otrng_assert_is_success(otrng_data_message_authenticator(
      data_message->mac, DATA_MSG_MAC_BYTES, mac_key, body, bodylen));

  free(body);

  otrng_assert(otrng_valid_data_message(mac_key, data_message) == otrng_true);

  otrng_data_message_free(data_message);
}

void units_data_message_add_tests(void) {
  g_test_add_func("/data_message/valid", test_data_message_valid);
  g_test_add_func("/data_message/serialize", test_data_message_serializes);
  g_test_add_func("/data_message/serialize_absent_dh",
                  test_data_message_serializes_absent_dh);
  g_test_add_func("/data_message/deserialize",
                  test_otrng_data_message_deserializes);
}
