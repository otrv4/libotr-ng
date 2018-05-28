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

void test_dake_prekey_message_serializes() {

  ecdh_keypair_p ecdh;
  dh_keypair_p dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {0};
  otrng_ecdh_keypair_generate(ecdh, sym);
  otrng_assert(otrng_dh_keypair_generate(dh) == SUCCESS);

  dake_prekey_message_s *prekey_message = otrng_dake_prekey_message_new();
  prekey_message->sender_instance_tag = 1;
  otrng_ec_point_copy(prekey_message->Y, ecdh->pub);
  prekey_message->B = otrng_dh_mpi_copy(dh->pub);

  uint8_t *serialized = NULL;
  otrng_assert(otrng_dake_prekey_message_asprintf(&serialized, NULL,
                                                  prekey_message) == SUCCESS);

  uint8_t expected[] = {
      0x0,
      0x04, // version

      PRE_KEY_MSG_TYPE, // message type

      0x0,
      0x0,
      0x0,
      0x1, // sender instance tag

  };

  uint8_t *cursor = serialized;
  otrng_assert_cmpmem(cursor, expected,
                      sizeof(expected)); /* size of expected */
  cursor += sizeof(expected);

  uint8_t serialized_y[PUB_KEY_SER_BYTES];
  int ser_len = otrng_serialize_ec_point(serialized_y, prekey_message->Y);
  otrng_assert_cmpmem(cursor, serialized_y, ser_len);

  cursor += ser_len;

  uint8_t serialized_b[DH3072_MOD_LEN_BYTES];
  size_t mpi_len = 0;
  otrng_err err = otrng_dh_mpi_serialize(serialized_b, DH3072_MOD_LEN_BYTES,
                                         &mpi_len, prekey_message->B);
  otrng_assert(err == SUCCESS);

  /* Skip first 4 because they are the size (mpi_len) */
  otrng_assert_cmpmem(cursor + 4, serialized_b, mpi_len);

  free(serialized);
  otrng_dh_keypair_destroy(dh);
  otrng_ecdh_keypair_destroy(ecdh);
  otrng_dake_prekey_message_free(prekey_message);
}

void test_otrng_dake_prekey_message_deserializes() {

  ecdh_keypair_p ecdh;
  dh_keypair_p dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_ecdh_keypair_generate(ecdh, sym);
  otrng_assert(otrng_dh_keypair_generate(dh) == SUCCESS);

  dake_prekey_message_s *prekey_message = otrng_dake_prekey_message_new();
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
  otrng_assert_ec_public_key_eq(deserialized->Y, prekey_message->Y);
  otrng_assert_dh_public_key_eq(deserialized->B, prekey_message->B);

  free(serialized);
  serialized = NULL;
  otrng_dh_keypair_destroy(dh);
  otrng_ecdh_keypair_destroy(ecdh);
  otrng_dake_prekey_message_free(prekey_message);
  otrng_dake_prekey_message_free(deserialized);
}

void test_dake_prekey_message_valid() {

  ecdh_keypair_p ecdh;
  dh_keypair_p dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_ecdh_keypair_generate(ecdh, sym);
  otrng_assert(otrng_dh_keypair_generate(dh) == SUCCESS);

  dake_prekey_message_s *prekey_message = otrng_dake_prekey_message_new();
  otrng_assert(prekey_message != NULL);

  otrng_ec_point_copy(prekey_message->Y, ecdh->pub);
  prekey_message->B = otrng_dh_mpi_copy(dh->pub);

  otrng_assert(otrng_valid_received_values(prekey_message->Y, prekey_message->B,
                                           NULL) == otrng_true);

  otrng_dake_prekey_message_free(prekey_message);

  dake_prekey_message_s *invalid_prekey_message =
      otrng_dake_prekey_message_new();

  // Invalid point
  otrng_ec_point_destroy(invalid_prekey_message->Y);
  invalid_prekey_message->B = otrng_dh_mpi_copy(dh->pub);

  otrng_assert(otrng_valid_received_values(invalid_prekey_message->Y,
                                           invalid_prekey_message->B,
                                           NULL) == otrng_false);

  otrng_ecdh_keypair_destroy(ecdh);
  otrng_dh_keypair_destroy(dh);
  otrng_dake_prekey_message_free(invalid_prekey_message);
}

static uint8_t encrypted[3] = {0xEE, 0xFF, 0xDD};
static uint8_t nonce[24] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x17, 0x18, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x17, 0x18, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x17, 0x18,
};

static uint8_t mac_tag[HASH_BYTES] = {0xFD};

static void
setup_attached_encrypted_message(dake_non_interactive_auth_message_p msg) {
  uint8_t pub_dh_key_s[DH3072_MOD_LEN_BYTES] = {
      0x77, 0x98, 0xd0, 0x39, 0x9f, 0xe3, 0x45, 0x5b, 0x2c, 0xb0, 0x62, 0x5f,
      0xb2, 0x62, 0x8f, 0x5a, 0x9c, 0x35, 0xa5, 0xd5, 0x19, 0xb0, 0xaf, 0x4b,
      0x70, 0xcc, 0xeb, 0xdc, 0x81, 0xc9, 0x24, 0xa3, 0x1b, 0xcb, 0xc1, 0xf8,
      0x4d, 0x84, 0xa7, 0x55, 0xb9, 0xd2, 0xba, 0x3c, 0x84, 0x6e, 0x62, 0x29,
      0xd5, 0x9b, 0x86, 0x11, 0xe7, 0xe9, 0x93, 0xd6, 0x41, 0x9e, 0xce, 0x9d,
      0xfb, 0x4a, 0x57, 0x91, 0x11, 0xdb, 0x5e, 0x4f, 0x4b, 0x99, 0x43, 0x58,
      0x50, 0xc9, 0x29, 0xce, 0x9b, 0x75, 0x4b, 0x56, 0x3a, 0xfc, 0xe5, 0x92,
      0x5b, 0xa3, 0x04, 0x9d, 0xf7, 0xf8, 0x1a, 0xed, 0x98, 0x86, 0x3a, 0xeb,
      0xd6, 0x23, 0xaf, 0xb9, 0x96, 0x73, 0xbd, 0x5a, 0x68, 0xb2, 0x99, 0xb1,
      0x28, 0xb3, 0x8b, 0x2b, 0xb4, 0x4b, 0x82, 0x23, 0x43, 0xee, 0xa0, 0xf9,
      0x64, 0x90, 0x13, 0x9e, 0xa8, 0x3d, 0x0f, 0x09, 0x36, 0xe3, 0x0a, 0x51,
      0x3f, 0x10, 0x91, 0xd6, 0x9b, 0x3b, 0x6d, 0x32, 0xf2, 0x08, 0xbc, 0x0e,
      0x9e, 0x63, 0x5a, 0x64, 0x22, 0x83, 0xe2, 0x9c, 0xfe, 0xf8, 0x68, 0xc5,
      0x14, 0x42, 0x8e, 0x8d, 0x25, 0x30, 0x69, 0x7b, 0x3c, 0x04, 0x25, 0x4f,
      0xef, 0x5b, 0x26, 0x09, 0xe6, 0xc3, 0xa7, 0x50, 0xeb, 0x25, 0x99, 0xea,
      0xa8, 0x7b, 0x94, 0xfc, 0x78, 0xce, 0x2c, 0x43, 0x0a, 0x2b, 0x0f, 0x1b,
      0xc7, 0xdd, 0xec, 0x75, 0xcc, 0x27, 0x86, 0x71, 0xc2, 0x1b, 0xcf, 0x77,
      0x7b, 0x4a, 0xce, 0xcb, 0xd7, 0xd9, 0xbf, 0x91, 0x6f, 0xe1, 0x3c, 0x00,
      0x1c, 0x32, 0xdd, 0xc1, 0x40, 0x91, 0xd6, 0xce, 0xca, 0x7d, 0x7c, 0xd8,
      0xaf, 0xdb, 0x24, 0xfb, 0xa9, 0xc6, 0x62, 0x19, 0x54, 0xf4, 0x2c, 0x7a,
      0xbc, 0x00, 0x3e, 0xc8, 0x66, 0xc1, 0xac, 0xd2, 0x03, 0x8b, 0x33, 0x52,
      0x08, 0x92, 0x88, 0xe9, 0x5b, 0x24, 0x12, 0x61, 0x0c, 0x54, 0x5e, 0x57,
      0x21, 0xe8, 0x40, 0x73, 0x89, 0x1c, 0x45, 0xf8, 0x99, 0x4f, 0xcc, 0xfa,
      0xd7, 0xf1, 0x58, 0x10, 0xb0, 0xeb, 0x53, 0x1a, 0x4c, 0xca, 0xb8, 0x0f,
      0x57, 0xf6, 0x35, 0x87, 0x87, 0x83, 0x1b, 0x66, 0x3b, 0x94, 0xfc, 0xcd,
      0x27, 0xac, 0x99, 0x30, 0x86, 0x46, 0x79, 0x23, 0xa5, 0xf8, 0x24, 0xe6,
      0x1a, 0x54, 0x89, 0x09, 0x15, 0x8f, 0x41, 0x81, 0x5e, 0x01, 0xbc, 0x7e,
      0x67, 0x84, 0x8a, 0x83, 0xf2, 0x6b, 0x99, 0x77, 0xd6, 0x20, 0x1e, 0xc2,
      0x13, 0xf0, 0x3c, 0xcd, 0x1e, 0xed, 0xcc, 0xed, 0x40, 0x8b, 0x73, 0xdd,
      0xf4, 0xd6, 0x23, 0x48, 0xf9, 0xbc, 0x94, 0x8c, 0x18, 0x88, 0x0d, 0x9d,
      0x76, 0x77, 0x63, 0xd7, 0xab, 0x4f, 0x7f, 0x25, 0x6d, 0xe2, 0xad, 0x80,
      0x23, 0x53, 0xe5, 0x4c, 0xa6, 0xbf, 0xc4, 0x2d, 0x3d, 0x88, 0x9d, 0x2d,
  };

  uint8_t pub_ecdh_key_s[ED448_POINT_BYTES] = {
      0x73, 0x58, 0x9d, 0x71, 0x77, 0xac, 0x23, 0x70, 0x07, 0xe4, 0xa4, 0x5c,
      0xf8, 0xcf, 0xb4, 0x96, 0x58, 0x18, 0x11, 0x8f, 0x9e, 0xc4, 0x00, 0x7b,
      0xef, 0xea, 0xba, 0x4f, 0x42, 0xd3, 0xfe, 0x16, 0x6f, 0xe0, 0xd5, 0xc6,
      0x76, 0x7c, 0x4b, 0x72, 0xc7, 0x74, 0xf1, 0x20, 0x7e, 0xf8, 0x00, 0xd4,
      0x43, 0xce, 0x4b, 0x51, 0x51, 0x6a, 0x46, 0x90, 0x00,
  };

  otrng_err err = otrng_dh_mpi_deserialize(&msg->dh, pub_dh_key_s,
                                           DH3072_MOD_LEN_BYTES, NULL);
  otrng_assert(SUCCESS == err);

  err = otrng_ec_point_decode(msg->ecdh, pub_ecdh_key_s);
  otrng_assert(SUCCESS == err);

  msg->enc_msg = malloc(3);
  memcpy(msg->enc_msg, encrypted, 3);
  msg->enc_msg_len = 3;
  msg->message_id = 0x1A;
  msg->ratchet_id = 0x2A;
  memcpy(msg->nonce, nonce, 24);
}

static void
setup_non_interactive_auth_message(dake_non_interactive_auth_message_p msg,
                                   const identity_message_fixture_s *f) {
  ecdh_keypair_p ecdh;
  dh_keypair_p dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {0};
  otrng_ecdh_keypair_generate(ecdh, sym);
  otrng_assert(otrng_dh_keypair_generate(dh) == SUCCESS);

  msg->enc_msg = NULL;
  msg->enc_msg_len = 0;

  msg->sender_instance_tag = 1;
  msg->receiver_instance_tag = 1;
  otrng_client_profile_copy(msg->profile, f->profile);
  otrng_ec_point_copy(msg->X, ecdh->pub);
  msg->A = otrng_dh_mpi_copy(dh->pub);
  memcpy(msg->auth_mac, mac_tag, HASH_BYTES);

  memset(msg->sigma, 0, sizeof(ring_sig_p));
  msg->prekey_message_id = 0x0A00000D;
  msg->long_term_key_id = 0x0B00000E;
  msg->prekey_profile_id = 0x0C00000F;

  otrng_dh_keypair_destroy(dh);
  otrng_ecdh_keypair_destroy(ecdh);
}

void test_xzdh_encrypted_message_asprintf() {
  uint8_t *dst = NULL;
  size_t dst_len = 0;
  dake_non_interactive_auth_message_p msg;

  // TODO: Extract xzdh encrypted message data type.
  msg->profile->versions = NULL;
  otrng_mpi_init(msg->profile->transitional_signature);
  msg->A = NULL;
  msg->enc_msg = NULL;
  otrng_assert(xzdh_encrypted_message_asprintf(&dst, &dst_len, msg) == SUCCESS);
  otrng_assert(dst == NULL);
  otrng_assert(dst_len == 0);

  uint8_t expected[] = {
      0x00, 0x00, 0x00, 0x2A, // ratched id
      0x00, 0x00, 0x00, 0x1A, // message id

      0x73, 0x58, 0x9d, 0x71, 0x77, 0xac, 0x23, 0x70, 0x07, 0xe4, 0xa4, 0x5c,
      0xf8, 0xcf, 0xb4, 0x96, 0x58, 0x18, 0x11, 0x8f, 0x9e, 0xc4, 0x00, 0x7b,
      0xef, 0xea, 0xba, 0x4f, 0x42, 0xd3, 0xfe, 0x16, 0x6f, 0xe0, 0xd5, 0xc6,
      0x76, 0x7c, 0x4b, 0x72, 0xc7, 0x74, 0xf1, 0x20, 0x7e, 0xf8, 0x00, 0xd4,
      0x43, 0xce, 0x4b, 0x51, 0x51, 0x6a, 0x46, 0x90, 0x00, // public ecdh key

      0x00, 0x00, 0x01, 0x80,                                     // MPI length
      0x77, 0x98, 0xd0, 0x39, 0x9f, 0xe3, 0x45, 0x5b, 0x2c, 0xb0, // MPI value
      0x62, 0x5f, 0xb2, 0x62, 0x8f, 0x5a, 0x9c, 0x35, 0xa5, 0xd5, 0x19, 0xb0,
      0xaf, 0x4b, 0x70, 0xcc, 0xeb, 0xdc, 0x81, 0xc9, 0x24, 0xa3, 0x1b, 0xcb,
      0xc1, 0xf8, 0x4d, 0x84, 0xa7, 0x55, 0xb9, 0xd2, 0xba, 0x3c, 0x84, 0x6e,
      0x62, 0x29, 0xd5, 0x9b, 0x86, 0x11, 0xe7, 0xe9, 0x93, 0xd6, 0x41, 0x9e,
      0xce, 0x9d, 0xfb, 0x4a, 0x57, 0x91, 0x11, 0xdb, 0x5e, 0x4f, 0x4b, 0x99,
      0x43, 0x58, 0x50, 0xc9, 0x29, 0xce, 0x9b, 0x75, 0x4b, 0x56, 0x3a, 0xfc,
      0xe5, 0x92, 0x5b, 0xa3, 0x04, 0x9d, 0xf7, 0xf8, 0x1a, 0xed, 0x98, 0x86,
      0x3a, 0xeb, 0xd6, 0x23, 0xaf, 0xb9, 0x96, 0x73, 0xbd, 0x5a, 0x68, 0xb2,
      0x99, 0xb1, 0x28, 0xb3, 0x8b, 0x2b, 0xb4, 0x4b, 0x82, 0x23, 0x43, 0xee,
      0xa0, 0xf9, 0x64, 0x90, 0x13, 0x9e, 0xa8, 0x3d, 0x0f, 0x09, 0x36, 0xe3,
      0x0a, 0x51, 0x3f, 0x10, 0x91, 0xd6, 0x9b, 0x3b, 0x6d, 0x32, 0xf2, 0x08,
      0xbc, 0x0e, 0x9e, 0x63, 0x5a, 0x64, 0x22, 0x83, 0xe2, 0x9c, 0xfe, 0xf8,
      0x68, 0xc5, 0x14, 0x42, 0x8e, 0x8d, 0x25, 0x30, 0x69, 0x7b, 0x3c, 0x04,
      0x25, 0x4f, 0xef, 0x5b, 0x26, 0x09, 0xe6, 0xc3, 0xa7, 0x50, 0xeb, 0x25,
      0x99, 0xea, 0xa8, 0x7b, 0x94, 0xfc, 0x78, 0xce, 0x2c, 0x43, 0x0a, 0x2b,
      0x0f, 0x1b, 0xc7, 0xdd, 0xec, 0x75, 0xcc, 0x27, 0x86, 0x71, 0xc2, 0x1b,
      0xcf, 0x77, 0x7b, 0x4a, 0xce, 0xcb, 0xd7, 0xd9, 0xbf, 0x91, 0x6f, 0xe1,
      0x3c, 0x00, 0x1c, 0x32, 0xdd, 0xc1, 0x40, 0x91, 0xd6, 0xce, 0xca, 0x7d,
      0x7c, 0xd8, 0xaf, 0xdb, 0x24, 0xfb, 0xa9, 0xc6, 0x62, 0x19, 0x54, 0xf4,
      0x2c, 0x7a, 0xbc, 0x00, 0x3e, 0xc8, 0x66, 0xc1, 0xac, 0xd2, 0x03, 0x8b,
      0x33, 0x52, 0x08, 0x92, 0x88, 0xe9, 0x5b, 0x24, 0x12, 0x61, 0x0c, 0x54,
      0x5e, 0x57, 0x21, 0xe8, 0x40, 0x73, 0x89, 0x1c, 0x45, 0xf8, 0x99, 0x4f,
      0xcc, 0xfa, 0xd7, 0xf1, 0x58, 0x10, 0xb0, 0xeb, 0x53, 0x1a, 0x4c, 0xca,
      0xb8, 0x0f, 0x57, 0xf6, 0x35, 0x87, 0x87, 0x83, 0x1b, 0x66, 0x3b, 0x94,
      0xfc, 0xcd, 0x27, 0xac, 0x99, 0x30, 0x86, 0x46, 0x79, 0x23, 0xa5, 0xf8,
      0x24, 0xe6, 0x1a, 0x54, 0x89, 0x09, 0x15, 0x8f, 0x41, 0x81, 0x5e, 0x01,
      0xbc, 0x7e, 0x67, 0x84, 0x8a, 0x83, 0xf2, 0x6b, 0x99, 0x77, 0xd6, 0x20,
      0x1e, 0xc2, 0x13, 0xf0, 0x3c, 0xcd, 0x1e, 0xed, 0xcc, 0xed, 0x40, 0x8b,
      0x73, 0xdd, 0xf4, 0xd6, 0x23, 0x48, 0xf9, 0xbc, 0x94, 0x8c, 0x18, 0x88,
      0x0d, 0x9d, 0x76, 0x77, 0x63, 0xd7, 0xab, 0x4f, 0x7f, 0x25, 0x6d, 0xe2,
      0xad, 0x80, 0x23, 0x53, 0xe5, 0x4c, 0xa6, 0xbf, 0xc4, 0x2d, 0x3d, 0x88,
      0x9d, 0x2d, // public dh key

      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x17, 0x18, // nonce
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x17, 0x18, 0x10, 0x11, 0x12, 0x13,
      0x14, 0x15, 0x17, 0x18,

      0x00, 0x00, 0x00, 0x03, // encrypted message len
      0xEE, 0xFF, 0xDD,       // encrypted message
  };

  setup_attached_encrypted_message(msg);

  otrng_assert(xzdh_encrypted_message_asprintf(&dst, &dst_len, msg) == SUCCESS);
  otrng_assert_cmpmem(expected, dst, sizeof(expected));

  free(dst);
  otrng_dake_non_interactive_auth_message_destroy(msg);
}

void test_xzdh_encrypted_message_deserialize() {
  uint8_t *dst = NULL;
  size_t dst_len = 0;

  dake_non_interactive_auth_message_p expected;
  dake_non_interactive_auth_message_p msg;

  // This is here so we don't need to initialize the user profile.
  // Otherwise, it will crash when msg is destroyed.
  expected->A = NULL;
  expected->profile->versions = NULL;
  otrng_mpi_init(expected->profile->transitional_signature);
  msg->A = NULL;
  msg->profile->versions = NULL;
  otrng_mpi_init(msg->profile->transitional_signature);

  setup_attached_encrypted_message(expected);
  otrng_assert(xzdh_encrypted_message_asprintf(&dst, &dst_len, expected) ==
               SUCCESS);

  size_t read = 0;
  size_t ret = xzdh_encrypted_message_deserialize(msg, dst, dst_len, &read);

  otrng_assert(ret != 0);
  otrng_assert(ret == read);

  otrng_assert(msg->enc_msg_len == expected->enc_msg_len);
  otrng_assert(msg->message_id == expected->message_id);
  otrng_assert(msg->ratchet_id == expected->ratchet_id);

  otrng_assert_cmpmem(msg->enc_msg, expected->enc_msg, msg->enc_msg_len);
  otrng_assert_cmpmem(msg->nonce, expected->nonce, 24);

  otrng_assert(otrng_ec_point_eq(msg->ecdh, expected->ecdh));
  otrng_assert(gcry_mpi_cmp(msg->dh, expected->dh) == 0);

  free(dst);
  otrng_dake_non_interactive_auth_message_destroy(expected);
  otrng_dake_non_interactive_auth_message_destroy(msg);
}

void test_dake_non_interactive_auth_message_serializes(
    identity_message_fixture_s *f, gconstpointer data) {

  dake_non_interactive_auth_message_p msg;
  setup_non_interactive_auth_message(msg, f);

  uint8_t *serialized = NULL;
  size_t len = 0;
  otrng_assert(otrng_dake_non_interactive_auth_message_asprintf(
                   &serialized, &len, msg) == SUCCESS);

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

  uint8_t *cursor = serialized;
  otrng_assert_cmpmem(cursor, expected_header, 11); /* size of expected */
  cursor += 11;

  size_t client_profile_len = 0;
  uint8_t *client_profile_serialized = NULL;
  otrng_assert(otrng_client_profile_asprintf(&client_profile_serialized,
                                             &client_profile_len,
                                             msg->profile) == SUCCESS);
  otrng_assert_cmpmem(cursor, client_profile_serialized, client_profile_len);
  free(client_profile_serialized);
  cursor += client_profile_len;

  uint8_t serialized_x[PUB_KEY_SER_BYTES];
  size_t ser_len = otrng_serialize_ec_point(serialized_x, msg->X);
  otrng_assert_cmpmem(cursor, serialized_x, ser_len);
  cursor += ser_len;

  uint8_t serialized_a[DH3072_MOD_LEN_BYTES];
  otrng_err err = otrng_dh_mpi_serialize(serialized_a, DH3072_MOD_LEN_BYTES,
                                         &ser_len, msg->A);
  otrng_assert(err == SUCCESS);

  /* Skip first 4 because they are the size */
  cursor += 4;
  otrng_assert_cmpmem(cursor, serialized_a, ser_len);
  cursor += ser_len;

  uint8_t serialized_ring_sig[RING_SIG_BYTES];
  otrng_serialize_ring_sig(serialized_ring_sig, msg->sigma);

  otrng_assert_cmpmem(cursor, serialized_ring_sig, RING_SIG_BYTES);
  cursor += RING_SIG_BYTES;

  // Prekey Message Identifier
  otrng_assert(*(cursor++) == 0x0A);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x0D);

  // Client Profile Identifier
  otrng_assert(*(cursor++) == 0x0B);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x0E);

  // Prekey Profile Identifier
  otrng_assert(*(cursor++) == 0x0C);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x0F);

  otrng_assert_cmpmem(cursor, mac_tag, HASH_BYTES);
  cursor += HASH_BYTES;

  free(serialized);
  otrng_dake_non_interactive_auth_message_destroy(msg);
}

void test_dake_non_interactive_auth_message_with_encrypted_message_serializes(
    identity_message_fixture_s *f, gconstpointer data) {

  dake_non_interactive_auth_message_p msg;
  setup_non_interactive_auth_message(msg, f);
  setup_attached_encrypted_message(msg);

  uint8_t *serialized = NULL;
  size_t len = 0;
  otrng_assert(otrng_dake_non_interactive_auth_message_asprintf(
                   &serialized, &len, msg) == SUCCESS);

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

  uint8_t *cursor = serialized;
  otrng_assert_cmpmem(cursor, expected_header, 11); /* size of expected */
  cursor += 11;

  size_t client_profile_len = 0;
  uint8_t *client_profile_serialized = NULL;
  otrng_assert(otrng_client_profile_asprintf(&client_profile_serialized,
                                             &client_profile_len,
                                             msg->profile) == SUCCESS);
  otrng_assert_cmpmem(cursor, client_profile_serialized, client_profile_len);
  free(client_profile_serialized);
  cursor += client_profile_len;

  uint8_t serialized_x[PUB_KEY_SER_BYTES];
  size_t ser_len = otrng_serialize_ec_point(serialized_x, msg->X);
  otrng_assert_cmpmem(cursor, serialized_x, ser_len);
  cursor += ser_len;

  uint8_t serialized_a[DH3072_MOD_LEN_BYTES];
  otrng_err err = otrng_dh_mpi_serialize(serialized_a, DH3072_MOD_LEN_BYTES,
                                         &ser_len, msg->A);
  otrng_assert(err == SUCCESS);

  /* Skip first 4 because they are the size */
  cursor += 4;
  otrng_assert_cmpmem(cursor, serialized_a, ser_len);
  cursor += ser_len;

  uint8_t serialized_ring_sig[RING_SIG_BYTES];
  otrng_serialize_ring_sig(serialized_ring_sig, msg->sigma);

  otrng_assert_cmpmem(cursor, serialized_ring_sig, RING_SIG_BYTES);
  cursor += RING_SIG_BYTES;

  // Prekey Message Identifier
  otrng_assert(*(cursor++) == 0x0A);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x0D);

  // Client Profile Identifier
  otrng_assert(*(cursor++) == 0x0B);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x0E);

  // Prekey Profile Identifier
  otrng_assert(*(cursor++) == 0x0C);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x00);
  otrng_assert(*(cursor++) == 0x0F);

  uint8_t *expected_encrypted_message = NULL;
  size_t expected_encrypted_message_len = 0;
  otrng_assert(xzdh_encrypted_message_asprintf(&expected_encrypted_message,
                                               &expected_encrypted_message_len,
                                               msg) == SUCCESS);

  otrng_assert_cmpmem(cursor, expected_encrypted_message,
                      expected_encrypted_message_len);
  free(expected_encrypted_message);
  cursor += expected_encrypted_message_len;

  otrng_assert_cmpmem(cursor, mac_tag, HASH_BYTES);
  cursor += HASH_BYTES;

  free(serialized);
  otrng_dake_non_interactive_auth_message_destroy(msg);
}

void test_otrng_dake_non_interactive_auth_message_deserializes(
    identity_message_fixture_s *f, gconstpointer data) {

  dake_non_interactive_auth_message_p expected;
  setup_non_interactive_auth_message(expected, f);

  uint8_t *serialized = NULL;
  size_t len = 0;
  otrng_assert(otrng_dake_non_interactive_auth_message_asprintf(
                   &serialized, &len, expected) == SUCCESS);

  dake_non_interactive_auth_message_p deserialized;
  otrng_assert(otrng_dake_non_interactive_auth_message_deserialize(
                   deserialized, serialized, len) == SUCCESS);
  free(serialized);

  g_assert_cmpuint(deserialized->sender_instance_tag, ==,
                   expected->sender_instance_tag);
  g_assert_cmpuint(deserialized->receiver_instance_tag, ==,
                   expected->receiver_instance_tag);
  otrng_assert_client_profile_eq(deserialized->profile, expected->profile);
  otrng_assert_ec_public_key_eq(deserialized->X, expected->X);
  otrng_assert_dh_public_key_eq(deserialized->A, expected->A);
  otrng_assert_cmpmem(deserialized->auth_mac, expected->auth_mac, HASH_BYTES);

  otrng_assert(
      otrng_ec_scalar_eq(deserialized->sigma->c1, expected->sigma->c1));
  otrng_assert(
      otrng_ec_scalar_eq(deserialized->sigma->r1, expected->sigma->r1));
  otrng_assert(
      otrng_ec_scalar_eq(deserialized->sigma->c2, expected->sigma->c2));
  otrng_assert(
      otrng_ec_scalar_eq(deserialized->sigma->r2, expected->sigma->r2));
  otrng_assert(
      otrng_ec_scalar_eq(deserialized->sigma->c3, expected->sigma->c3));
  otrng_assert(
      otrng_ec_scalar_eq(deserialized->sigma->r3, expected->sigma->r3));

  otrng_assert(deserialized->prekey_message_id == expected->prekey_message_id);
  otrng_assert(deserialized->long_term_key_id == expected->long_term_key_id);
  otrng_assert(deserialized->prekey_profile_id == expected->prekey_profile_id);

  otrng_dake_non_interactive_auth_message_destroy(expected);
  otrng_dake_non_interactive_auth_message_destroy(deserialized);
}
