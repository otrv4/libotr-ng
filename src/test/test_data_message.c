#include "../data_message.h"

void
test_data_message_serializes() {
  dh_init();

  ec_keypair_t ecdh;
  dh_keypair_t dh;

  ec_keypair_generate(ecdh);
  dh_keypair_generate(dh);

  data_message_t *data_msg = data_message_new();
  otrv4_assert(data_msg);

  data_msg->sender_instance_tag = 1;
  data_msg->receiver_instance_tag = 2;
  data_msg->flags = 0xA;
  data_msg->ratchet_id = 10;
  data_msg->message_id = 99;
  ec_public_key_copy(data_msg->our_ecdh, ecdh->pub);
  data_msg->our_dh = dh_mpi_copy(dh->pub);
  memset(data_msg->nonce, 0xF, DATA_MSG_NONCE_BYTES);
  data_msg->enc_msg = malloc(3);
  memset(data_msg->enc_msg, 0xE, 3);
  data_msg->enc_msg_len = 3;

  uint8_t *serialized = NULL;
  size_t serlen = 0;
  otrv4_assert(data_message_body_aprint(&serialized, &serlen, data_msg));

  g_assert_cmpint(DATA_MESSAGE_MIN_BYTES+7, ==, serlen);

  char expected[] = {
    0x0, 0x04,              // version
    0x03,                   // message type
    0x0, 0x0, 0x0, 0x1,     // sender instance tag
    0x0, 0x0, 0x0, 0x2,     // receiver instance tag
    0xA,                    // flags
    0x0, 0x0, 0x0, 0xA,     // ratchet id
    0x0, 0x0, 0x0, 99,      // message id
  };

  uint8_t *cursor = serialized;
  otrv4_assert_cmpmem(cursor, expected, 20);
  cursor += 20;

  uint8_t serialized_y[sizeof(ec_public_key_t)+2] = {0};
  ec_public_key_serialize(serialized_y, sizeof(ec_public_key_t), data_msg->our_ecdh);
  otrv4_assert_cmpmem(cursor, serialized_y, sizeof(ec_public_key_t));
  cursor += sizeof(ec_public_key_t);

  uint8_t serialized_b[DH3072_MOD_LEN_BYTES] = {0};
  size_t mpi_len = dh_mpi_serialize(serialized_b, DH3072_MOD_LEN_BYTES, data_msg->our_dh);
  //Skip first 4 because they are the size (mpi_len)
  otrv4_assert_cmpmem(cursor+4, serialized_b, mpi_len);

  cursor += 4+mpi_len;

  otrv4_assert_cmpmem(cursor, data_msg->nonce, DATA_MSG_NONCE_BYTES);
  cursor += DATA_MSG_NONCE_BYTES;

  uint8_t expected_enc[7] = {
    0x0, 0x0, 0x0, 0x3,
    0xE, 0xE, 0xE,
  };
  otrv4_assert_cmpmem(cursor, expected_enc, 7);

  dh_keypair_destroy(dh);
  ec_keypair_destroy(ecdh);
  data_message_free(data_msg);
  free(serialized);
  dh_free();
}
