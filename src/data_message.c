#include "data_message.h"
#include "serialize.h"
#include "constants.h"

data_message_t*
data_message_new() {
  data_message_t *ret = malloc(sizeof(data_message_t));
  if (ret == NULL)
    return NULL;

  ret->flags = 0;
  ret->enc_msg = NULL;
  ret->enc_msg_len = 0;
  ret->old_mac_keys = NULL;
  ret->old_mac_keys_len = 0;
  return ret;
}

void
data_message_free(data_message_t *data_msg) {
  if (data_msg == NULL)
    return;

  data_msg->enc_msg_len = 0;
  free(data_msg->enc_msg);
  data_msg->enc_msg = NULL;

  data_msg->old_mac_keys = 0;
  free(data_msg->old_mac_keys);
  data_msg->old_mac_keys = NULL;
}

bool
data_message_body_aprint(uint8_t **body, size_t *bodylen, const data_message_t *data_msg) {
  size_t s = DATA_MESSAGE_MIN_BYTES+data_msg->enc_msg_len;
  uint8_t *dst = malloc(s);
  if (dst == NULL)
    return false;

  uint8_t *cursor = dst;
  cursor += serialize_uint16(cursor, OTR_VERSION);
  cursor += serialize_uint8(cursor, OTR_DATA_MSG_TYPE);
  cursor += serialize_uint32(cursor, data_msg->sender_instance_tag);
  cursor += serialize_uint32(cursor, data_msg->receiver_instance_tag);
  cursor += serialize_uint8(cursor, data_msg->flags);
  cursor += serialize_uint32(cursor, data_msg->ratchet_id);
  cursor += serialize_uint32(cursor, data_msg->message_id);
  cursor += serialize_ec_public_key(cursor, data_msg->our_ecdh);
  cursor += serialize_dh_public_key(cursor, data_msg->our_dh);
  cursor += serialize_bytes_array(cursor, data_msg->nonce, DATA_MSG_NONCE_BYTES);
  cursor += serialize_data(cursor, data_msg->enc_msg, data_msg->enc_msg_len);

  *body = dst;
  *bodylen = s;

  return true;
}
