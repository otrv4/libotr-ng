/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
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

#include "protocol.h"

#include "data_message.h"
#include "debug.h"
#include "messaging.h"
#include "padding.h"
#include "random.h"
#include "serialize.h"

#ifndef S_SPLINT_S
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <libotr/b64.h>
#pragma clang diagnostic pop
#endif

INTERNAL void maybe_create_keys(otrng_client_s *client) {
  const otrng_client_callbacks_s *cb = client->global_state->callbacks;
  uint32_t instance_tag;

  instance_tag = otrng_client_get_instance_tag(client);
  if (!instance_tag) {
    otrng_client_callbacks_create_instag(cb, client);
  }
}

INTERNAL struct goldilocks_448_point_s *our_ecdh(const otrng_s *otr) {
  return &otr->keys->our_ecdh->pub[0];
}

INTERNAL dh_public_key our_dh(const otrng_s *otr) {
  return otr->keys->our_dh->pub;
}

INTERNAL struct goldilocks_448_point_s *our_ecdh_first(const otrng_s *otr) {
  return &otr->keys->our_ecdh_first->pub[0];
}

INTERNAL dh_public_key our_dh_first(const otrng_s *otr) {
  return otr->keys->our_dh_first->pub;
}

INTERNAL const otrng_client_profile_s *get_my_client_profile(otrng_s *otr) {
  otrng_client_s *client = otr->client;
  maybe_create_keys(client);

  return otrng_client_get_client_profile(client);
}

INTERNAL const otrng_client_profile_s *get_my_exp_client_profile(otrng_s *otr) {
  otrng_client_s *client = otr->client;

  return otrng_client_get_exp_client_profile(client);
}

INTERNAL const otrng_prekey_profile_s *get_my_prekey_profile(otrng_s *otr) {
  otrng_client_s *client = otr->client;

  maybe_create_keys(client);

  return otrng_client_get_prekey_profile(client);
}

INTERNAL const otrng_prekey_profile_s *get_my_exp_prekey_profile(otrng_s *otr) {
  otrng_client_s *client = otr->client;

  return otrng_client_get_exp_prekey_profile(client);
}

INTERNAL uint32_t our_instance_tag(const otrng_s *otr) {
  return otrng_client_get_instance_tag(otr->client);
}

static char *build_error_message(const char *error_code,
                                 const char *error_name) {
  size_t prefix_len = strlen(ERROR_PREFIX);
  size_t size = prefix_len + strlen(error_code) + strlen(error_name) + 1;
  char *err_msg = otrng_xmalloc(size);

  strncpy(err_msg, ERROR_PREFIX, size);
  strncpy(err_msg + prefix_len, error_code, size - prefix_len);
  strncat(err_msg, error_name, size - prefix_len);

  return err_msg;
}

INTERNAL void otrng_error_message(string_p *to_send, otrng_err_code err_code) {
  switch (err_code) {
  case OTRNG_ERR_MSG_NONE:
    break;
  case OTRNG_ERR_MSG_UNREADABLE:
    *to_send = build_error_message(ERROR_CODE_1, "OTRNG_ERR_MSG_UNREADABLE");
    break;
  case OTRNG_ERR_MSG_NOT_PRIVATE:
    *to_send =
        build_error_message(ERROR_CODE_2, "OTRNG_ERR_MSG_NOT_PRIVATE_STATE");
    break;
  case OTRNG_ERR_MSG_MALFORMED:
    *to_send = build_error_message(ERROR_CODE_3, "OTRNG_ERR_MALFORMED");
    break;
  default:
    break;
  }
}

tstatic otrng_result encrypt_data_message(data_message_s *data_msg,
                                          const uint8_t *msg, size_t msg_len,
                                          const k_msg_enc enc_key) {
  uint8_t *c = NULL;
  uint8_t actual_enc_key[ENC_ACTUAL_KEY_BYTES];
  int err;

  random_bytes(data_msg->nonce, DATA_MSG_NONCE_BYTES);

  c = otrng_xmalloc_z(msg_len);

  memcpy(actual_enc_key, enc_key, ENC_ACTUAL_KEY_BYTES);

  err = crypto_stream_xor(c, msg, msg_len, data_msg->nonce, actual_enc_key);
  otrng_secure_wipe(actual_enc_key, ENC_ACTUAL_KEY_BYTES);

  if (err) {
    otrng_free(c);
    return OTRNG_ERROR;
  }

  data_msg->enc_msg_len = msg_len;
  data_msg->enc_msg = c;

#ifdef DEBUG
  debug_print("\n");
  debug_print("nonce = ");
  otrng_memdump(data_msg->nonce, DATA_MSG_NONCE_BYTES);
  debug_print("message = ");
  otrng_memdump(msg, msg_len);
  debug_print("cipher = ");
  otrng_memdump(c, msg_len);
#endif

  return OTRNG_SUCCESS;
}

/*@null@*/ tstatic data_message_s *
generate_data_message(const otrng_s *otr, const uint32_t ratchet_id) {
  data_message_s *data_msg = otrng_data_message_new();
  if (!data_msg) {
    return NULL;
  }

  data_msg->sender_instance_tag = our_instance_tag(otr);
  data_msg->receiver_instance_tag = otr->their_instance_tag;
  data_msg->previous_chain_n = otr->keys->pn;
  data_msg->ratchet_id = ratchet_id;
  data_msg->message_id = otr->keys->j;
  otrng_ec_point_copy(data_msg->ecdh, our_ecdh(otr));
  data_msg->dh = otrng_dh_mpi_copy(our_dh(otr));

  return data_msg;
}

tstatic otrng_result serialize_and_encode_data_message(
    string_p *dst, const k_msg_mac mac_key, uint8_t *to_reveal_mac_keys,
    size_t to_reveal_mac_keys_len, const data_message_s *data_msg) {
  uint8_t *body = NULL;
  size_t body_len = 0;
  size_t ser_len;
  uint8_t *ser;

  if (!otrng_data_message_body_serialize(&body, &body_len, data_msg)) {
    return OTRNG_ERROR;
  }

  ser_len = body_len + MAC_KEY_BYTES + to_reveal_mac_keys_len;

  ser = otrng_xmalloc_z(ser_len);

  memcpy(ser, body, body_len);
  otrng_free(body);

  if (otrng_failed(otrng_data_message_authenticator(
          ser + body_len, MAC_KEY_BYTES, mac_key, ser, body_len))) {
    otrng_free(ser);
    return OTRNG_ERROR;
  }

  if (to_reveal_mac_keys) {
    if (otrng_serialize_bytes_array(ser + body_len + DATA_MSG_MAC_BYTES,
                                    to_reveal_mac_keys,
                                    to_reveal_mac_keys_len) == 0) {
      otrng_free(ser);
      return OTRNG_ERROR;
    }
  }

  *dst = otrl_base64_otr_encode(ser, ser_len);

  otrng_free(ser);
  return OTRNG_SUCCESS;
}

tstatic otrng_result send_data_message(string_p *to_send, const uint8_t *msg,
                                       size_t msg_len, otrng_s *otr,
                                       unsigned char flags) {
  data_message_s *data_msg = NULL;
  uint32_t ratchet_id = otr->keys->i;
  k_msg_enc enc_key;
  k_msg_mac mac_key;

  /* if j == 0 */
  if (!otrng_key_manager_derive_dh_ratchet_keys(
          otr->keys, otr->client->max_stored_msg_keys, NULL, NULL, 0, 's',
          otr->client->global_state->callbacks)) {
    return OTRNG_ERROR;
  }

  memset(enc_key, 0, ENC_KEY_BYTES);
  memset(mac_key, 0, MAC_KEY_BYTES);

  if (!otrng_key_manager_derive_chain_keys(
          enc_key, mac_key, otr->keys, NULL, otr->client->max_stored_msg_keys,
          0, 's', otr->client->global_state->callbacks)) {
    return OTRNG_ERROR;
  }

  data_msg = generate_data_message(otr, ratchet_id);
  if (!data_msg) {
    otrng_secure_wipe(enc_key, ENC_KEY_BYTES);
    otrng_secure_wipe(mac_key, MAC_KEY_BYTES);
    return OTRNG_ERROR;
  }

  data_msg->flags = flags;
  data_msg->sender_instance_tag = our_instance_tag(otr);
  data_msg->receiver_instance_tag = otr->their_instance_tag;

  if (!encrypt_data_message(data_msg, msg, msg_len, enc_key)) {
    otrng_secure_wipe(enc_key, ENC_KEY_BYTES);
    otrng_secure_wipe(mac_key, MAC_KEY_BYTES);
    otrng_data_message_free(data_msg);
    return OTRNG_ERROR;
  }

  otrng_secure_wipe(enc_key, ENC_KEY_BYTES);

  /* Authenticator = KDF_1(0x1A || MKmac || KDF_1(usage_authenticator ||
   * data_message_sections, 64), 64) */
  if (otr->keys->j == 0) {
    size_t ser_mac_keys_len =
        otrng_list_len(otr->keys->old_mac_keys) * MAC_KEY_BYTES;
    uint8_t *ser_mac_keys =
        otrng_serialize_old_mac_keys(otr->keys->old_mac_keys);
    otr->keys->old_mac_keys = NULL;

    if (!serialize_and_encode_data_message(to_send, mac_key, ser_mac_keys,
                                           ser_mac_keys_len, data_msg)) {
      otrng_secure_wipe(mac_key, MAC_KEY_BYTES);
      otrng_free(ser_mac_keys);
      otrng_data_message_free(data_msg);

      return OTRNG_ERROR;
    }
    otrng_free(ser_mac_keys);
  } else {
    if (!serialize_and_encode_data_message(to_send, mac_key, NULL, 0,
                                           data_msg)) {
      otrng_secure_wipe(mac_key, MAC_KEY_BYTES);
      otrng_data_message_free(data_msg);
      return OTRNG_ERROR;
    }
  }

  otr->keys->j++;

  otrng_secure_wipe(mac_key, MAC_KEY_BYTES);
  otrng_data_message_free(data_msg);

  return OTRNG_SUCCESS;
}

tstatic otrng_result serialize_tlvs(uint8_t **dst, size_t *dst_len,
                                    const tlv_list_s *tlvs) {
  const tlv_list_s *current = tlvs;
  uint8_t *cursor = NULL;

  *dst = NULL;
  *dst_len = 0;

  if (!tlvs) {
    return OTRNG_SUCCESS;
  }

  for (*dst_len = 0; current; current = current->next) {
    *dst_len += current->data->len + 4;
  }

  *dst = otrng_xmalloc_z(*dst_len);

  cursor = *dst;
  for (current = tlvs; current; current = current->next) {
    cursor += otrng_tlv_serialize(cursor, current->data);
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result append_tlvs(uint8_t **dst, size_t *dst_len,
                                 const string_p msg, const tlv_list_s *tlvs,
                                 const otrng_s *otr) {
  uint8_t *ser = NULL;
  size_t len = 0;
  size_t msg_len;
  uint8_t *padding = NULL;
  size_t padding_len = 0;
  char *res;

  if (!serialize_tlvs(&ser, &len, tlvs)) {
    return OTRNG_ERROR;
  }

  /* Append padding */
  msg_len = strlen(msg) + 1 + len;
  if (!generate_padding(&padding, &padding_len, msg_len, otr)) {
    otrng_free(ser);
    return OTRNG_ERROR;
  }

  *dst_len = msg_len + padding_len;
  *dst = otrng_xmalloc_z(*dst_len);

  res = otrng_stpcpy((char *)*dst, msg);
  if (ser) {
    memcpy(res + 1, ser, len);
  }

  if (padding) {
    memcpy(*dst + msg_len, padding, padding_len);
  }

  otrng_free(ser);
  otrng_free(padding);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_prepare_to_send_data_message(string_p *to_send,
                                                         const string_p msg,
                                                         const tlv_list_s *tlvs,
                                                         otrng_s *otr,
                                                         unsigned char flags) {
  uint8_t *msg2 = NULL;
  size_t msg_len = 0;
  otrng_result result;

  if (otr->state == OTRNG_STATE_FINISHED) {
    otrng_client_callbacks_handle_event(otr->client->global_state->callbacks,
                                        OTRNG_MSG_EVENT_CONNECTION_ENDED);
    return OTRNG_ERROR; /* Should restart */
  }

  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    otrng_client_callbacks_handle_event(
        otr->client->global_state->callbacks,
        OTRNG_MSG_EVENT_SENDING_NOT_IN_ENCRYPTED_STATE); // TODO: queue the
                                                         // message
    return OTRNG_ERROR;
  }

  if (!append_tlvs(&msg2, &msg_len, msg, tlvs, otr)) {
    return OTRNG_ERROR;
  }

  result = send_data_message(to_send, msg2, msg_len, otr, flags);
  if (result == OTRNG_ERROR) {
    otrng_client_callbacks_handle_event(otr->client->global_state->callbacks,
                                        OTRNG_MSG_EVENT_ENCRYPTION_ERROR);
    otrng_free(msg2);

    return OTRNG_ERROR;
  }

  otr->last_sent = time(NULL);

  otrng_free(msg2);

  return OTRNG_SUCCESS;
}
