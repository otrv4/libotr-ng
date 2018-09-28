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

#include "protocol.h"

#include "data_message.h"
#include "debug.h"
#include "messaging.h"
#include "padding.h"
#include "random.h"
#include "serialize.h"

#ifndef S_SPLINT_S
#include <libotr/b64.h>
#endif

INTERNAL void maybe_create_keys(otrng_client_s *client) {
  const otrng_client_callbacks_s *cb = client->global_state->callbacks;
  const otrng_client_id_s client_id = client->client_id;
  uint32_t instance_tag;

  if (!client->keypair) {
    // TODO @orchestration Remove this when orchestration is done
    fprintf(stderr, "protocol.c maybe_create_keys -> creating private key\n");
    otrng_client_callbacks_create_privkey_v4(cb, client_id);
  }

  if (!client->forging_key) {
    otrng_client_callbacks_create_forging_key(cb, client_id);
  }

  if (!client->shared_prekey_pair) {
    otrng_client_callbacks_create_shared_prekey(cb, client, client_id);
  }

  instance_tag = otrng_client_get_instance_tag(client);
  if (!instance_tag) {
    otrng_client_callbacks_create_instag(cb, client_id);
  }
}

INTERNAL struct goldilocks_448_point_s *our_ecdh(const otrng_s *otr) {
  return &otr->keys->our_ecdh->pub[0];
}

INTERNAL dh_public_key_p our_dh(const otrng_s *otr) {
  return otr->keys->our_dh->pub;
}

INTERNAL const client_profile_s *get_my_client_profile(otrng_s *otr) {
  otrng_client_s *client = otr->client;
  maybe_create_keys(client);
  return otrng_client_get_client_profile(client);
}

INTERNAL const client_profile_s *get_my_exp_client_profile(otrng_s *otr) {
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
  case OTRNG_ERR_MSG_ENCRYPTION_ERROR:
    *to_send = build_error_message(ERROR_CODE_3, "OTRNG_ERR_ENCRYPTION_ERROR");
    break;
  case OTRNG_ERR_MSG_MALFORMED:
    *to_send = build_error_message(ERROR_CODE_4, "OTRNG_ERR_MALFORMED");
    break;
  }
}

tstatic otrng_result encrypt_data_message(data_message_s *data_msg,
                                          const uint8_t *message,
                                          size_t message_len,
                                          const msg_enc_key enc_key) {
  uint8_t *c = NULL;
  int err;

  random_bytes(data_msg->nonce, sizeof(data_msg->nonce));

  c = otrng_xmalloc(message_len);

  err = crypto_stream_xor(c, message, message_len, data_msg->nonce, enc_key);
  if (err) {
    free(c);
    return OTRNG_ERROR;
  }

  data_msg->enc_msg_len = message_len;
  data_msg->enc_msg = c;

#ifdef DEBUG
  debug_print("\n");
  debug_print("nonce = ");
  otrng_memdump(data_msg->nonce, DATA_MSG_NONCE_BYTES);
  debug_print("msg = ");
  otrng_memdump(message, message_len);
  debug_print("cipher = ");
  otrng_memdump(c, message_len);
#endif

  return OTRNG_SUCCESS;
}

tstatic data_message_s *generate_data_msg(const otrng_s *otr,
                                          const uint32_t ratchet_id) {
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

tstatic otrng_result serialize_and_encode_data_msg(
    string_p *dst, const msg_mac_key mac_key, uint8_t *to_reveal_mac_keys,
    size_t to_reveal_mac_keys_len, const data_message_s *data_msg) {
  uint8_t *body = NULL;
  size_t bodylen = 0;
  size_t serlen;
  uint8_t *ser;

  if (!otrng_data_message_body_asprintf(&body, &bodylen, data_msg)) {
    return OTRNG_ERROR;
  }

  serlen = bodylen + MAC_KEY_BYTES + to_reveal_mac_keys_len;

  ser = otrng_xmalloc(serlen);

  memcpy(ser, body, bodylen);
  free(body);

  if (otrng_failed(otrng_data_message_authenticator(
          ser + bodylen, MAC_KEY_BYTES, mac_key, ser, bodylen))) {
    free(ser);
    return OTRNG_ERROR;
  }

  if (to_reveal_mac_keys) {
    otrng_serialize_bytes_array(ser + bodylen + DATA_MSG_MAC_BYTES,
                                to_reveal_mac_keys, to_reveal_mac_keys_len);
  }

  *dst = otrl_base64_otr_encode(ser, serlen);

  free(ser);
  return OTRNG_SUCCESS;
}

tstatic otrng_result send_data_message(string_p *to_send,
                                       const uint8_t *message,
                                       size_t message_len, otrng_s *otr,
                                       unsigned char flags,
                                       otrng_warning *warn) {
  data_message_s *data_msg = NULL;
  uint32_t ratchet_id = otr->keys->i;
  msg_enc_key enc_key;
  msg_mac_key mac_key;

  /* if j == 0 */
  if (!otrng_key_manager_derive_dh_ratchet_keys(
          otr->keys, otr->client->max_stored_msg_keys, NULL, otr->keys->j, 0,
          's', warn)) {
    return OTRNG_ERROR;
  }

  memset(enc_key, 0, sizeof(msg_enc_key));
  memset(mac_key, 0, sizeof(msg_mac_key));

  otrng_key_manager_derive_chain_keys(enc_key, mac_key, otr->keys, NULL,
                                      otr->client->max_stored_msg_keys, 0, 's',
                                      warn);

  data_msg = generate_data_msg(otr, ratchet_id);
  if (!data_msg) {
    otrng_secure_wipe(enc_key, sizeof(msg_enc_key));
    otrng_secure_wipe(mac_key, sizeof(msg_mac_key));
    return OTRNG_ERROR;
  }

  data_msg->flags = flags;
  data_msg->sender_instance_tag = our_instance_tag(otr);
  data_msg->receiver_instance_tag = otr->their_instance_tag;

  if (!encrypt_data_message(data_msg, message, message_len, enc_key)) {
    otrng_error_message(to_send, OTRNG_ERR_MSG_ENCRYPTION_ERROR);

    otrng_secure_wipe(enc_key, sizeof(msg_enc_key));
    otrng_secure_wipe(mac_key, sizeof(msg_mac_key));
    otrng_data_message_free(data_msg);
    return OTRNG_ERROR;
  }

  otrng_secure_wipe(enc_key, sizeof(msg_enc_key));

  /* Authenticator = KDF_1(0x1A || MKmac || KDF_1(usage_authenticator ||
   * data_message_sections, 64), 64) */
  if (otr->keys->j == 0) {
    size_t ser_mac_keys_len =
        otrng_list_len(otr->keys->old_mac_keys) * MAC_KEY_BYTES;
    uint8_t *ser_mac_keys =
        otrng_serialize_old_mac_keys(otr->keys->old_mac_keys);
    otr->keys->old_mac_keys = NULL;

    if (!serialize_and_encode_data_msg(to_send, mac_key, ser_mac_keys,
                                       ser_mac_keys_len, data_msg)) {
      otrng_secure_wipe(mac_key, sizeof(msg_mac_key));
      free(ser_mac_keys);
      otrng_data_message_free(data_msg);
      return OTRNG_ERROR;
    }
    free(ser_mac_keys);
  } else {
    if (!serialize_and_encode_data_msg(to_send, mac_key, NULL, 0, data_msg)) {
      otrng_secure_wipe(mac_key, sizeof(msg_mac_key));
      otrng_data_message_free(data_msg);
      return OTRNG_ERROR;
    }
  }

  otr->keys->j++;

  otrng_secure_wipe(mac_key, sizeof(msg_mac_key));
  otrng_data_message_free(data_msg);

  return OTRNG_SUCCESS;
}

tstatic otrng_result serialize_tlvs(uint8_t **dst, size_t *dstlen,
                                    const tlv_list_s *tlvs) {
  const tlv_list_s *current = tlvs;
  uint8_t *cursor = NULL;

  *dst = NULL;
  *dstlen = 0;

  if (!tlvs) {
    return OTRNG_SUCCESS;
  }

  for (*dstlen = 0; current; current = current->next) {
    *dstlen += current->data->len + 4;
  }

  *dst = otrng_xmalloc(*dstlen);

  cursor = *dst;
  for (current = tlvs; current; current = current->next) {
    cursor += otrng_tlv_serialize(cursor, current->data);
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result append_tlvs(uint8_t **dst, size_t *dst_len,
                                 const string_p message, const tlv_list_s *tlvs,
                                 const otrng_s *otr) {
  uint8_t *ser = NULL;
  size_t len = 0;
  size_t message_len;
  uint8_t *padding = NULL;
  size_t padding_len = 0;
  char *res;

  if (!serialize_tlvs(&ser, &len, tlvs)) {
    return OTRNG_ERROR;
  }

  // Append padding
  message_len = strlen(message) + 1 + len;
  if (!generate_padding(&padding, &padding_len, message_len, otr)) {
    free(ser);
    return OTRNG_ERROR;
  }

  *dst_len = message_len + padding_len;
  *dst = otrng_xmalloc(*dst_len);

  res = otrng_stpcpy((char *)*dst, message);
  if (ser) {
    memcpy(res + 1, ser, len);
  }

  if (padding) {
    memcpy(*dst + message_len, padding, padding_len);
  }

  free(ser);
  free(padding);
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_prepare_to_send_data_message(
    string_p *to_send, otrng_warning *warn, const string_p message,
    const tlv_list_s *tlvs, otrng_s *otr, unsigned char flags) {
  uint8_t *msg = NULL;
  size_t msg_len = 0;
  otrng_result result;

  if (otr->state == OTRNG_STATE_FINISHED) {
    return OTRNG_ERROR; // Should restart
  }

  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    if (warn) {
      *warn = OTRNG_WARN_SEND_NOT_ENCRYPTED; // TODO: @queing queue message
    }
    return OTRNG_ERROR;
  }

  if (!append_tlvs(&msg, &msg_len, message, tlvs, otr)) {
    return OTRNG_ERROR;
  }

  result = send_data_message(to_send, msg, msg_len, otr, flags, warn);

  otr->last_sent = time(NULL);

  free(msg);

  return result;
}
