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

#include "protocol.h"

#include "data_message.h"
#include "padding.h"
#include "random.h"
#include "serialize.h"
#include <libotr/b64.h>

tstatic void create_privkey_cb_v4(const otrng_conversation_state_s *conv) {
  if (!conv || !conv->client || !conv->client->callbacks) {
    return;
  }

  // TODO: @client Change to receive conv->client
  conv->client->callbacks->create_privkey(conv->client->client_id);
}

tstatic void create_shared_prekey(const otrng_conversation_state_s *conv) {
  if (!conv || !conv->client || !conv->client->callbacks) {
    return;
  }

  // TODO: @client The callback may not be invoked at all if the mode does not
  // support non-interactive DAKE, but this is for later.
  conv->client->callbacks->create_shared_prekey(conv);
}

INTERNAL void maybe_create_keys(const otrng_conversation_state_s *conv) {
  if (!conv->client->keypair) {
    create_privkey_cb_v4(conv);
  }

  if (!conv->client->shared_prekey_pair) {
    create_shared_prekey(conv);
  }

  uint32_t instance_tag = otrng_client_state_get_instance_tag(conv->client);
  if (!instance_tag) {
    // TODO: invoke callback
    // create_instance_tag(conv);
  }
}

INTERNAL struct goldilocks_448_point_s *our_ecdh(const otrng_s *otr) {
  return &otr->keys->our_ecdh->pub[0];
}

INTERNAL dh_public_key_p our_dh(const otrng_s *otr) {
  return otr->keys->our_dh->pub;
}

INTERNAL const client_profile_s *get_my_client_profile(otrng_s *otr) {
  maybe_create_keys(otr->conversation);
  otrng_client_state_s *state = otr->conversation->client;
  return otrng_client_state_get_or_create_client_profile(state);
}

INTERNAL uint32_t our_instance_tag(const otrng_s *otr) {
  return otrng_client_state_get_instance_tag(otr->conversation->client);
}

static char *build_error_message(const char *error_code,
                                 const char *error_name) {
  size_t s = strlen(ERROR_PREFIX) + strlen(error_code) + strlen(error_name) + 1;
  char *err_msg = malloc(s);
  if (!err_msg) {
    return NULL;
  }

  strcpy(err_msg, ERROR_PREFIX);
  strcpy(err_msg + strlen(ERROR_PREFIX), error_code);
  strcat(err_msg, error_name);

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

tstatic otrng_err encrypt_data_message(data_message_s *data_msg,
                                       const uint8_t *message,
                                       size_t message_len,
                                       const msg_enc_key_p enc_key) {
  uint8_t *c = NULL;

  random_bytes(data_msg->nonce, sizeof(data_msg->nonce));

  c = malloc(message_len);
  if (!c) {
    return OTRNG_ERROR;
  }

  // TODO: @c_logic message is an UTF-8 string. Is there any problem to cast
  // it to (unsigned char *)
  // encrypted_message = XSalsa20_Enc(MKenc, nonce, m)
  int err =
      crypto_stream_xor(c, message, message_len, data_msg->nonce, enc_key);
  if (err) {
    free(c);
    return OTRNG_ERROR;
  }

  data_msg->enc_msg_len = message_len;
  data_msg->enc_msg = c;

#ifdef DEBUG
  printf("\n");
  printf("nonce = ");
  otrng_memdump(data_msg->nonce, DATA_MSG_NONCE_BYTES);
  printf("msg = ");
  otrng_memdump(message, message_len);
  printf("cipher = ");
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

tstatic otrng_err serialize_and_encode_data_msg(
    string_p *dst, const msg_mac_key_p mac_key, uint8_t *to_reveal_mac_keys,
    size_t to_reveal_mac_keys_len, const data_message_s *data_msg) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  if (!otrng_data_message_body_asprintf(&body, &bodylen, data_msg)) {
    return OTRNG_ERROR;
  }

  size_t serlen = bodylen + MAC_KEY_BYTES + to_reveal_mac_keys_len;

  uint8_t *ser = malloc(serlen);
  if (!ser) {
    free(body);
    return OTRNG_ERROR;
  }

  memcpy(ser, body, bodylen);
  free(body);

  if (!otrng_data_message_authenticator(ser + bodylen, MAC_KEY_BYTES, mac_key,
                                        ser, bodylen)) {
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

tstatic otrng_err send_data_message(string_p *to_send, const uint8_t *message,
                                    size_t message_len, otrng_s *otr,
                                    unsigned char flags, otrng_notif notif) {
  data_message_s *data_msg = NULL;
  uint32_t ratchet_id = otr->keys->i;
  msg_enc_key_p enc_key;
  msg_mac_key_p mac_key;

  /* if j == 0 */
  if (!otrng_key_manager_derive_dh_ratchet_keys(
          otr->keys, otr->conversation->client->max_stored_msg_keys,
          otr->keys->j, 0, 's', notif)) {
    return OTRNG_ERROR;
  }

  memset(enc_key, 0, sizeof(msg_enc_key_p));
  memset(mac_key, 0, sizeof(msg_enc_key_p));

  otrng_key_manager_derive_chain_keys(
      enc_key, mac_key, otr->keys,
      otr->conversation->client->max_stored_msg_keys, 0, 's', notif);

  data_msg = generate_data_msg(otr, ratchet_id);
  if (!data_msg) {
    sodium_memzero(enc_key, sizeof(msg_enc_key_p));
    sodium_memzero(mac_key, sizeof(msg_mac_key_p));
    return OTRNG_ERROR;
  }

  data_msg->flags = flags;
  data_msg->sender_instance_tag = our_instance_tag(otr);
  data_msg->receiver_instance_tag = otr->their_instance_tag;

  if (!encrypt_data_message(data_msg, message, message_len, enc_key)) {
    otrng_error_message(to_send, OTRNG_ERR_MSG_ENCRYPTION_ERROR);

    sodium_memzero(enc_key, sizeof(msg_enc_key_p));
    sodium_memzero(mac_key, sizeof(msg_mac_key_p));
    otrng_data_message_free(data_msg);
    return OTRNG_ERROR;
  }

  sodium_memzero(enc_key, sizeof(msg_enc_key_p));

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
      sodium_memzero(mac_key, sizeof(msg_mac_key_p));
      free(ser_mac_keys);
      otrng_data_message_free(data_msg);
      return OTRNG_ERROR;
    }
    free(ser_mac_keys);
  } else {
    if (!serialize_and_encode_data_msg(to_send, mac_key, NULL, 0, data_msg)) {
      sodium_memzero(mac_key, sizeof(msg_mac_key_p));
      otrng_data_message_free(data_msg);
      return OTRNG_ERROR;
    }
  }

  otr->keys->j++;

  sodium_memzero(mac_key, sizeof(msg_mac_key_p));
  otrng_data_message_free(data_msg);

  return OTRNG_SUCCESS;
}

tstatic otrng_err serialize_tlvs(uint8_t **dst, size_t *dstlen,
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

  *dst = malloc(*dstlen);
  if (!*dst) {
    return OTRNG_ERROR;
  }

  cursor = *dst;
  for (current = tlvs; current; current = current->next) {
    cursor += otrng_tlv_serialize(cursor, current->data);
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_err append_tlvs(uint8_t **dst, size_t *dst_len,
                              const string_p message, const tlv_list_s *tlvs,
                              const otrng_s *otr) {
  uint8_t *ser = NULL;
  size_t len = 0;

  if (!serialize_tlvs(&ser, &len, tlvs)) {
    return OTRNG_ERROR;
  }

  // Append padding
  size_t message_len = strlen(message) + 1 + len;
  uint8_t *padding = NULL;
  size_t padding_len = 0;
  if (!generate_padding(&padding, &padding_len, message_len, otr)) {
    free(ser);
    return OTRNG_ERROR;
  }

  *dst_len = message_len + padding_len;
  *dst = malloc(*dst_len);
  if (!*dst) {
    free(ser);
    free(padding);
    return OTRNG_ERROR;
  }

  memcpy(otrng_stpcpy((char *)*dst, message) + 1, ser, len);

  if (padding) {
    memcpy(*dst + message_len, padding, padding_len);
  }

  free(ser);
  free(padding);
  return OTRNG_SUCCESS;
}

INTERNAL otrng_err otrng_prepare_to_send_data_message(
    string_p *to_send, otrng_notif notif, const string_p message,
    const tlv_list_s *tlvs, otrng_s *otr, unsigned char flags) {
  uint8_t *msg = NULL;
  size_t msg_len = 0;

  if (otr->state == OTRNG_STATE_FINISHED) {
    return OTRNG_ERROR; // Should restart
  }

  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    notif = OTRNG_NOTIF_STATE_NOT_ENCRYPTED; // TODO: @queing queue message
    return OTRNG_ERROR;
  }

  if (!append_tlvs(&msg, &msg_len, message, tlvs, otr)) {
    return OTRNG_ERROR;
  }

  otrng_err result =
      send_data_message(to_send, msg, msg_len, otr, flags, notif);

  otr->last_sent = time(NULL);

  free(msg);

  return result;
}
