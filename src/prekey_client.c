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

#include "prekey_client.h"
#include "random.h"
#include "serialize.h"

#include <libotr/b64.h>

API otrng_prekey_client_s *
otrng_prekey_client_new(uint32_t instance_tag,
                        const client_profile_s *profile) {
  otrng_prekey_client_s *ret = malloc(sizeof(otrng_prekey_client_s));
  if (!ret) {
    return NULL;
  }

  if (!instance_tag) {
    return NULL;
  }

  if (!profile) {
    return NULL;
  }

  ret->instance_tag = instance_tag;
  ret->client_profile = profile;
  otrng_ecdh_keypair_destroy(ret->ephemeral_ecdh);

  return ret;
}

API void otrng_prekey_client_free(otrng_prekey_client_s *client) {
  if (!client) {
    return;
  }

  otrng_ecdh_keypair_destroy(client->ephemeral_ecdh);
  client->client_profile = NULL;
}

#define OTRNG_PREKEY_DAKE1_MSG 0x35

INTERNAL
otrng_err
otrng_prekey_dake1_message_asprint(uint8_t **serialized, size_t *serialized_len,
                                   const otrng_prekey_dake1_message_s *msg) {

  uint8_t *client_profile_buff = NULL;
  size_t client_profile_buff_len = 0;
  if (!otrng_client_profile_asprintf(&client_profile_buff,
                                     &client_profile_buff_len,
                                     msg->client_profile)) {
    return OTRNG_ERROR;
  }

  size_t ret_len = 2 + 1 + 4 + client_profile_buff_len + ED448_POINT_BYTES;
  uint8_t *ret = malloc(ret_len);
  if (!ret) {
    free(client_profile_buff);
    return OTRNG_ERROR;
  }

  size_t w = 0;
  w += otrng_serialize_uint16(ret + w, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(ret + w, OTRNG_PREKEY_DAKE1_MSG);
  w += otrng_serialize_uint32(ret + w, msg->client_instance_tag);
  w += otrng_serialize_bytes_array(ret + w, client_profile_buff,
                                   client_profile_buff_len);
  w += otrng_serialize_ec_point(ret + w, msg->I);
  free(client_profile_buff);

  if (serialized_len) {
    *serialized_len = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL
void otrng_prekey_dake1_message_destroy(otrng_prekey_dake1_message_s *msg) {}

static char *prekey_encode(const uint8_t *buffer, size_t buffer_len) {
  size_t base64_len = ((buffer_len + 2) / 3) * 4;
  char *ret = malloc(base64_len + 2);
  if (!ret) {
    return NULL;
  }

  otrl_base64_encode(ret, buffer, buffer_len);
  ret[base64_len + 1] = '.';
  ret[base64_len + 2] = 0;

  return ret;
}

static otrng_err prekey_decode(const char *message, uint8_t **buffer,
                               size_t *buffer_len) {
  size_t l = strlen(message);

  if ('.' != message[l]) {
    return OTRNG_ERROR;
  }

  *buffer = malloc(((l - 1 + 3) / 4) * 3);
  if (!*buffer) {
    return OTRNG_ERROR;
  }

  *buffer_len = otrl_base64_decode(*buffer, message, l - 1);
  return OTRNG_SUCCESS;
}

static char *start_dake_and_then_send(otrng_prekey_client_s *client,
                                      otrng_prekey_next_message_t next) {
  otrng_prekey_dake1_message_s msg[1];
  msg->client_instance_tag = client->instance_tag;
  otrng_client_profile_copy(msg->client_profile, client->client_profile);

  otrng_ecdh_keypair_destroy(client->ephemeral_ecdh);

  uint8_t sym[ED448_PRIVATE_BYTES] = {0};
  random_bytes(sym, ED448_PRIVATE_BYTES);
  otrng_ecdh_keypair_generate(client->ephemeral_ecdh, sym);
  goldilocks_bzero(sym, ED448_PRIVATE_BYTES);
  otrng_ec_point_copy(msg->I, client->ephemeral_ecdh->pub);

  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
  otrng_err success =
      otrng_prekey_dake1_message_asprint(&serialized, &serialized_len, msg);
  otrng_prekey_dake1_message_destroy(msg);

  if (!success) {
    return NULL;
  }

  char *ret = prekey_encode(serialized, serialized_len);
  free(serialized);

  client->after_dake = next;
  return ret;
}

API char *
otrng_prekey_client_request_storage_status(otrng_prekey_client_s *client) {
  return start_dake_and_then_send(client,
                                  OTRNG_PREKEY_STORAGE_INFORMATION_REQUEST);
}

static char *receive_decoded(otrng_prekey_client_s *client,
                             const uint8_t *decoded, size_t decoded_len) {
  return NULL;
}

API char *otrng_prekey_client_receive(otrng_prekey_client_s *client,
                                      const char *message) {
  uint8_t *serialized = NULL;
  size_t serialized_len = 0;

  if (!prekey_decode(message, &serialized, &serialized_len)) {
    return NULL;
  }

  return receive_decoded(client, serialized, serialized_len);
}
