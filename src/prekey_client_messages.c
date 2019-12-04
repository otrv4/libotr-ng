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

#include <assert.h>

#include <sodium.h>

#include "alloc.h"
#include "deserialize.h"
#include "prekey_client_messages.h"
#include "prekey_client_shared.h"
#include "serialize.h"
#include "shake.h"

static const char *prekey_hash_domain = "OTR-Prekey-Server";

static void kdf_init_with_usage(goldilocks_shake256_ctx_p hash, uint8_t usage) {
  /* This can't actually fail, so we ignore the result */
  (void)hash_init_with_usage_and_domain_separation(hash, usage,
                                                   prekey_hash_domain);
}

INTERNAL void otrng_prekey_ensemble_query_retrieval_message_serialize(
    /*@notnull@*/ uint8_t **dst, /*@notnull@*/ size_t *len,
    /*@notnull@*/ const otrng_prekey_ensemble_query_retrieval_message_s *msg) {
  size_t w = 0;

  assert(len);
  assert(dst);

  *len = 2 + 1 + 4 + (4 + strlen(msg->identity)) +
         (4 + otrng_strlen_ns(msg->versions));
  *dst = otrng_xmalloc(*len);

  w += otrng_serialize_uint16(*dst, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(*dst + w,
                             OTRNG_PREKEY_ENSEMBLE_QUERY_RETRIEVAL_MSG);
  w += otrng_serialize_uint32(*dst + w, msg->instance_tag);
  w += otrng_serialize_data(*dst + w, (uint8_t *)msg->identity,
                            strlen(msg->identity));
  w += otrng_serialize_data(*dst + w, (uint8_t *)msg->versions,
                            otrng_strlen_ns(msg->versions));
  assert(w == *len);
}

INTERNAL void otrng_prekey_ensemble_query_retrieval_message_destroy(
    /*@notnull@*/ otrng_prekey_ensemble_query_retrieval_message_s *msg) {
  assert(msg);

  otrng_free(msg->identity);
  msg->identity = NULL;

  otrng_free(msg->versions);
  msg->versions = NULL;
}

INTERNAL otrng_prekey_publication_message_s *
otrng_prekey_publication_message_new() {
  return otrng_xmalloc_z(sizeof(otrng_prekey_publication_message_s));
}

INTERNAL void otrng_prekey_publication_message_destroy(
    otrng_prekey_publication_message_s *msg) {
  int i;

  if (!msg) {
    return;
  }

  if (msg->prekey_messages) {
    for (i = 0; i < msg->num_prekey_messages; i++) {
      otrng_prekey_message_free(msg->prekey_messages[i]);
    }

    otrng_free(msg->prekey_messages);
    msg->prekey_messages = NULL;
  }

  otrng_client_profile_free(msg->client_profile);
  msg->client_profile = NULL;

  otrng_prekey_profile_free(msg->prekey_profile);
  msg->prekey_profile = NULL;
}

INTERNAL otrng_bool otrng_prekey_storage_status_message_valid(
    const otrng_prekey_storage_status_message_s *msg,
    const uint8_t mac_key[MAC_KEY_BYTES]) {

  size_t bufl = 1 + 4 + 4;
  uint8_t *buf = otrng_xmalloc_z(bufl);
  uint8_t mac_tag[HASH_BYTES];
  uint8_t usage_status_MAC = 0x0B;
  goldilocks_shake256_ctx_p hmac;

  *buf = OTRNG_PREKEY_STORAGE_STATUS_MSG; /* message type */
  if (otrng_serialize_uint32(buf + 1, msg->client_instance_tag) == 0) {
    otrng_free(buf);
    return otrng_false;
  }

  if (otrng_serialize_uint32(buf + 5, msg->stored_prekeys) == 0) {
    otrng_free(buf);
    return otrng_false;
  }

  /* KDF(usage_status_MAC, prekey_mac_k || message type || receiver instance
   tag
   || Stored Prekey Messages Number, 64) */
  kdf_init_with_usage(hmac, usage_status_MAC);

  if (hash_update(hmac, mac_key, MAC_KEY_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hmac);
    otrng_free(buf);
    return otrng_false;
  }

  if (hash_update(hmac, buf, bufl) == GOLDILOCKS_FAILURE) {
    hash_destroy(hmac);
    otrng_free(buf);
    return otrng_false;
  }

  hash_final(hmac, mac_tag, HASH_BYTES);
  hash_destroy(hmac);

  otrng_free(buf);

  if (sodium_memcmp(mac_tag, msg->mac, HASH_BYTES) != 0) {
    otrng_secure_wipe(mac_tag, HASH_BYTES);
    return otrng_false;
  }

  return otrng_true;
}

INTERNAL otrng_result otrng_prekey_storage_status_message_deserialize(
    otrng_prekey_storage_status_message_s *dst, const uint8_t *ser,
    size_t ser_len) {
  size_t w = 0;
  size_t read = 0;

  uint8_t msg_type = 0;

  if (!otrng_prekey_parse_header(&msg_type, ser, ser_len, &w)) {
    return OTRNG_ERROR;
  }

  if (msg_type != OTRNG_PREKEY_STORAGE_STATUS_MSG) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->client_instance_tag, ser + w, ser_len - w,
                                &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_uint32(&dst->stored_prekeys, ser + w, ser_len - w,
                                &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_bytes_array(dst->mac, DATA_MSG_MAC_BYTES, ser + w,
                                     ser_len - w)) {
    return OTRNG_ERROR;
  }

  w += DATA_MSG_MAC_BYTES;

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_prekey_storage_status_message_destroy(
    otrng_prekey_storage_status_message_s *msg) {
  if (!msg) {
    return;
  }

  msg->client_instance_tag = 0;
  msg->stored_prekeys = 0;
  otrng_secure_wipe(msg->mac, DATA_MSG_MAC_BYTES);
}

INTERNAL otrng_result otrng_prekey_ensemble_retrieval_message_deserialize(
    otrng_prekey_ensemble_retrieval_message_s *dst, const uint8_t *ser,
    size_t ser_len) {
  size_t w = 0;
  size_t read = 0;
  uint8_t l = 0;
  uint8_t *tmp_buf = NULL;
  size_t tmp_read = 0;

  uint8_t msg_type = 0;

  int i;

  if (!otrng_prekey_parse_header(&msg_type, ser, ser_len, &w)) {
    return OTRNG_ERROR;
  }

  if (msg_type != OTRNG_PREKEY_ENSEMBLE_RETRIEVAL_MSG) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->instance_tag, ser + w, ser_len - w,
                                &read)) {
    return OTRNG_ERROR;
  }
  w += read;

  if (!otrng_deserialize_data(&tmp_buf, &tmp_read, ser + w, ser_len - w,
                              &read)) {
    return OTRNG_ERROR;
  }
  w += read;
  dst->identity = otrng_xmalloc_z((tmp_read + 1) * sizeof(uint8_t));
  memcpy(dst->identity, tmp_buf, tmp_read);
  otrng_free(tmp_buf);

  if (!otrng_deserialize_uint8(&l, ser + w, ser_len - w, &read)) {
    return OTRNG_ERROR;
  }
  w += read;

  dst->ensembles = otrng_xmalloc_z(sizeof(prekey_ensemble_s *) * l);

  dst->num_ensembles = l;

  for (i = 0; i < l; i++) {
    dst->ensembles[i] = otrng_prekey_ensemble_new();

    if (!otrng_prekey_ensemble_deserialize(dst->ensembles[i], ser + w,
                                           ser_len - w, &read)) {
      return OTRNG_ERROR;
    }

    w += read;
  }

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_prekey_ensemble_retrieval_message_destroy(
    otrng_prekey_ensemble_retrieval_message_s *msg) {
  int i;

  if (!msg) {
    return;
  }

  otrng_free(msg->identity);

  if (msg->ensembles) {
    for (i = 0; i < msg->num_ensembles; i++) {
      otrng_prekey_ensemble_free(msg->ensembles[i]);
    }
    otrng_free(msg->ensembles);
  }

  msg->ensembles = NULL;
}

INTERNAL otrng_result otrng_prekey_success_message_deserialize(
    otrng_prekey_success_message_s *destination, const uint8_t *source,
    size_t source_len) {
  const uint8_t *cursor = source;
  int64_t len = source_len;
  size_t read = 0;
  uint8_t message_type = 0;

  uint16_t protocol_version = 0;
  if (!otrng_deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (protocol_version != OTRNG_PROTOCOL_VERSION_4) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint8(&message_type, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (message_type != OTRNG_PREKEY_SUCCESS_MSG) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&destination->client_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  return otrng_deserialize_bytes_array(destination->mac, HASH_BYTES, cursor,
                                       len);
}
