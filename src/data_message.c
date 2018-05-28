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

#include <libotr/mem.h>

#define OTRNG_DATA_MESSAGE_PRIVATE

#include "data_message.h"
#include "deserialize.h"
#include "serialize.h"
#include "shake.h"

// TODO: add j, i, k, pn here
INTERNAL data_message_s *otrng_data_message_new() {
  data_message_s *ret = malloc(sizeof(data_message_s));
  if (!ret)
    return NULL;

  ret->flags = 0;
  ret->enc_msg = NULL;
  ret->enc_msg_len = 0;

  ret->dh = NULL;
  otrng_ec_bzero(ret->ecdh, ED448_POINT_BYTES);

  memset(ret->nonce, 0, sizeof ret->nonce);
  memset(ret->mac, 0, sizeof ret->mac);

  return ret;
}

tstatic void data_message_destroy(data_message_s *data_msg) {
  data_msg->flags = 0;

  otrng_ec_point_destroy(data_msg->ecdh);
  otrng_dh_mpi_release(data_msg->dh);
  data_msg->dh = NULL;

  sodium_memzero(data_msg->nonce, sizeof data_msg->nonce);
  data_msg->enc_msg_len = 0;
  // TODO: check if this free is always needed
  free(data_msg->enc_msg);
  data_msg->enc_msg = NULL;
  sodium_memzero(data_msg->mac, sizeof data_msg->mac);
}

INTERNAL void otrng_data_message_free(data_message_s *data_msg) {
  if (!data_msg)
    return;

  data_message_destroy(data_msg);

  free(data_msg);
  data_msg = NULL;
}

INTERNAL otrng_err otrng_data_message_body_asprintf(
    uint8_t **body, size_t *bodylen, const data_message_s *data_msg) {
  // TODO: why is DH_MPI_BYTES + 4 not on the DATA_MESSAGE_MIN_BYTES const?
  size_t s = DATA_MESSAGE_MIN_BYTES + DH_MPI_BYTES + 4 + data_msg->enc_msg_len;
  uint8_t *dst = malloc(s);
  if (!dst)
    return ERROR;

  uint8_t *cursor = dst;
  cursor += otrng_serialize_uint16(cursor, VERSION);
  cursor += otrng_serialize_uint8(cursor, DATA_MSG_TYPE);
  cursor += otrng_serialize_uint32(cursor, data_msg->sender_instance_tag);
  cursor += otrng_serialize_uint32(cursor, data_msg->receiver_instance_tag);
  cursor += otrng_serialize_uint8(cursor, data_msg->flags);
  cursor += otrng_serialize_uint32(cursor, data_msg->previous_chain_n);
  cursor += otrng_serialize_uint32(cursor, data_msg->ratchet_id);
  cursor += otrng_serialize_uint32(cursor, data_msg->message_id);
  cursor += otrng_serialize_ec_point(cursor, data_msg->ecdh);

  // TODO: This could be NULL. We need to test.
  size_t len = 0;
  if (!otrng_serialize_dh_public_key(cursor, (s - (cursor - dst)), &len,
                                     data_msg->dh)) {
    free(dst);
    dst = NULL;
    return ERROR;
  }
  cursor += len;
  cursor += otrng_serialize_bytes_array(cursor, data_msg->nonce,
                                        DATA_MSG_NONCE_BYTES);
  cursor +=
      otrng_serialize_data(cursor, data_msg->enc_msg, data_msg->enc_msg_len);

  if (body)
    *body = dst;

  if (bodylen)
    *bodylen = cursor - dst;

  return SUCCESS;
}

INTERNAL otrng_err otrng_data_message_deserialize(data_message_s *dst,
                                                  const uint8_t *buff,
                                                  size_t bufflen,
                                                  size_t *nread) {
  const uint8_t *cursor = buff;
  int64_t len = bufflen;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (!otrng_deserialize_uint16(&protocol_version, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (protocol_version != VERSION)
    return ERROR;

  uint8_t message_type = 0;
  if (!otrng_deserialize_uint8(&message_type, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (message_type != DATA_MSG_TYPE)
    return ERROR;

  if (!otrng_deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (!otrng_deserialize_uint32(&dst->receiver_instance_tag, cursor, len,
                                &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (!otrng_deserialize_uint8(&dst->flags, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (!otrng_deserialize_uint32(&dst->previous_chain_n, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (!otrng_deserialize_uint32(&dst->ratchet_id, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (!otrng_deserialize_uint32(&dst->message_id, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (!otrng_deserialize_ec_point(dst->ecdh, cursor))
    return ERROR;

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  otrng_mpi_p b_mpi; // no need to free, because nothing is copied now
  if (!otrng_mpi_deserialize_no_copy(b_mpi, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  // TODO: If the DH key is absent the MPI will have a zero length, per spec.
  // We need to test what otrng_dh_mpi_deserialize does when b_mpi->data is
  // NULL.

  if (!otrng_dh_mpi_deserialize(&dst->dh, b_mpi->data, b_mpi->len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (!otrng_deserialize_bytes_array(dst->nonce, DATA_MSG_NONCE_BYTES, cursor,
                                     len))
    return ERROR;

  cursor += DATA_MSG_NONCE_BYTES;
  len -= DATA_MSG_NONCE_BYTES;

  if (!otrng_deserialize_data(&dst->enc_msg, cursor, len, &read))
    return ERROR;

  dst->enc_msg_len = read - 4;
  cursor += read;
  len -= read;

  return otrng_deserialize_bytes_array((uint8_t *)&dst->mac, DATA_MSG_MAC_BYTES,
                                       cursor, len);
}

INTERNAL static otrng_err otrng_data_message_sections_hash(uint8_t *dst,
                                                           size_t dstlen,
                                                           const uint8_t *body,
                                                           size_t bodylen) {
  if (dstlen < 64)
    return ERROR;

  // KDF_1(0x1B || data_message_sections, 64)
  shake_256_kdf1(dst, 64, 0x1B, body, bodylen);

  return SUCCESS;
}

INTERNAL otrng_err otrng_data_message_authenticator(uint8_t *dst, size_t dstlen,
                                                    const m_mac_key_p mac_key,
                                                    const uint8_t *body,
                                                    size_t bodylen) {
  if (dstlen < DATA_MSG_MAC_BYTES)
    return ERROR;

  // Authenticator = KDF_1(0x1C || MKmac || KDF_1(0x1B || data_message_sections,
  // 64), 64)
  uint8_t sections[64];
  if (!otrng_data_message_sections_hash(sections, 64, body, bodylen))
    return ERROR;

  goldilocks_shake256_ctx_p auth_hash;
  hash_init_with_usage(auth_hash, 0x1C);
  hash_update(auth_hash, mac_key, sizeof(m_mac_key_p));
  hash_update(auth_hash, sections, 64);
  sodium_memzero(sections, 64);

  hash_final(auth_hash, dst, DATA_MSG_MAC_BYTES);
  return SUCCESS;
}

INTERNAL otrng_bool otrng_valid_data_message(m_mac_key_p mac_key,
                                             const data_message_s *data_msg) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  if (!otrng_data_message_body_asprintf(&body, &bodylen, data_msg)) {
    return otrng_false;
  }

  uint8_t mac_tag[DATA_MSG_MAC_BYTES];
  otrng_err ret = otrng_data_message_authenticator(mac_tag, sizeof mac_tag,
                                                   mac_key, body, bodylen);

  free(body);
  body = NULL;

  if (ret == ERROR)
    return otrng_false;

  if (otrl_mem_differ(mac_tag, data_msg->mac, sizeof mac_tag) != 0) {
    sodium_memzero(mac_tag, sizeof mac_tag);
    return otrng_false;
  }

  if (!otrng_ec_point_valid(data_msg->ecdh))
    return otrng_false;

  if (!data_msg->dh)
    return otrng_true;

  return otrng_dh_mpi_valid(data_msg->dh);
}
