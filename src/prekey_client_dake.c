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

#include <assert.h>

#include "deserialize.h"
#include "prekey_client_dake.h"
#include "prekey_client_shared.h"
#include "serialize.h"
#include "shake.h"

INTERNAL void
otrng_prekey_dake1_message_destroy(otrng_prekey_dake1_message_s *msg) {
  if (!msg) {
    return;
  }

  otrng_client_profile_destroy(msg->client_profile);
  otrng_free(msg->client_profile);
  msg->client_profile = NULL;
  otrng_ec_point_destroy(msg->I);
}

INTERNAL otrng_result otrng_prekey_dake1_message_serialize(
    uint8_t **ser, size_t *ser_len, const otrng_prekey_dake1_message_s *msg) {
  uint8_t *client_profile_buffer = NULL;
  size_t client_profile_buff_len = 0;
  size_t ret_len;
  uint8_t *ret;
  size_t w = 0;

  if (!otrng_client_profile_serialize(&client_profile_buffer,
                                      &client_profile_buff_len,
                                      msg->client_profile)) {
    return OTRNG_ERROR;
  }

  ret_len = 2 + 1 + 4 + client_profile_buff_len + ED448_POINT_BYTES;
  ret = otrng_xmalloc_z(ret_len);

  w += otrng_serialize_uint16(ret + w, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(ret + w, OTRNG_PREKEY_DAKE1_MSG);
  w += otrng_serialize_uint32(ret + w, msg->client_instance_tag);
  w += otrng_serialize_bytes_array(ret + w, client_profile_buffer,
                                   client_profile_buff_len);
  w += otrng_serialize_ec_point(ret + w, msg->I);
  otrng_free(client_profile_buffer);

  *ser = ret;
  if (ser_len) {
    *ser_len = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_prekey_dake2_message_s *otrng_prekey_dake2_message_new() {
  otrng_prekey_dake2_message_s *dake_2 =
      otrng_xmalloc_z(sizeof(otrng_prekey_dake2_message_s));
  otrng_prekey_dake2_message_init(dake_2);
  return dake_2;
}

INTERNAL void
otrng_prekey_dake2_message_init(otrng_prekey_dake2_message_s *dake_2) {
  memset(dake_2, 0, sizeof(otrng_prekey_dake2_message_s));
  dake_2->sigma = otrng_xmalloc_z(sizeof(ring_sig_s));
}

INTERNAL void
otrng_prekey_dake2_message_destroy(otrng_prekey_dake2_message_s *dake_2) {
  if (!dake_2) {
    return;
  }

  if (dake_2->composite_identity) {
    otrng_free(dake_2->composite_identity);
    dake_2->composite_identity = NULL;
  }

  if (dake_2->server_identity) {
    otrng_free(dake_2->server_identity);
    dake_2->server_identity = NULL;
  }

  otrng_ec_point_destroy(dake_2->S);
  otrng_ring_sig_destroy(dake_2->sigma);
  otrng_free(dake_2->sigma);
  dake_2->sigma = NULL;
}

INTERNAL otrng_result otrng_prekey_dake2_message_deserialize(
    otrng_prekey_dake2_message_s *dst, const uint8_t *ser, size_t ser_len) {

  size_t w = 0;
  size_t read = 0;
  uint8_t msg_type = 0;
  const uint8_t *composite_identity_start;

  if (!otrng_prekey_parse_header(&msg_type, ser, ser_len, &w)) {
    return OTRNG_ERROR;
  }

  if (msg_type != OTRNG_PREKEY_DAKE2_MSG) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->client_instance_tag, ser + w, ser_len - w,
                                &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  composite_identity_start = ser + w;
  if (!otrng_deserialize_data(&dst->server_identity, &dst->server_identity_len,
                              ser + w, ser_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_public_key(dst->server_pub_key, ser + w, ser_len - w,
                                    &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  /* Store the composite identity, so we can use it to generate `t` */
  dst->composite_identity_len = ser + w - composite_identity_start;
  dst->composite_identity = otrng_xmalloc(dst->composite_identity_len);
  memcpy(dst->composite_identity, composite_identity_start,
         dst->composite_identity_len);

  if (!otrng_deserialize_ec_point(dst->S, ser + w, ser_len - w)) {
    return OTRNG_ERROR;
  }

  w += ED448_POINT_BYTES;

  if (!otrng_deserialize_ring_sig(dst->sigma, ser + w, ser_len - w, NULL)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL void
otrng_prekey_dake3_message_serialize(uint8_t **ser, size_t *ser_len,
                                     const otrng_prekey_dake3_message_s *msg) {
  size_t ret_len =
      2 + 1 + 4 + RING_SIG_BYTES + (4 + msg->msg_len) + ED448_POINT_BYTES;
  uint8_t *ret = otrng_xmalloc_z(ret_len);
  size_t w = 0;

  w += otrng_serialize_uint16(ret + w, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(ret + w, OTRNG_PREKEY_DAKE3_MSG);
  w += otrng_serialize_uint32(ret + w, msg->client_instance_tag);
  w += otrng_serialize_ring_sig(ret + w, msg->sigma);
  w += otrng_serialize_data(ret + w, msg->msg, msg->msg_len);

  assert(w <= ret_len);

  *ser = ret;
  if (ser_len) {
    *ser_len = w;
  }
}

INTERNAL otrng_prekey_dake3_message_s *otrng_prekey_dake3_message_new() {
  otrng_prekey_dake3_message_s *dake_3 =
      otrng_xmalloc_z(sizeof(otrng_prekey_dake3_message_s));
  otrng_prekey_dake3_message_init(dake_3);
  return dake_3;
}

INTERNAL void
otrng_prekey_dake3_message_init(otrng_prekey_dake3_message_s *dake_3) {
  memset(dake_3, 0, sizeof(otrng_prekey_dake3_message_s));
  dake_3->sigma = otrng_xmalloc_z(sizeof(ring_sig_s));
}

INTERNAL void
otrng_prekey_dake3_message_destroy(otrng_prekey_dake3_message_s *dake_3) {
  if (!dake_3) {
    return;
  }

  otrng_free(dake_3->msg);
  dake_3->msg = NULL;

  otrng_ring_sig_destroy(dake_3->sigma);
  otrng_free(dake_3->sigma);
  dake_3->sigma = NULL;
}
