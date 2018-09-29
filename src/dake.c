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
#include <stdio.h>
#include <stdlib.h>

#define OTRNG_DAKE_PRIVATE

#include "alloc.h"
#include "dake.h"
#include "deserialize.h"
#include "error.h"
#include "key_management.h"
#include "serialize.h"
#include "shake.h"

INTERNAL dake_identity_message_s *
otrng_dake_identity_message_new(const client_profile_s *profile) {
  dake_identity_message_s *identity_message;

  if (!profile) {
    return NULL;
  }

  identity_message = otrng_xmalloc_z(sizeof(dake_identity_message_s));
  identity_message->profile = otrng_xmalloc_z(sizeof(client_profile_s));
  otrng_client_profile_copy(identity_message->profile, profile);
  otrng_secure_wipe(identity_message->Y, ED448_POINT_BYTES);

  return identity_message;
}

INTERNAL void
otrng_dake_identity_message_destroy(dake_identity_message_s *identity_message) {
  identity_message->sender_instance_tag = 0;
  identity_message->receiver_instance_tag = 0;
  otrng_client_profile_destroy(identity_message->profile);
  free(identity_message->profile);
  identity_message->profile = NULL;
  otrng_ec_point_destroy(identity_message->Y);
  otrng_dh_mpi_release(identity_message->B);
  identity_message->B = NULL;
}

INTERNAL void
otrng_dake_identity_message_free(dake_identity_message_s *identity_message) {
  if (!identity_message) {
    return;
  }

  otrng_dake_identity_message_destroy(identity_message);
  free(identity_message);
}

INTERNAL otrng_result otrng_dake_identity_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_identity_message_s *identity_message) {
  size_t profile_len = 0;
  uint8_t *profile = NULL;
  size_t size, len;
  uint8_t *buff;
  uint8_t *cursor;
  if (!otrng_client_profile_asprintf(&profile, &profile_len,
                                     identity_message->profile)) {
    return OTRNG_ERROR;
  }

  size = IDENTITY_MAX_BYTES + profile_len;
  buff = otrng_xmalloc_z(size);

  cursor = buff;
  cursor += otrng_serialize_uint16(cursor, OTRNG_PROTOCOL_VERSION_4);
  cursor += otrng_serialize_uint8(cursor, IDENTITY_MSG_TYPE);
  cursor +=
      otrng_serialize_uint32(cursor, identity_message->sender_instance_tag);
  cursor +=
      otrng_serialize_uint32(cursor, identity_message->receiver_instance_tag);
  cursor += otrng_serialize_bytes_array(cursor, profile, profile_len);
  cursor += otrng_serialize_ec_point(cursor, identity_message->Y);

  free(profile);

  if (!otrng_serialize_dh_public_key(cursor, (size - (cursor - buff)), &len,
                                     identity_message->B)) {
    free(buff);
    return OTRNG_ERROR;
  }
  cursor += len;

  if (dst) {
    *dst = buff;
  } else {
    return OTRNG_ERROR;
  }

  if (nbytes) {
    *nbytes = cursor - buff;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_dake_identity_message_deserialize(
    dake_identity_message_s *dst, const uint8_t *src, size_t src_len) {
  const uint8_t *cursor = src;
  int64_t len = src_len;
  size_t read = 0;

  uint16_t protocol_version = 0;
  uint8_t message_type = 0;

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

  if (message_type != IDENTITY_MSG_TYPE) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->sender_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_uint32(&dst->receiver_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_client_profile_deserialize(dst->profile, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_ec_point(dst->Y, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  return otrng_deserialize_dh_mpi_otr(&dst->B, cursor, len, &read);
}

INTERNAL dake_auth_r_s *otrng_dake_auth_r_new() {
  dake_auth_r_s *r = otrng_xmalloc_z(sizeof(dake_auth_r_s));
  otrng_dake_auth_r_init(r);
  return r;
}

INTERNAL void otrng_dake_auth_r_init(dake_auth_r_s *auth_r) {
  memset(auth_r, 0, sizeof(dake_auth_r_s));
  auth_r->sigma = otrng_xmalloc_z(sizeof(ring_sig_s));
  auth_r->profile = otrng_xmalloc_z(sizeof(client_profile_s));
}

INTERNAL void otrng_dake_auth_r_destroy(dake_auth_r_s *auth_r) {
  otrng_dh_mpi_release(auth_r->A);
  auth_r->A = NULL;
  otrng_ec_point_destroy(auth_r->X);
  otrng_client_profile_destroy(auth_r->profile);
  free(auth_r->profile);
  auth_r->profile = NULL;
  otrng_ring_sig_destroy(auth_r->sigma);
  free(auth_r->sigma);
  auth_r->sigma = NULL;
}

INTERNAL otrng_result otrng_dake_auth_r_asprintf(uint8_t **dst, size_t *nbytes,
                                                 const dake_auth_r_s *auth_r) {
  size_t our_profile_len = 0;
  uint8_t *our_profile = NULL;
  size_t size, len;
  uint8_t *buff, *cursor;

  if (!otrng_client_profile_asprintf(&our_profile, &our_profile_len,
                                     auth_r->profile)) {
    return OTRNG_ERROR;
  }

  size = AUTH_R_MAX_BYTES + our_profile_len;

  buff = otrng_xmalloc_z(size);

  cursor = buff;
  cursor += otrng_serialize_uint16(cursor, OTRNG_PROTOCOL_VERSION_4);
  cursor += otrng_serialize_uint8(cursor, AUTH_R_MSG_TYPE);
  cursor += otrng_serialize_uint32(cursor, auth_r->sender_instance_tag);
  cursor += otrng_serialize_uint32(cursor, auth_r->receiver_instance_tag);
  cursor += otrng_serialize_bytes_array(cursor, our_profile, our_profile_len);
  cursor += otrng_serialize_ec_point(cursor, auth_r->X);

  free(our_profile);

  len = 0;
  if (!otrng_serialize_dh_public_key(cursor, (size - (cursor - buff)), &len,
                                     auth_r->A)) {
    free(buff);
    return OTRNG_ERROR;
  }

  cursor += len;
  cursor += otrng_serialize_ring_sig(cursor, auth_r->sigma);

  if (dst) {
    *dst = buff;
  } else {
    return OTRNG_ERROR;
  }

  if (nbytes) {
    *nbytes = cursor - buff;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_dake_auth_r_deserialize(dake_auth_r_s *dst,
                                                    const uint8_t *buffer,
                                                    size_t buflen) {
  const uint8_t *cursor = buffer;
  int64_t len = buflen;
  size_t read = 0;
  uint16_t protocol_version = 0;
  uint8_t message_type = 0;

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

  if (message_type != AUTH_R_MSG_TYPE) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->sender_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_uint32(&dst->receiver_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_client_profile_deserialize(dst->profile, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_ec_point(dst->X, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_dh_mpi_otr(&dst->A, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  return otrng_deserialize_ring_sig(dst->sigma, cursor, len, &read);
}

INTERNAL dake_auth_i_s *otrng_dake_auth_i_new() {
  dake_auth_i_s *r = otrng_xmalloc_z(sizeof(dake_auth_i_s));
  otrng_dake_auth_i_init(r);
  return r;
}

INTERNAL void otrng_dake_auth_i_init(dake_auth_i_s *auth_i) {
  memset(auth_i, 0, sizeof(dake_auth_i_s));
  auth_i->sigma = otrng_xmalloc_z(sizeof(ring_sig_s));
}

INTERNAL void otrng_dake_auth_i_destroy(dake_auth_i_s *auth_i) {
  otrng_ring_sig_destroy(auth_i->sigma);
  free(auth_i->sigma);
  auth_i->sigma = NULL;
}

INTERNAL otrng_result otrng_dake_auth_i_asprintf(uint8_t **dst, size_t *nbytes,
                                                 const dake_auth_i_s *auth_i) {
  size_t size = DAKE_HEADER_BYTES + RING_SIG_BYTES;
  uint8_t *cursor;

  *dst = otrng_xmalloc_z(size);

  if (nbytes) {
    *nbytes = size;
  }

  cursor = *dst;
  cursor += otrng_serialize_uint16(cursor, OTRNG_PROTOCOL_VERSION_4);
  cursor += otrng_serialize_uint8(cursor, AUTH_I_MSG_TYPE);
  cursor += otrng_serialize_uint32(cursor, auth_i->sender_instance_tag);
  cursor += otrng_serialize_uint32(cursor, auth_i->receiver_instance_tag);
  otrng_serialize_ring_sig(cursor, auth_i->sigma);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_dake_auth_i_deserialize(dake_auth_i_s *dst,
                                                    const uint8_t *buffer,
                                                    size_t buflen) {
  const uint8_t *cursor = buffer;
  int64_t len = buflen;
  size_t read = 0;
  uint16_t protocol_version = 0;
  uint8_t message_type = 0;

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

  if (message_type != AUTH_I_MSG_TYPE) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->sender_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_uint32(&dst->receiver_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  return otrng_deserialize_ring_sig(dst->sigma, cursor, len, &read);
}

INTERNAL dake_prekey_message_s *otrng_dake_prekey_message_new(void) {
  dake_prekey_message_s *prekey_message =
      otrng_xmalloc_z(sizeof(dake_prekey_message_s));

  return prekey_message;
}

INTERNAL dake_prekey_message_s *
otrng_dake_prekey_message_build(uint32_t instance_tag, const ec_point ecdh,
                                const dh_public_key dh) {
  dake_prekey_message_s *m = otrng_dake_prekey_message_new();
  uint32_t *identifier;
  if (!m) {
    return NULL;
  }

  m->sender_instance_tag = instance_tag;

  otrng_ec_point_copy(m->Y, ecdh);
  m->B = otrng_dh_mpi_copy(dh);

  identifier = gcry_random_bytes(4, GCRY_STRONG_RANDOM);
  m->id = *identifier;

  gcry_free(identifier);

  return m;
}

INTERNAL void
otrng_dake_prekey_message_destroy(dake_prekey_message_s *prekey_message) {
  prekey_message->id = 0;
  otrng_ec_point_destroy(prekey_message->Y);
  otrng_dh_mpi_release(prekey_message->B);
  prekey_message->B = NULL;
}

INTERNAL void
otrng_dake_prekey_message_free(dake_prekey_message_s *prekey_message) {
  if (!prekey_message) {
    return;
  }

  otrng_dake_prekey_message_destroy(prekey_message);
  free(prekey_message);
}

INTERNAL otrng_result otrng_dake_prekey_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_prekey_message_s *prekey_message) {

  size_t size = PRE_KEY_MAX_BYTES;
  *dst = otrng_xmalloc_z(size);

  return otrng_dake_prekey_message_serialize(*dst, size, nbytes,
                                             prekey_message);
}

INTERNAL otrng_result otrng_dake_prekey_message_serialize(
    uint8_t *dst, size_t dstlen, size_t *written,
    const dake_prekey_message_s *src) {
  size_t w = 0, len;
  w += otrng_serialize_uint16(dst + w, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(dst + w, PRE_KEY_MSG_TYPE);
  w += otrng_serialize_uint32(dst + w, src->id);
  w += otrng_serialize_uint32(dst + w, src->sender_instance_tag);
  w += otrng_serialize_ec_point(dst + w, src->Y);

  if (!otrng_serialize_dh_public_key(dst + w, dstlen - w, &len, src->B)) {
    return OTRNG_ERROR;
  }

  w += len;

  if (written) {
    *written = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_dake_prekey_message_deserialize(
    dake_prekey_message_s *dst, const uint8_t *src, size_t src_len,
    size_t *nread) {
  const uint8_t *cursor = src;
  int64_t len = src_len;
  size_t read = 0;
  uint16_t protocol_version = 0;
  uint8_t message_type = 0;
  otrng_result ret;

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

  if (message_type != PRE_KEY_MSG_TYPE) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->id, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_uint32(&dst->sender_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_ec_point(dst->Y, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  ret = otrng_deserialize_dh_mpi_otr(&dst->B, cursor, len, &read);

  if (nread) {
    *nread = cursor - src + read;
  }

  return ret;
}

INTERNAL dake_non_interactive_auth_message_s *
otrng_dake_non_interactive_auth_message_new() {
  dake_non_interactive_auth_message_s *r =
      otrng_xmalloc_z(sizeof(dake_non_interactive_auth_message_s));
  otrng_dake_non_interactive_auth_message_init(r);
  return r;
}

INTERNAL void otrng_dake_non_interactive_auth_message_init(
    dake_non_interactive_auth_message_s *a) {
  memset(a, 0, sizeof(dake_non_interactive_auth_message_s));
  a->sigma = otrng_xmalloc_z(sizeof(ring_sig_s));
  a->profile = otrng_xmalloc_z(sizeof(client_profile_s));
}

INTERNAL void otrng_dake_non_interactive_auth_message_destroy(
    dake_non_interactive_auth_message_s *non_interactive_auth) {
  otrng_dh_mpi_release(non_interactive_auth->A);
  non_interactive_auth->A = NULL;
  otrng_ec_point_destroy(non_interactive_auth->X);
  otrng_client_profile_destroy(non_interactive_auth->profile);
  free(non_interactive_auth->profile);
  non_interactive_auth->profile = NULL;
  otrng_ring_sig_destroy(non_interactive_auth->sigma);
  free(non_interactive_auth->sigma);
  non_interactive_auth->sigma = NULL;
  otrng_secure_wipe(non_interactive_auth->auth_mac, HASH_BYTES);
}

INTERNAL otrng_result otrng_dake_non_interactive_auth_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_non_interactive_auth_message_s *non_interactive_auth) {
  size_t our_profile_len = 0;
  uint8_t *our_profile = NULL;
  size_t size, len;
  uint8_t *buff, *cursor;

  if (!dst) {
    return OTRNG_ERROR;
  }

  if (!otrng_client_profile_asprintf(&our_profile, &our_profile_len,
                                     non_interactive_auth->profile)) {
    return OTRNG_ERROR;
  }

  size = NON_INT_AUTH_MAX_BYTES + our_profile_len;
  buff = otrng_xmalloc_z(size);

  cursor = buff;
  cursor += otrng_serialize_uint16(cursor, OTRNG_PROTOCOL_VERSION_4);
  cursor += otrng_serialize_uint8(cursor, NON_INT_AUTH_MSG_TYPE);
  cursor +=
      otrng_serialize_uint32(cursor, non_interactive_auth->sender_instance_tag);
  cursor += otrng_serialize_uint32(cursor,
                                   non_interactive_auth->receiver_instance_tag);
  cursor += otrng_serialize_bytes_array(cursor, our_profile, our_profile_len);
  cursor += otrng_serialize_ec_point(cursor, non_interactive_auth->X);

  free(our_profile);

  len = 0;
  if (!otrng_serialize_dh_public_key(cursor, (size - (cursor - buff)), &len,
                                     non_interactive_auth->A)) {
    free(buff);
    return OTRNG_ERROR;
  }

  cursor += len;
  cursor += otrng_serialize_ring_sig(cursor, non_interactive_auth->sigma);

  cursor +=
      otrng_serialize_uint32(cursor, non_interactive_auth->prekey_message_id);

  cursor += otrng_serialize_bytes_array(cursor, non_interactive_auth->auth_mac,
                                        sizeof(non_interactive_auth->auth_mac));

  *dst = buff;

  if (nbytes) {
    *nbytes = cursor - buff;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_dake_non_interactive_auth_message_deserialize(
    dake_non_interactive_auth_message_s *dst, const uint8_t *buffer,
    size_t buflen) {
  const uint8_t *cursor = buffer;
  int64_t len = buflen;
  size_t read = 0;
  uint16_t protocol_version = 0;
  uint8_t message_type = 0;

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

  if (message_type != NON_INT_AUTH_MSG_TYPE) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->sender_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_uint32(&dst->receiver_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_client_profile_deserialize(dst->profile, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_ec_point(dst->X, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_dh_mpi_otr(&dst->A, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (dst->sigma == NULL) {
    dst->sigma = otrng_xmalloc_z(sizeof(ring_sig_s));
  }

  if (!otrng_deserialize_ring_sig(dst->sigma, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_uint32(&dst->prekey_message_id, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  return otrng_deserialize_bytes_array(dst->auth_mac, HASH_BYTES, cursor, len);
}

INTERNAL otrng_bool otrng_valid_received_values(
    const uint32_t sender_instance_tag, const ec_point their_ecdh,
    const dh_mpi their_dh, const client_profile_s *profile) {
  /* Verify that the point their_ecdh received is on curve 448. */
  if (!otrng_ec_point_valid(their_ecdh)) {
    return otrng_false;
  }

  /* Verify that the DH public key their_dh is from the correct group. */
  if (!otrng_dh_mpi_valid(their_dh)) {
    return otrng_false;
  }

  /* Verify their profile is valid (and not expired). */
  if (!otrng_client_profile_valid(profile, sender_instance_tag)) {
    return otrng_false;
  }

  return otrng_true;
}

#define MAX_T_LENGTH                                                           \
  (3 * HASH_BYTES + 2 * ED448_POINT_BYTES + 2 * DH_MPI_MAX_BYTES +             \
   ED448_SHARED_PREKEY_BYTES)

tstatic otrng_result build_rsign_tag(
    uint8_t *dst, size_t dstlen, size_t *written, uint8_t first_usage,
    const client_profile_s *i_profile, const client_profile_s *r_profile,
    const ec_point i_ecdh, const ec_point r_ecdh, const dh_mpi i_dh,
    const dh_mpi r_dh, const uint8_t *ser_r_shared_prekey,
    size_t ser_r_shared_prekey_len, const uint8_t *phi, size_t phi_len) {
  uint8_t *ser_i_profile = NULL, *ser_r_profile = NULL;
  size_t ser_i_profile_len, ser_r_profile_len = 0;
  uint8_t ser_i_ecdh[ED448_POINT_BYTES], ser_r_ecdh[ED448_POINT_BYTES];
  uint8_t ser_i_dh[DH_MPI_MAX_BYTES], ser_r_dh[DH_MPI_MAX_BYTES];
  size_t ser_i_dh_len = 0, ser_r_dh_len = 0;

  uint8_t hash_ser_i_profile[HASH_BYTES];
  uint8_t hash_ser_r_profile[HASH_BYTES];
  uint8_t hash_phi[HASH_BYTES];

  if (dstlen < MAX_T_LENGTH) {
    return OTRNG_ERROR;
  }

  if (otrng_serialize_ec_point(ser_i_ecdh, i_ecdh) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  if (otrng_serialize_ec_point(ser_r_ecdh, r_ecdh) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  if (!otrng_serialize_dh_public_key(ser_i_dh, DH_MPI_MAX_BYTES, &ser_i_dh_len,
                                     i_dh)) {
    return OTRNG_ERROR;
  }

  if (!otrng_serialize_dh_public_key(ser_r_dh, DH_MPI_MAX_BYTES, &ser_r_dh_len,
                                     r_dh)) {
    return OTRNG_ERROR;
  }

  do {
    uint8_t usage_bob_client_profile = first_usage;
    uint8_t usage_alice_client_profile = first_usage + 1;
    uint8_t usage_phi = first_usage + 2;
    uint8_t *cursor;

    if (!otrng_client_profile_asprintf(&ser_i_profile, &ser_i_profile_len,
                                       i_profile)) {
      continue;
    }

    if (!otrng_client_profile_asprintf(&ser_r_profile, &ser_r_profile_len,
                                       r_profile)) {
      continue;
    }

    shake_256_kdf1(hash_ser_i_profile, HASH_BYTES, usage_bob_client_profile,
                   ser_i_profile, ser_i_profile_len);
    shake_256_kdf1(hash_ser_r_profile, HASH_BYTES, usage_alice_client_profile,
                   ser_r_profile, ser_r_profile_len);
    shake_256_kdf1(hash_phi, HASH_BYTES, usage_phi, phi, phi_len);

    cursor = dst;
    memcpy(cursor, hash_ser_i_profile, HASH_BYTES);
    cursor += HASH_BYTES;

    memcpy(cursor, hash_ser_r_profile, HASH_BYTES);
    cursor += HASH_BYTES;

    memcpy(cursor, ser_i_ecdh, ED448_POINT_BYTES);
    cursor += ED448_POINT_BYTES;

    memcpy(cursor, ser_r_ecdh, ED448_POINT_BYTES);
    cursor += ED448_POINT_BYTES;

    memcpy(cursor, ser_i_dh, ser_i_dh_len);
    cursor += ser_i_dh_len;

    memcpy(cursor, ser_r_dh, ser_r_dh_len);
    cursor += ser_r_dh_len;

    if (ser_r_shared_prekey) {
      memcpy(cursor, ser_r_shared_prekey, ser_r_shared_prekey_len);
      cursor += ser_r_shared_prekey_len;
    }

    memcpy(cursor, hash_phi, HASH_BYTES);
    cursor += HASH_BYTES;

    if (written) {
      *written = cursor - dst;
    }
  } while (0);

  free(ser_i_profile);
  free(ser_r_profile);

  // I don't _think_ these are necessary, since the points are public values
  otrng_secure_wipe(ser_i_ecdh, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_r_ecdh, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_i_dh, DH3072_MOD_LEN_BYTES);
  otrng_secure_wipe(ser_r_dh, DH3072_MOD_LEN_BYTES);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result build_interactive_rsign_tag(
    uint8_t **msg, size_t *msg_len, const char auth_tag_type,
    const otrng_dake_participant_data_s *initiator,
    const otrng_dake_participant_data_s *responder, const uint8_t *phi,
    size_t phi_len) {

  size_t written = 0;
  otrng_result result = OTRNG_ERROR;
  uint8_t *buff = otrng_xmalloc_z(1 + MAX_T_LENGTH);

  assert(auth_tag_type == 'i' || auth_tag_type == 'r');
  if (auth_tag_type == 'r') {
    // t = 0x0 || KDF_1(0x05 || Bobs_Client_Profile, 64) || KDF_1(0x06 ||
    // Alices_Client_Profile, 64) || Y || X || B || A || KDF_1(0x07 || phi, 64)
    *buff = 0x0;
    result = build_rsign_tag(
        buff + 1, MAX_T_LENGTH, &written, 0x05, initiator->client_profile,
        responder->client_profile, &initiator->ecdh, &responder->ecdh,
        initiator->dh, responder->dh, NULL, 0, phi, phi_len);
  } else if (auth_tag_type == 'i') {
    // t = 0x1 || KDF_1(0x08 || Bobs_Client_Profile, 64) || KDF_1(0x09 ||
    // Alices_Client_Profile, 64) || Y || X || B || A || KDF_1(0x0A || phi, 64)
    *buff = 0x01;
    result = build_rsign_tag(
        buff + 1, MAX_T_LENGTH, &written, 0x08, initiator->client_profile,
        responder->client_profile, &initiator->ecdh, &responder->ecdh,
        initiator->dh, responder->dh, NULL, 0, phi, phi_len);
  }

  if (result == OTRNG_ERROR) {
    free(buff);
    return OTRNG_ERROR;
  }

  *msg = buff;
  if (msg_len) {
    *msg_len = written + 1;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
build_non_interactive_rsign_tag(uint8_t **msg, size_t *msg_len,
                                const otrng_dake_participant_data_s *initiator,
                                const otrng_dake_participant_data_s *responder,
                                const otrng_shared_prekey_pub r_shared_prekey,
                                const uint8_t *phi, size_t phi_len) {

  uint8_t first_usage = 0x0D;
  uint8_t ser_r_shared_prekey[ED448_SHARED_PREKEY_BYTES];
  otrng_result result;

  *msg = otrng_xmalloc_z(MAX_T_LENGTH);

  otrng_serialize_shared_prekey(ser_r_shared_prekey, r_shared_prekey);

  result = build_rsign_tag(*msg, MAX_T_LENGTH, msg_len, first_usage,
                           initiator->client_profile, responder->client_profile,
                           &initiator->ecdh, &responder->ecdh, initiator->dh,
                           responder->dh, ser_r_shared_prekey,
                           ED448_SHARED_PREKEY_BYTES, phi, phi_len);

  // This is probably not necessary, since the shared prekey is a public value
  otrng_secure_wipe(ser_r_shared_prekey, ED448_SHARED_PREKEY_BYTES);

  return result;
}

INTERNAL otrng_result build_fallback_non_interactive_rsign_tag(
    uint8_t **msg, size_t *msg_len,
    const otrng_dake_participant_data_s *initiator,
    const otrng_dake_participant_data_s *responder,
    const otrng_shared_prekey_pub r_shared_prekey, const uint8_t *phi,
    size_t phi_len) {

  uint8_t first_usage = 0x0D;
  uint8_t ser_r_shared_prekey[ED448_SHARED_PREKEY_BYTES];
  otrng_result result;

  *msg = otrng_xmalloc_z(MAX_T_LENGTH);

  otrng_serialize_shared_prekey(ser_r_shared_prekey, r_shared_prekey);

  result = build_rsign_tag(
      *msg, MAX_T_LENGTH, msg_len, first_usage, initiator->exp_client_profile,
      responder->client_profile, &initiator->ecdh, &responder->ecdh,
      initiator->dh, responder->dh, ser_r_shared_prekey,
      ED448_SHARED_PREKEY_BYTES, phi, phi_len);

  // Probably not necessary
  otrng_secure_wipe(ser_r_shared_prekey, ED448_SHARED_PREKEY_BYTES);

  return result;
}

INTERNAL otrng_result otrng_dake_non_interactive_auth_message_authenticator(
    uint8_t dst[HASH_BYTES], const dake_non_interactive_auth_message_s *auth,
    const uint8_t *t, size_t t_len, uint8_t tmp_key[HASH_BYTES]) {

  // OTRv4 section "Non-Interactive-Auth Message"
  /* auth_mac_k = KDF_1(0x0C || tmp_k, 64) */
  uint8_t usage_auth_mac_key = 0x0C;
  uint8_t *auth_mac_k = otrng_secure_alloc(HASH_BYTES);

  (void)auth;

  shake_256_kdf1(auth_mac_k, HASH_BYTES, usage_auth_mac_key, tmp_key,
                 HASH_BYTES);

  // OTRv4 section, "Non-Interactive DAKE Overview"
  /* Auth MAC = KDF_1(usage_auth_mac || auth_mac_k || t, 64) */
  otrng_key_manager_calculate_auth_mac(dst, auth_mac_k, t, t_len);

  otrng_secure_wipe(auth_mac_k, HASH_BYTES);
  free(auth_mac_k);

  return OTRNG_SUCCESS;
}
