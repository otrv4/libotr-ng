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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OTRNG_DAKE_PRIVATE

#include "dake.h"
#include "deserialize.h"
#include "error.h"
#include "serialize.h"
#include "str.h"

INTERNAL dake_identity_message_s *
otrng_dake_identity_message_new(const user_profile_s *profile) {
  if (profile == NULL)
    return NULL;

  dake_identity_message_s *identity_message =
      malloc(sizeof(dake_identity_message_s));
  if (!identity_message) {
    return NULL;
  }

  identity_message->sender_instance_tag = 0;
  identity_message->receiver_instance_tag = 0;
  identity_message->profile->versions = NULL;
  otrng_ec_bzero(identity_message->Y, ED448_POINT_BYTES);
  identity_message->B = NULL;
  otrng_user_profile_copy(identity_message->profile, profile);

  return identity_message;
}

INTERNAL void
otrng_dake_identity_message_destroy(dake_identity_message_s *identity_message) {
  otrng_user_profile_destroy(identity_message->profile);
  otrng_ec_point_destroy(identity_message->Y);
  otrng_dh_mpi_release(identity_message->B);
  identity_message->B = NULL;
}

INTERNAL void
otrng_dake_identity_message_free(dake_identity_message_s *identity_message) {
  if (!identity_message)
    return;

  otrng_dake_identity_message_destroy(identity_message);
  free(identity_message);
  identity_message = NULL;
}

INTERNAL otrng_err otrng_dake_identity_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_identity_message_s *identity_message) {
  size_t profile_len = 0;
  uint8_t *profile = NULL;
  if (otrng_user_profile_asprintf(&profile, &profile_len,
                                  identity_message->profile)) {
    return ERROR;
  }

  size_t s = IDENTITY_MIN_BYTES + profile_len;
  uint8_t *buff = malloc(s);
  if (!buff) {
    free(profile);
    profile = NULL;
    return ERROR;
  }

  uint8_t *cursor = buff;
  cursor += otrng_serialize_uint16(cursor, VERSION);
  cursor += otrng_serialize_uint8(cursor, IDENTITY_MSG_TYPE);
  cursor +=
      otrng_serialize_uint32(cursor, identity_message->sender_instance_tag);
  cursor +=
      otrng_serialize_uint32(cursor, identity_message->receiver_instance_tag);
  cursor += otrng_serialize_bytes_array(cursor, profile, profile_len);
  cursor += otrng_serialize_ec_point(cursor, identity_message->Y);

  free(profile);
  profile = NULL;

  size_t len = 0;
  otrng_err err =
      otrng_serialize_dh_public_key(cursor, &len, identity_message->B);
  if (err) {
    free(buff);
    buff = NULL;
    return ERROR;
  }
  cursor += len;

  if (dst)
    *dst = buff;

  if (nbytes)
    *nbytes = cursor - buff;

  return SUCCESS;
}

INTERNAL otrng_err otrng_dake_identity_message_deserialize(
    dake_identity_message_s *dst, const uint8_t *src, size_t src_len) {
  const uint8_t *cursor = src;
  int64_t len = src_len;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (otrng_deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (protocol_version != VERSION) {
    return ERROR;
  }

  uint8_t message_type = 0;
  if (otrng_deserialize_uint8(&message_type, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (message_type != IDENTITY_MSG_TYPE) {
    return ERROR;
  }

  if (otrng_deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (otrng_deserialize_uint32(&dst->receiver_instance_tag, cursor, len,
                               &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (otrng_user_profile_deserialize(dst->profile, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (otrng_deserialize_ec_point(dst->Y, cursor)) {
    return ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  otrng_mpi_p b_mpi; // no need to free, because nothing is copied now
  if (otrng_mpi_deserialize_no_copy(b_mpi, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  return otrng_dh_mpi_deserialize(&dst->B, b_mpi->data, b_mpi->len, &read);
}

INTERNAL void otrng_dake_auth_r_destroy(dake_auth_r_s *auth_r) {
  otrng_dh_mpi_release(auth_r->A);
  auth_r->A = NULL;
  otrng_ec_point_destroy(auth_r->X);
  otrng_user_profile_destroy(auth_r->profile);
  otrng_ring_sig_destroy(auth_r->sigma);
}

INTERNAL otrng_err otrng_dake_auth_r_asprintf(uint8_t **dst, size_t *nbytes,
                                                const dake_auth_r_s *auth_r) {
  size_t our_profile_len = 0;
  uint8_t *our_profile = NULL;

  if (otrng_user_profile_asprintf(&our_profile, &our_profile_len,
                                  auth_r->profile)) {
    return ERROR;
  }

  size_t s = AUTH_R_MIN_BYTES + our_profile_len;

  uint8_t *buff = malloc(s);
  if (!buff) {
    free(our_profile);
    our_profile = NULL;
    return ERROR;
  }

  uint8_t *cursor = buff;
  cursor += otrng_serialize_uint16(cursor, VERSION);
  cursor += otrng_serialize_uint8(cursor, AUTH_R_MSG_TYPE);
  cursor += otrng_serialize_uint32(cursor, auth_r->sender_instance_tag);
  cursor += otrng_serialize_uint32(cursor, auth_r->receiver_instance_tag);
  cursor += otrng_serialize_bytes_array(cursor, our_profile, our_profile_len);
  cursor += otrng_serialize_ec_point(cursor, auth_r->X);

  free(our_profile);
  our_profile = NULL;

  size_t len = 0;
  otrng_err err = otrng_serialize_dh_public_key(cursor, &len, auth_r->A);
  if (err) {
    free(buff);
    buff = NULL;
    return ERROR;
  }

  cursor += len;
  cursor += otrng_serialize_ring_sig(cursor, auth_r->sigma);

  if (dst)
    *dst = buff;

  if (nbytes)
    *nbytes = cursor - buff;

  return SUCCESS;
}

INTERNAL otrng_err otrng_dake_auth_r_deserialize(dake_auth_r_s *dst,
                                                   const uint8_t *buffer,
                                                   size_t buflen) {
  const uint8_t *cursor = buffer;
  int64_t len = buflen;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (otrng_deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (protocol_version != VERSION) {
    return ERROR;
  }

  uint8_t message_type = 0;
  if (otrng_deserialize_uint8(&message_type, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (message_type != AUTH_R_MSG_TYPE) {
    return ERROR;
  }

  if (otrng_deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (otrng_deserialize_uint32(&dst->receiver_instance_tag, cursor, len,
                               &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (otrng_user_profile_deserialize(dst->profile, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (otrng_deserialize_ec_point(dst->X, cursor)) {
    return ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  otrng_mpi_p tmp_mpi; // no need to free, because nothing is copied now
  if (otrng_mpi_deserialize_no_copy(tmp_mpi, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (otrng_dh_mpi_deserialize(&dst->A, tmp_mpi->data, tmp_mpi->len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  return otrng_deserialize_ring_sig(dst->sigma, cursor, len, &read);
}

INTERNAL void otrng_dake_auth_i_destroy(dake_auth_i_s *auth_i) {
  otrng_ring_sig_destroy(auth_i->sigma);
}

INTERNAL otrng_err otrng_dake_auth_i_asprintf(uint8_t **dst, size_t *nbytes,
                                                const dake_auth_i_s *auth_i) {
  size_t s = DAKE_HEADER_BYTES + RING_SIG_BYTES;
  *dst = malloc(s);

  if (!*dst) {
    return ERROR;
  }

  if (nbytes) {
    *nbytes = s;
  }

  uint8_t *cursor = *dst;
  cursor += otrng_serialize_uint16(cursor, VERSION);
  cursor += otrng_serialize_uint8(cursor, AUTH_I_MSG_TYPE);
  cursor += otrng_serialize_uint32(cursor, auth_i->sender_instance_tag);
  cursor += otrng_serialize_uint32(cursor, auth_i->receiver_instance_tag);
  cursor += otrng_serialize_ring_sig(cursor, auth_i->sigma);

  return SUCCESS;
}

INTERNAL otrng_err otrng_dake_auth_i_deserialize(dake_auth_i_s *dst,
                                                   const uint8_t *buffer,
                                                   size_t buflen) {
  const uint8_t *cursor = buffer;
  int64_t len = buflen;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (otrng_deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (protocol_version != VERSION) {
    return ERROR;
  }

  uint8_t message_type = 0;
  if (otrng_deserialize_uint8(&message_type, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (message_type != AUTH_I_MSG_TYPE) {
    return ERROR;
  }

  if (otrng_deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (otrng_deserialize_uint32(&dst->receiver_instance_tag, cursor, len,
                               &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  return otrng_deserialize_ring_sig(dst->sigma, cursor, len, &read);
}

INTERNAL dake_prekey_message_s *
otrng_dake_prekey_message_new(const user_profile_s *profile) {
  if (profile == NULL)
    return NULL;

  dake_prekey_message_s *prekey_message = malloc(sizeof(dake_prekey_message_s));
  if (!prekey_message) {
    return NULL;
  }

  prekey_message->sender_instance_tag = 0;
  prekey_message->receiver_instance_tag = 0;
  prekey_message->profile->versions = NULL;
  otrng_ec_bzero(prekey_message->Y, ED448_POINT_BYTES);
  prekey_message->B = NULL;
  otrng_user_profile_copy(prekey_message->profile, profile);

  return prekey_message;
}

INTERNAL void
otrng_dake_prekey_message_destroy(dake_prekey_message_s *prekey_message) {
  otrng_user_profile_destroy(prekey_message->profile);
  otrng_ec_point_destroy(prekey_message->Y);
  otrng_dh_mpi_release(prekey_message->B);
  prekey_message->B = NULL;
}

INTERNAL void
otrng_dake_prekey_message_free(dake_prekey_message_s *prekey_message) {
  if (!prekey_message)
    return;

  otrng_dake_prekey_message_destroy(prekey_message);
  free(prekey_message);
  prekey_message = NULL;
}

INTERNAL otrng_err otrng_dake_prekey_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_prekey_message_s *prekey_message) {
  size_t profile_len = 0;
  uint8_t *profile = NULL;
  if (otrng_user_profile_asprintf(&profile, &profile_len,
                                  prekey_message->profile)) {
    return ERROR;
  }

  size_t s = PRE_KEY_MIN_BYTES + profile_len;
  uint8_t *buff = malloc(s);
  if (!buff) {
    free(profile);
    profile = NULL;
    return ERROR;
  }

  uint8_t *cursor = buff;
  cursor += otrng_serialize_uint16(cursor, VERSION);
  cursor += otrng_serialize_uint8(cursor, PRE_KEY_MSG_TYPE);
  cursor += otrng_serialize_uint32(cursor, prekey_message->sender_instance_tag);
  cursor +=
      otrng_serialize_uint32(cursor, prekey_message->receiver_instance_tag);
  cursor += otrng_serialize_bytes_array(cursor, profile, profile_len);
  cursor += otrng_serialize_ec_point(cursor, prekey_message->Y);

  free(profile);
  profile = NULL;

  size_t len = 0;
  otrng_err err =
      otrng_serialize_dh_public_key(cursor, &len, prekey_message->B);
  if (err) {
    free(buff);
    buff = NULL;
    return ERROR;
  }
  cursor += len;

  if (dst)
    *dst = buff;

  if (nbytes)
    *nbytes = cursor - buff;

  return SUCCESS;
}

INTERNAL otrng_err otrng_dake_prekey_message_deserialize(
    dake_prekey_message_s *dst, const uint8_t *src, size_t src_len) {
  const uint8_t *cursor = src;
  int64_t len = src_len;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (otrng_deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (protocol_version != VERSION) {
    return ERROR;
  }

  uint8_t message_type = 0;
  if (otrng_deserialize_uint8(&message_type, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (message_type != PRE_KEY_MSG_TYPE) {
    return ERROR;
  }

  if (otrng_deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (otrng_deserialize_uint32(&dst->receiver_instance_tag, cursor, len,
                               &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (otrng_user_profile_deserialize(dst->profile, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  if (otrng_deserialize_ec_point(dst->Y, cursor)) {
    return ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  otrng_mpi_p b_mpi; // no need to free, because nothing is copied now
  if (otrng_mpi_deserialize_no_copy(b_mpi, cursor, len, &read)) {
    return ERROR;
  }

  cursor += read;
  len -= read;

  return otrng_dh_mpi_deserialize(&dst->B, b_mpi->data, b_mpi->len, &read);
}

INTERNAL void otrng_dake_non_interactive_auth_message_destroy(
    dake_non_interactive_auth_message_s *non_interactive_auth) {
  otrng_dh_mpi_release(non_interactive_auth->A);
  non_interactive_auth->A = NULL;
  otrng_ec_point_destroy(non_interactive_auth->X);
  otrng_user_profile_destroy(non_interactive_auth->profile);
  otrng_ring_sig_destroy(non_interactive_auth->sigma);
  non_interactive_auth->enc_msg = NULL;
  non_interactive_auth->enc_msg_len = 0;
  sodium_memzero(non_interactive_auth->nonce, DATA_MSG_NONCE_BYTES);
  sodium_memzero(non_interactive_auth->auth_mac, HASH_BYTES);
}

INTERNAL otrng_err otrng_dake_non_interactive_auth_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_non_interactive_auth_message_s *non_interactive_auth) {
  size_t data_msg_len = 0;

  if (non_interactive_auth->enc_msg)
    data_msg_len =
        4 + DATA_MSG_NONCE_BYTES + non_interactive_auth->enc_msg_len + 4;

  size_t our_profile_len = 0;
  uint8_t *our_profile = NULL;

  if (otrng_user_profile_asprintf(&our_profile, &our_profile_len,
                                  non_interactive_auth->profile))
    return ERROR;

  size_t s = NON_INT_AUTH_BYTES + our_profile_len + data_msg_len;

  uint8_t *buff = malloc(s);
  if (!buff) {
    free(our_profile);
    our_profile = NULL;
    return ERROR;
  }

  uint8_t *cursor = buff;
  cursor += otrng_serialize_uint16(cursor, VERSION);
  cursor += otrng_serialize_uint8(cursor, NON_INT_AUTH_MSG_TYPE);
  cursor +=
      otrng_serialize_uint32(cursor, non_interactive_auth->sender_instance_tag);
  cursor += otrng_serialize_uint32(cursor,
                                   non_interactive_auth->receiver_instance_tag);
  cursor += otrng_serialize_bytes_array(cursor, our_profile, our_profile_len);
  cursor += otrng_serialize_ec_point(cursor, non_interactive_auth->X);

  free(our_profile);
  our_profile = NULL;

  size_t len = 0;
  otrng_err err =
      otrng_serialize_dh_public_key(cursor, &len, non_interactive_auth->A);
  if (err) {
    free(buff);
    buff = NULL;
    return ERROR;
  }

  cursor += len;
  cursor += otrng_serialize_ring_sig(cursor, non_interactive_auth->sigma);

  if (non_interactive_auth->enc_msg) {
    cursor += otrng_serialize_uint32(cursor, non_interactive_auth->message_id);
    cursor += otrng_serialize_bytes_array(cursor, non_interactive_auth->nonce,
                                          DATA_MSG_NONCE_BYTES);
    cursor += otrng_serialize_data(cursor, non_interactive_auth->enc_msg,
                                   non_interactive_auth->enc_msg_len);
  }

  cursor += otrng_serialize_bytes_array(cursor, non_interactive_auth->auth_mac,
                                        sizeof(non_interactive_auth->auth_mac));

  if (dst)
    *dst = buff;

  if (nbytes)
    *nbytes = cursor - buff;

  return SUCCESS;
}

INTERNAL otrng_err otrng_dake_non_interactive_auth_message_deserialize(
    dake_non_interactive_auth_message_s *dst, const uint8_t *buffer,
    size_t buflen) {
  const uint8_t *cursor = buffer;
  int64_t len = buflen;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (otrng_deserialize_uint16(&protocol_version, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (protocol_version != VERSION)
    return ERROR;

  uint8_t message_type = 0;
  if (otrng_deserialize_uint8(&message_type, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (message_type != NON_INT_AUTH_MSG_TYPE)
    return ERROR;

  if (otrng_deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (otrng_deserialize_uint32(&dst->receiver_instance_tag, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (otrng_user_profile_deserialize(dst->profile, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (otrng_deserialize_ec_point(dst->X, cursor))
    return ERROR;

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  otrng_mpi_p tmp_mpi; // no need to free, because nothing is copied now
  if (otrng_mpi_deserialize_no_copy(tmp_mpi, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (otrng_dh_mpi_deserialize(&dst->A, tmp_mpi->data, tmp_mpi->len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (otrng_deserialize_ring_sig(dst->sigma, cursor, len, &read))
    return ERROR;

  cursor += read;
  len -= read;

  if (len > 64) {
    if (otrng_deserialize_uint32(&dst->message_id, cursor, len, &read))
      return ERROR;

    cursor += read;
    len -= read;

    if (otrng_deserialize_bytes_array((uint8_t *)&dst->nonce,
                                      DATA_MSG_NONCE_BYTES, cursor, len))
      return ERROR;

    cursor += DATA_MSG_NONCE_BYTES;
    len -= DATA_MSG_NONCE_BYTES;

    if (otrng_deserialize_data(&dst->enc_msg, cursor, len, &read))
      return ERROR;

    dst->enc_msg_len = read - 4;
    cursor += read;
    len -= read;
  }

  return otrng_deserialize_bytes_array(dst->auth_mac, HASH_BYTES, cursor, len);
}

tstatic otrng_bool not_expired(time_t expires) {
  if (difftime(expires, time(NULL)) > 0) {
    return otrng_true;
  }

  return otrng_false;
}

tstatic otrng_bool no_rollback_detected(const char *versions) {
  while (*versions) {
    if (*versions != '3' && *versions != '4')
      return otrng_false;

    versions++;
  }
  return otrng_true;
}

INTERNAL otrng_bool otrng_valid_received_values(
    const ec_point_p their_ecdh, const dh_mpi_p their_dh,
    const user_profile_s *profile) {
  /* Verify that the point their_ecdh received is on curve 448. */
  if (otrng_ec_point_valid(their_ecdh) == otrng_false)
    return otrng_false;

  /* Verify that the DH public key their_dh is from the correct group. */
  if (otrng_dh_mpi_valid(their_dh) == otrng_false)
    return otrng_false;

  /* Verify their profile is valid (and not expired). */
  if (otrng_user_profile_verify_signature(profile) == otrng_false)
    return otrng_false;

  if (not_expired(profile->expires) == otrng_false)
    return otrng_false;

  if (no_rollback_detected(profile->versions) == otrng_false)
    return otrng_false;

  return otrng_true;
}
