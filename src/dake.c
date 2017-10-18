#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "constants.h"
#include "dake.h"
#include "deserialize.h"
#include "error.h"
#include "random.h"
#include "serialize.h"
#include "str.h"
#include "user_profile.h"

dake_identity_message_t *
dake_identity_message_new(const user_profile_t *profile) {
  if (profile == NULL)
    return NULL;

  dake_identity_message_t *identity_message =
      malloc(sizeof(dake_identity_message_t));
  if (!identity_message) {
    return NULL;
  }

  identity_message->sender_instance_tag = 0;
  identity_message->receiver_instance_tag = 0;
  identity_message->profile->versions = NULL;
  identity_message->B = NULL;
  user_profile_copy(identity_message->profile, profile);

  return identity_message;
}

void dake_identity_message_destroy(dake_identity_message_t *identity_message) {
  user_profile_destroy(identity_message->profile);
  ec_point_destroy(identity_message->Y);
  dh_mpi_release(identity_message->B);
  identity_message->B = NULL;
}

void dake_identity_message_free(dake_identity_message_t *identity_message) {
  if (!identity_message)
    return;

  dake_identity_message_destroy(identity_message);
  free(identity_message);
}

otr4_err_t dake_identity_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_identity_message_t *identity_message) {
  size_t profile_len = 0;
  uint8_t *profile = NULL;
  if (user_profile_asprintf(&profile, &profile_len,
                            identity_message->profile)) {
    return OTR4_ERROR;
  }

  size_t s = PRE_KEY_MIN_BYTES + profile_len;
  uint8_t *buff = malloc(s);
  if (!buff) {
    free(profile);
    return OTR4_ERROR;
  }

  uint8_t *cursor = buff;
  cursor += serialize_uint16(cursor, OTR_VERSION);
  cursor += serialize_uint8(cursor, OTR_IDENTITY_MSG_TYPE);
  cursor += serialize_uint32(cursor, identity_message->sender_instance_tag);
  cursor += serialize_uint32(cursor, identity_message->receiver_instance_tag);
  cursor += serialize_bytes_array(cursor, profile, profile_len);
  if (serialize_ec_point(cursor, identity_message->Y)) {
    free(profile);
    free(buff);
    return OTR4_ERROR;
  }
  cursor += ED448_POINT_BYTES;
  size_t len = 0;
  otr4_err_t err = serialize_dh_public_key(cursor, &len, identity_message->B);
  if (err) {
    free(profile);
    free(buff);
    return OTR4_ERROR;
  }
  cursor += len;

  if (dst)
    *dst = buff;

  if (nbytes)
    *nbytes = cursor - buff;

  free(profile);
  return OTR4_SUCCESS;
}

otr4_err_t dake_identity_message_deserialize(dake_identity_message_t *dst,
                                             const uint8_t *src,
                                             size_t src_len) {
  const uint8_t *cursor = src;
  int64_t len = src_len;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (protocol_version != OTR_VERSION) {
    return OTR4_ERROR;
  }

  uint8_t message_type = 0;
  if (deserialize_uint8(&message_type, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (message_type != OTR_IDENTITY_MSG_TYPE) {
    return OTR4_ERROR;
  }

  if (deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (deserialize_uint32(&dst->receiver_instance_tag, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (user_profile_deserialize(dst->profile, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (deserialize_ec_point(dst->Y, cursor)) {
    return OTR4_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  otr_mpi_t b_mpi; // no need to free, because nothing is copied now
  if (otr_mpi_deserialize_no_copy(b_mpi, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  return dh_mpi_deserialize(&dst->B, b_mpi->data, b_mpi->len, &read);
}

bool not_expired(time_t expires) {
  if (difftime(expires, time(NULL)) > 0) {
    return true;
  }

  return false;
}

static bool no_rollback_detected(const char *versions) {
  while (*versions) {
    if (*versions == '2' || *versions == '1')
      return false;

    if (*versions == '3' || *versions == '4') {
      versions++;
      return true;
    }
  }

  return false;
}

bool valid_received_values(const ec_point_t their_ecdh, const dh_mpi_t their_dh,
                           const user_profile_t *profile) {
  bool valid = true;

  /* Verify that the point X received is on curve 448. */
  valid &= ec_point_valid(their_ecdh);

  /* Verify that the DH public key A is from the correct group. */
  valid &= dh_mpi_valid(their_dh);

  /* Verify their profile is valid (and not expired). */
  valid &= user_profile_valid_signature(profile);
  valid &= not_expired(profile->expires);
  valid &= no_rollback_detected(profile->versions);

  return valid;
}

otr4_err_t dake_auth_r_asprintf(uint8_t **dst, size_t *nbytes,
                                const dake_auth_r_t *dre_auth) {
  size_t our_profile_len = 0;
  uint8_t *our_profile = NULL;

  if (user_profile_asprintf(&our_profile, &our_profile_len,
                            dre_auth->profile)) {
    return OTR4_ERROR;
  }

  size_t s = AUTH_R_MIN_BYTES + our_profile_len;

  uint8_t *buff = malloc(s);
  if (!buff) {
    free(our_profile);
    return OTR4_ERROR;
  }

  uint8_t *cursor = buff;
  cursor += serialize_uint16(cursor, OTR_VERSION);
  cursor += serialize_uint8(cursor, OTR_AUTH_R_MSG_TYPE);
  cursor += serialize_uint32(cursor, dre_auth->sender_instance_tag);
  cursor += serialize_uint32(cursor, dre_auth->receiver_instance_tag);
  cursor += serialize_bytes_array(cursor, our_profile, our_profile_len);
  if (serialize_ec_point(cursor, dre_auth->X)) {
    free(our_profile);
    free(buff);
    return OTR4_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  size_t len = 0;

  otr4_err_t err = serialize_dh_public_key(cursor, &len, dre_auth->A);
  if (err) {
    free(our_profile);
    free(buff);
    return OTR4_ERROR;
  }

  cursor += len;
  cursor += serialize_snizkpk_proof(cursor, dre_auth->sigma);

  if (dst)
    *dst = buff;

  if (nbytes)
    *nbytes = cursor - buff;

  free(our_profile);
  return OTR4_SUCCESS;
}

void dake_auth_r_destroy(dake_auth_r_t *auth_r) {
  dh_mpi_release(auth_r->A);
  auth_r->A = NULL;
  ec_point_destroy(auth_r->X);
  user_profile_destroy(auth_r->profile);
  snizkpk_proof_destroy(auth_r->sigma);
}

void dake_auth_r_free(dake_auth_r_t *auth_r) {
  if (!auth_r)
    return;

  dake_auth_r_destroy(auth_r);
  free(auth_r);
}

otr4_err_t dake_auth_r_deserialize(dake_auth_r_t *dst, const uint8_t *buffer,
                                   size_t buflen) {
  const uint8_t *cursor = buffer;
  int64_t len = buflen;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (protocol_version != OTR_VERSION) {
    return OTR4_ERROR;
  }

  uint8_t message_type = 0;
  if (deserialize_uint8(&message_type, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (message_type != OTR_AUTH_R_MSG_TYPE) {
    return OTR4_ERROR;
  }

  if (deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (deserialize_uint32(&dst->receiver_instance_tag, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (user_profile_deserialize(dst->profile, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (deserialize_ec_point(dst->X, cursor)) {
    return OTR4_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  otr_mpi_t tmp_mpi; // no need to free, because nothing is copied now
  if (otr_mpi_deserialize_no_copy(tmp_mpi, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (dh_mpi_deserialize(&dst->A, tmp_mpi->data, tmp_mpi->len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  return deserialize_snizkpk_proof(dst->sigma, cursor, len, &read);
}

void dake_auth_i_destroy(dake_auth_i_t *auth_i) {
  snizkpk_proof_destroy(auth_i->sigma);
}

void dake_auth_i_free(dake_auth_i_t *auth_i) {
  if (!auth_i)
    return;

  dake_auth_i_destroy(auth_i);
  free(auth_i);
}

otr4_err_t dake_auth_i_asprintf(uint8_t **dst, size_t *nbytes,
                                const dake_auth_i_t *dre_auth) {
  size_t s = DAKE_HEADER_BYTES + SNIZKPK_BYTES;
  *dst = malloc(s);

  if (!*dst) {
    return OTR4_ERROR;
  }

  if (nbytes) {
    *nbytes = s;
  }

  uint8_t *cursor = *dst;
  cursor += serialize_uint16(cursor, OTR_VERSION);
  cursor += serialize_uint8(cursor, OTR_AUTH_I_MSG_TYPE);
  cursor += serialize_uint32(cursor, dre_auth->sender_instance_tag);
  cursor += serialize_uint32(cursor, dre_auth->receiver_instance_tag);
  cursor += serialize_snizkpk_proof(cursor, dre_auth->sigma);

  return OTR4_SUCCESS;
}

otr4_err_t dake_auth_i_deserialize(dake_auth_i_t *dst, const uint8_t *buffer,
                                   size_t buflen) {
  const uint8_t *cursor = buffer;
  int64_t len = buflen;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (protocol_version != OTR_VERSION) {
    return OTR4_ERROR;
  }

  uint8_t message_type = 0;
  if (deserialize_uint8(&message_type, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (message_type != OTR_AUTH_I_MSG_TYPE) {
    return OTR4_ERROR;
  }

  if (deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  if (deserialize_uint32(&dst->receiver_instance_tag, cursor, len, &read)) {
    return OTR4_ERROR;
  }

  cursor += read;
  len -= read;

  return deserialize_snizkpk_proof(dst->sigma, cursor, len, &read);
}
