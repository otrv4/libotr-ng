#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dake.h"
#include "str.h"
#include "serialize.h"
#include "deserialize.h"
#include "user_profile.h"
#include "random.h"

dake_pre_key_t *
dake_pre_key_new(const user_profile_t *profile) {
  if (profile == NULL) {
    return NULL;
  }

  dake_pre_key_t *pre_key = malloc(sizeof(dake_pre_key_t));
  if (pre_key == NULL) {
    return NULL;
  }

  pre_key->sender_instance_tag = 0;
  pre_key->receiver_instance_tag = 0;
  user_profile_copy(pre_key->sender_profile, profile);

  return pre_key;
}

void
dake_pre_key_free(dake_pre_key_t *pre_key) {
  free(pre_key);
}

bool
dake_pre_key_aprint(uint8_t **dst, size_t *nbytes, const dake_pre_key_t *pre_key) {
  size_t profile_len = 0;
  uint8_t *profile = NULL;
  if (!user_profile_aprint(&profile, &profile_len, pre_key->sender_profile)) {
    return false;
  }

  size_t s = PRE_KEY_MIN_BYTES+profile_len;
  *dst = malloc(s);
  if (*dst == NULL) {
    free(profile);
    return false;
  }

  if (nbytes != NULL) { *nbytes = s; }

  uint8_t *target = *dst;
  target += serialize_uint16(target, OTR_VERSION);
  target += serialize_uint8(target, OTR_PRE_KEY_MSG_TYPE);
  target += serialize_uint32(target, pre_key->sender_instance_tag);
  target += serialize_uint32(target, pre_key->receiver_instance_tag);
  target += serialize_bytes_array(target, profile, profile_len);
  target += serialize_ec_public_key(target, pre_key->Y);
  target += serialize_dh_public_key(target, pre_key->B);

  free(profile);
  return true;
}

bool
dake_pre_key_deserialize(dake_pre_key_t *dst, const uint8_t *src, size_t src_len) {
    const uint8_t *cursor = src;
    int64_t len = src_len;
    size_t read = 0;
    
    uint16_t protocol_version = 0;
    if(!deserialize_uint16(&protocol_version, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    if (protocol_version != OTR_VERSION) {
      return false;
    }

    uint8_t message_type = 0;
    if(!deserialize_uint8(&message_type, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    if (message_type != OTR_PRE_KEY_MSG_TYPE) {
      return false;
    }

    if(!deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    if(!deserialize_uint32(&dst->receiver_instance_tag, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    if (!user_profile_deserialize(dst->sender_profile, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    //TODO deserialize_ec_public_key()
    ec_public_key_copy(dst->Y, cursor);
    cursor += sizeof(ec_public_key_t);
    len -= sizeof(ec_public_key_t);

    otr_mpi_t b_mpi; // no need to free, because nothing is copied now
    if (!otr_mpi_deserialize_no_copy(b_mpi, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    if (!dh_mpi_deserialize(&dst->B, b_mpi->data, b_mpi->len, &read)) {
      return false;
    }

    return true;
}

dake_dre_auth_t *
dake_dre_auth_new(const user_profile_t *profile) {
  if (profile == NULL) {
    return NULL;
  }

  dake_dre_auth_t *dre_auth = malloc(sizeof(dake_dre_auth_t));
  if (dre_auth  == NULL) {
    return NULL;
  }

  dre_auth->sender_instance_tag = 0;
  dre_auth->receiver_instance_tag = 0;
  user_profile_copy(dre_auth->profile, profile);

  return dre_auth;
}

void
dake_dre_auth_free(dake_dre_auth_t *dre_auth) {
}

static bool
dake_dre_auth_generate_gamma(dr_cs_symmetric_key_t k,
                             const cs_public_key_t *their_pub,
                             dake_dre_auth_t *dre_auth) {
  dr_cs_generate_symmetric_key(k);
  if (!dr_cs_encrypt(dre_auth->gamma, k, dre_auth->profile->pub_key, their_pub)) {
    return false;
  }

  return true;
}

static bool
dake_dre_auth_generate_phi_message(uint8_t **dst, size_t *dst_len,
                                   const user_profile_t *their_profile,
                                   const ec_public_key_t their_ecdh,
                                   const dh_mpi_t their_dh,
                                   dake_dre_auth_t *dre_auth) {

  *dst = NULL;
  size_t our_profile_len = 0, their_profile_len = 0;
  uint8_t *our_profile_buff = NULL, *their_profile_buff = NULL;

  if (!user_profile_aprint(&our_profile_buff, &our_profile_len, dre_auth->profile)) {
    goto generate_phi_message_error;
  }

  if (!user_profile_aprint(&their_profile_buff, &their_profile_len, their_profile)) {
    goto generate_phi_message_error;
  }

  size_t msg_len = our_profile_len \
                   + their_profile_len \
                   + 2*sizeof(ec_public_key_t) \
                   + 2*DH3072_MOD_LEN_BYTES;

  *dst = malloc(msg_len);
  if (*dst == NULL) {
    goto generate_phi_message_error;
  }

  if (dst_len != NULL) { *dst_len = msg_len; }

  uint8_t *cursor = *dst;
  cursor += serialize_bytes_array(cursor, their_profile_buff, their_profile_len);
  cursor += serialize_bytes_array(cursor, our_profile_buff, our_profile_len);
  cursor += serialize_ec_public_key(cursor, their_ecdh);
  cursor += serialize_ec_public_key(cursor, dre_auth->X);
  cursor += serialize_dh_public_key(cursor, their_dh);
  cursor += serialize_dh_public_key(cursor, dre_auth->A);

  return true;

generate_phi_message_error:
    free(our_profile_buff);
    free(their_profile_buff);
    free(*dst);
    return false;
}

static bool
dake_dre_auth_generate_phi(const uint8_t *phi_msg, const size_t phi_msg_len,
                           const dr_cs_symmetric_key_t k,
                           dake_dre_auth_t *dre_auth) {

  size_t s = crypto_secretbox_MACBYTES + phi_msg_len;
  dre_auth->phi = malloc(s);
  if (dre_auth->phi == NULL) {
    return false;
  }

  dre_auth->phi_len = s;

  uint8_t *enc_key[crypto_secretbox_KEYBYTES] = {0};
  //TODO: sha3(ec_key, k);

  random_bytes(dre_auth->nonce, NONCE_BYTES);
  if(-1 == crypto_secretbox_easy(dre_auth->phi, phi_msg, phi_msg_len, dre_auth->nonce, (unsigned char*) enc_key)) {
    free(dre_auth->phi);
    dre_auth->phi = NULL;
    dre_auth->phi_len = 0;

    return false;
  }

  return true;
}

static bool
dake_dre_auth_generate_sigma(const user_profile_t *their_profile,
                             const ec_public_key_t their_ecdh,
                             const dh_mpi_t their_dh,
                             const cs_keypair_t our_keypair,
                             const cs_public_key_t *their_pub,
                             dake_dre_auth_t *dre_auth) {
  
  size_t our_profile_len = 0, their_profile_len = 0;
  uint8_t *our_profile_buff = NULL, *their_profile_buff = NULL;
  uint8_t *sigma_msg = NULL;

  if (!user_profile_aprint(&our_profile_buff, &our_profile_len, dre_auth->profile)) {
    goto generate_sigma_error;
  }

  if (!user_profile_aprint(&their_profile_buff, &their_profile_len, their_profile)) {
    goto generate_sigma_error;
  }
  
  size_t sigma_msg_len = our_profile_len      \
                         + their_profile_len  \
                         + sizeof(ec_public_key_t) \
                         + DH3072_MOD_LEN_BYTES \
                         + sizeof(dre_auth->gamma);

  sigma_msg = malloc(sigma_msg_len);
  if (sigma_msg == NULL) {
    goto generate_sigma_error;
  }

  uint8_t *cursor = sigma_msg;
  cursor += serialize_bytes_array(cursor, their_profile_buff, their_profile_len);
  cursor += serialize_bytes_array(cursor, our_profile_buff, our_profile_len);
  cursor += serialize_ec_public_key(cursor, their_ecdh);
  cursor += serialize_dh_public_key(cursor, their_dh);
  cursor += serialize_bytes_array(cursor, dre_auth->gamma, sizeof(dre_auth->gamma));

  ec_point_t their_ephemeral;
  if(!ec_point_deserialize(their_ephemeral, their_ecdh)) {
    goto generate_sigma_error;
  }

  ring_signature_auth(dre_auth->sigma,
                      sigma_msg, our_keypair, their_pub, their_ephemeral);

  free(our_profile_buff);
  free(their_profile_buff);
  free(sigma_msg);
  return true;

generate_sigma_error:
  free(our_profile_buff);
  free(their_profile_buff);
  free(sigma_msg);
  return false;
}

bool
dake_dre_auth_generate_gamma_phi_sigma(const cs_keypair_t our_keypair,
                                       const cs_public_key_t *their_pub,
                                       const user_profile_t *their_profile,
                                       const ec_public_key_t their_ecdh,
                                       const dh_mpi_t their_dh,
                                       dake_dre_auth_t *dre_auth) {
  dr_cs_symmetric_key_t k;
  if (!dake_dre_auth_generate_gamma(k, their_pub, dre_auth)){
    return false;
  }

  uint8_t *phi_msg = NULL;
  size_t phi_msg_len = 0;
  if (!dake_dre_auth_generate_phi_message(&phi_msg, &phi_msg_len, their_profile, their_ecdh, their_dh, dre_auth)) {
    return false;
  }

  if (!dake_dre_auth_generate_phi(phi_msg, phi_msg_len, k, dre_auth)) {
    free(phi_msg);
    return false;
  }
  free(phi_msg);

  if (!dake_dre_auth_generate_sigma(their_profile, their_ecdh, their_dh, our_keypair, their_pub, dre_auth)) {
    return false;
  }

  return true;
}

bool
dake_dre_auth_aprint(uint8_t **dst, size_t *nbytes, const dake_dre_auth_t *dre_auth) {
  size_t our_profile_len = 0;
  uint8_t *our_profile = NULL;

  if (!user_profile_aprint(&our_profile, &our_profile_len, dre_auth->profile)) {
    return false;
  }

  size_t s = DRE_AUTH_MIN_BYTES + our_profile_len + dre_auth->phi_len;
  *dst = malloc(s);
  if (*dst == NULL) {
    free(our_profile);
    return false;
  }

  if (nbytes != NULL) { *nbytes = s; }

  uint8_t *cursor = *dst;
  cursor += serialize_uint16(cursor, OTR_VERSION);
  cursor += serialize_uint8(cursor, OTR_DRE_AUTH_MSG_TYPE);
  cursor += serialize_uint32(cursor, dre_auth->sender_instance_tag);
  cursor += serialize_uint32(cursor, dre_auth->receiver_instance_tag);
  cursor += serialize_bytes_array(cursor, our_profile, our_profile_len);
  cursor += serialize_ec_public_key(cursor, dre_auth->X);
  cursor += serialize_dh_public_key(cursor, dre_auth->A);

  cursor += serialize_bytes_array(cursor, dre_auth->gamma, sizeof(dr_cs_encrypted_symmetric_key_t));
  cursor += serialize_bytes_array(cursor, dre_auth->sigma, sizeof(rs_auth_t));
  cursor += serialize_bytes_array(cursor, dre_auth->nonce, NONCE_BYTES);
  cursor += serialize_bytes_array(cursor, dre_auth->phi, dre_auth->phi_len);

  free(our_profile);
  return true;
}


void
dake_dre_auth_deserialize(dake_dre_auth_t *target, uint8_t *data) {
}

static bool
not_expired(time_t expires) {
  if (difftime(expires, time(NULL)) > 0) {
    return true;
  }

  return false;
}

bool
dake_pre_key_validate(const dake_pre_key_t *pre_key) {
  ec_point_t y;
  if (!ec_point_deserialize(y, pre_key->Y)) {
    return false;
  }

  bool valid = user_profile_verify_signature(pre_key->sender_profile);
  valid &= not_expired(pre_key->sender_profile->expires);
  valid &= ec_point_valid(y);
  valid &= dh_mpi_valid(pre_key->B);
  // something Nick said
  return valid;
}

