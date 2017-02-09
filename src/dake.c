#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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
  user_profile_copy(pre_key->profile, profile);

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
  if (!user_profile_aprint(&profile, &profile_len, pre_key->profile)) {
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

    if (!user_profile_deserialize(dst->profile, cursor, len, &read)) {
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

  bool valid = user_profile_verify_signature(pre_key->profile);
  valid &= not_expired(pre_key->profile->expires);
  valid &= ec_point_valid(y);
  valid &= dh_mpi_valid(pre_key->B);

  // TODO: something Nick said about degenerated keys

  return valid;
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

  dre_auth->phi = NULL;
  dre_auth->phi_len = 0;

  return dre_auth;
}

void
dake_dre_auth_free(dake_dre_auth_t *dre_auth) {
  memset(dre_auth->nonce, 0, NONCE_BYTES);
  memset(dre_auth->gamma, 0, sizeof(dr_cs_encrypted_symmetric_key_t));
  memset(dre_auth->sigma, 0, sizeof(rs_auth_t));

  free(dre_auth->phi);
  dre_auth->phi = NULL;
  dre_auth->phi_len = 0;
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
                                   const user_profile_t *our_profile,
                                   const ec_public_key_t our_ecdh,
                                   const dh_mpi_t our_dh,
                                   const user_profile_t *their_profile,
                                   const ec_public_key_t their_ecdh,
                                   const dh_mpi_t their_dh) {

  *dst = NULL;
  size_t our_profile_len = 0, their_profile_len = 0;
  uint8_t *our_profile_buff = NULL, *their_profile_buff = NULL;

  if (!user_profile_aprint(&our_profile_buff, &our_profile_len, our_profile)) {
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
  cursor += serialize_ec_public_key(cursor, our_ecdh);
  cursor += serialize_dh_public_key(cursor, their_dh);
  cursor += serialize_dh_public_key(cursor, our_dh);

  return true;

generate_phi_message_error:
    free(our_profile_buff);
    free(their_profile_buff);
    free(*dst);
    return false;
}

static bool
sha3_256(uint8_t *dst, size_t dst_len, const uint8_t *src, size_t src_len) {
  if (gcry_md_get_algo_dlen(GCRY_MD_SHA3_256) != dst_len) {
    return false;
  }

  gcry_md_hash_buffer(GCRY_MD_SHA3_256, dst, src, src_len);
  return true;
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

  uint8_t enc_key[crypto_secretbox_KEYBYTES];
  memset(enc_key, 0, crypto_secretbox_KEYBYTES);
  if(!sha3_256(enc_key, crypto_secretbox_KEYBYTES, k, sizeof(dr_cs_symmetric_key_t))) {
    return false;
  }

  random_bytes(dre_auth->nonce, NONCE_BYTES);
  if(-1 == crypto_secretbox_easy(dre_auth->phi, phi_msg, phi_msg_len, dre_auth->nonce, (unsigned char*) enc_key)) {
    free(dre_auth->phi);
    dre_auth->phi = NULL;
    dre_auth->phi_len = 0;

    memset(enc_key, 0, crypto_secretbox_KEYBYTES);
    return false;
  }

  memset(enc_key, 0, crypto_secretbox_KEYBYTES);
  return true;
}

static bool
dake_dre_auth_generate_sigma_message(uint8_t **dst, size_t *dst_len,
                                     const user_profile_t *their_profile,
                                     const ec_public_key_t their_ecdh,
                                     const dh_mpi_t their_dh,
                                     const dake_dre_auth_t *dre_auth) {
  size_t our_profile_len = 0, their_profile_len = 0;
  uint8_t *our_profile_buff = NULL, *their_profile_buff = NULL;

  if (!user_profile_aprint(&our_profile_buff, &our_profile_len, dre_auth->profile)) {
    goto generate_sigma_message_error;
  }

  if (!user_profile_aprint(&their_profile_buff, &their_profile_len, their_profile)) {
    goto generate_sigma_message_error;
  }
  
  size_t s = our_profile_len      \
             + their_profile_len  \
             + sizeof(ec_public_key_t) \
             + DH3072_MOD_LEN_BYTES \
             + sizeof(dre_auth->gamma);

  *dst = malloc(s);
  if (*dst == NULL) {
    goto generate_sigma_message_error;
  }

  if (dst_len != NULL) { *dst_len = s; }

  uint8_t *cursor = *dst;
  cursor += serialize_bytes_array(cursor, their_profile_buff, their_profile_len);
  cursor += serialize_bytes_array(cursor, our_profile_buff, our_profile_len);
  cursor += serialize_ec_public_key(cursor, their_ecdh);
  cursor += serialize_dh_public_key(cursor, their_dh);
  cursor += serialize_bytes_array(cursor, dre_auth->gamma, sizeof(dre_auth->gamma));

  free(our_profile_buff);
  free(their_profile_buff);
  return true;

generate_sigma_message_error:
  free(our_profile_buff);
  free(their_profile_buff);
  return false;
}

static bool
dake_dre_auth_generate_sigma(const user_profile_t *their_profile,
                             const ec_public_key_t their_ecdh,
                             const dh_mpi_t their_dh,
                             const cs_keypair_t our_keypair,
                             dake_dre_auth_t *dre_auth) {
  uint8_t *sigma_msg = NULL;

  if (!dake_dre_auth_generate_sigma_message(&sigma_msg, NULL,
      their_profile, their_ecdh, their_dh, dre_auth)) {
    goto dake_dre_auth_generate_sigma_error;
  }

  ec_point_t their_ephemeral;
  if(!ec_point_deserialize(their_ephemeral, their_ecdh)) {
    goto dake_dre_auth_generate_sigma_error;
  }

  ring_signature_auth(dre_auth->sigma,
                      sigma_msg, our_keypair, their_profile->pub_key, their_ephemeral);

  free(sigma_msg);
  return true;

dake_dre_auth_generate_sigma_error:
  free(sigma_msg);
  return false;
}

bool
dake_dre_auth_generate_gamma_phi_sigma(const cs_keypair_t our_keypair,
                                       const ec_public_key_t our_ecdh,
                                       const dh_mpi_t our_dh,
                                       const user_profile_t *their_profile,
                                       const ec_public_key_t their_ecdh,
                                       const dh_mpi_t their_dh,
                                       dake_dre_auth_t *dre_auth) {
  dr_cs_symmetric_key_t k;
  if (!dake_dre_auth_generate_gamma(k, their_profile->pub_key, dre_auth)){
    return false;
  }

  uint8_t *phi_msg = NULL;
  size_t phi_msg_len = 0;
  if (!dake_dre_auth_generate_phi_message(&phi_msg, &phi_msg_len,
      dre_auth->profile, our_ecdh, our_dh, their_profile, their_ecdh, their_dh)) {
    return false;
  }

  if (!dake_dre_auth_generate_phi(phi_msg, phi_msg_len, k, dre_auth)) {
    free(phi_msg);
    return false;
  }
  free(phi_msg);

  if (!dake_dre_auth_generate_sigma(their_profile, their_ecdh, their_dh, our_keypair, dre_auth)) {
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

  cursor += serialize_bytes_array(cursor, dre_auth->gamma, sizeof(dr_cs_encrypted_symmetric_key_t));
  cursor += serialize_bytes_array(cursor, dre_auth->sigma, sizeof(rs_auth_t));
  cursor += serialize_bytes_array(cursor, dre_auth->nonce, NONCE_BYTES);
  cursor += serialize_bytes_array(cursor, dre_auth->phi, dre_auth->phi_len);

  free(our_profile);
  return true;
}


void
dake_dre_auth_deserialize(dake_dre_auth_t *target, uint8_t *data) {
    //TODO
    return;
}

static bool
dake_dre_auth_verify_sigma(const user_profile_t *their_profile,
                           const user_profile_t *our_profile,
                           const ec_public_key_t our_ecdh_pub,
                           const dh_mpi_t our_dh_pub,
                           const dake_dre_auth_t *dre_auth) {
  ec_point_t y;
  if (!ec_point_deserialize(y, our_ecdh_pub)) {
    return false;
  }

  uint8_t *sigma_msg = NULL;
  bool valid = dake_dre_auth_generate_sigma_message(&sigma_msg, NULL, our_profile, our_ecdh_pub, our_dh_pub, dre_auth);
  valid &= ring_signature_auth_valid(dre_auth->sigma, sigma_msg, their_profile->pub_key, our_profile->pub_key, y);

  free(sigma_msg);
  return valid;
}

bool
dake_dre_auth_validate(const user_profile_t *our_profile,
                       const cs_keypair_t our_cs_keypair,
                       const ec_public_key_t our_ecdh_pub,
                       const dh_mpi_t our_dh_pub,
                       const dake_dre_auth_t *dre_auth) {
  bool valid = user_profile_verify_signature(dre_auth->profile);
  valid &= not_expired(dre_auth->profile->expires);

  // TODO: something Nick said about degenerated keys

  //TODO: these validations could be part of otr_t
  dr_cs_symmetric_key_t k;
  valid &= dake_dre_auth_verify_sigma(dre_auth->profile, our_profile, our_ecdh_pub, our_dh_pub, dre_auth);
  valid &= dr_cs_decrypt(k, dre_auth->gamma, our_cs_keypair, dre_auth->profile->pub_key);

  uint8_t enc_key[crypto_secretbox_KEYBYTES];
  memset(enc_key, 0, crypto_secretbox_KEYBYTES);
  if(!sha3_256(enc_key, crypto_secretbox_KEYBYTES, k, sizeof(dr_cs_symmetric_key_t))) {
    return false;
  }

  //decrypt phi
  size_t msg_len = dre_auth->phi_len - crypto_secretbox_MACBYTES;
  uint8_t *phi_msg = malloc(msg_len);
  if (phi_msg == NULL) {
    return false;
  }

  if (crypto_secretbox_open_easy(phi_msg, dre_auth->phi, dre_auth->phi_len, dre_auth->nonce, enc_key) != 0) {
    return false; 
  }

  memset(enc_key, 0, crypto_secretbox_KEYBYTES);

  //I. deserialize dake_dre_auth_phi_msg_t from phi_msg
  //- our_profile
  //- their_profile
  //- our_ecdh
  //- their_ecdh
  //- our_dh
  //- their_dh

  //II. Check if their_ecdh and their_dh are valid
  //III. Check if our_profile matches with what we have sent.
  //IV. Check if their_profile matches the one in the DRE-AUTH body
  //V. Check if our_ecdh matches and has not been used.
  //VI. Check if our_dh matches and has not been used.

  //Verify the decripted message
  //a. Is X ok? are they the same?
  //b. Is A ok? are they the same?

  //ec_point_t x;
  //if (!ec_point_deserialize(x, dre_auth->X)) {
  //  return false;
  //}

  //valid &= ec_point_valid(x);
  //valid &= dh_mpi_valid(dre_auth->A);

  free(phi_msg);
  return valid;
}
