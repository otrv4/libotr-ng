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

  //TODO: initialize ephemeral keys
  
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
dake_dre_auth_new(const user_profile_t *our_profile, const user_profile_t *sender_profile) {
  if (our_profile == NULL || sender_profile == NULL) {
    return NULL;
  }

  dake_dre_auth_t *dre_auth = malloc(sizeof(dake_dre_auth_t));
  if (dre_auth  == NULL) {
    return NULL;
  }

  dre_auth->sender_instance_tag = 0;
  dre_auth->receiver_instance_tag = 0;
  user_profile_copy(dre_auth->our_profile, our_profile);
  user_profile_copy(dre_auth->sender_profile, sender_profile);

  return dre_auth;
}

void
dake_dre_auth_free(dake_dre_auth_t *dre_auth) {
}

static bool
dake_dre_auth_generate_gamma(dr_cs_symmetric_key_t k,
                             
                             dake_dre_auth_t *dre_auth) {
  dr_cs_generate_symmetric_key(k);
  if (!dr_cs_encrypt(dre_auth->gamma, k, dre_auth->our_profile->pub_key, dre_auth->sender_profile->pub_key)) {
    return false;
  }

  return true;
}

static bool
dake_dre_auth_generate_cipher(dr_cs_symmetric_key_t k,
                              ec_public_key_t their_ecdh,
                              dh_mpi_t their_dh,
                              dake_dre_auth_t *dre_auth) {

  //TODO: pass as parameter
  size_t our_profile_len = 0, their_profile_len = 0;
  uint8_t *their_profile = NULL, *our_profile = NULL;

  size_t msg_len = our_profile_len \
                   + their_profile_len \
                   + 2*sizeof(ec_public_key_t) \
                   + 2*DH3072_MOD_LEN_BYTES;

  uint8_t *m = malloc(msg_len);
  if (m == NULL) {
    return false;
  }

  uint8_t *target = m;
  target += serialize_bytes_array(target, their_profile, their_profile_len);
  target += serialize_bytes_array(target, our_profile, our_profile_len);
  target += serialize_ec_public_key(target, their_ecdh);
  target += serialize_ec_public_key(target, dre_auth->X);
  target += serialize_dh_public_key(target, their_dh);
  target += serialize_dh_public_key(target, dre_auth->A);

  uint8_t *enc_key[crypto_secretbox_KEYBYTES] = {0};
  uint8_t *cipher = malloc(crypto_secretbox_MACBYTES + msg_len);
  if (cipher == NULL) {
    return false;
  }

  //TODO: sha3(ec_key, k);
  random_bytes(dre_auth->nonce, NONCE_BYTES);
  if(-1 == crypto_secretbox_easy(cipher, m, msg_len, dre_auth->nonce, (unsigned char*) enc_key)) {
    return false;
  }

  return true;
}

static bool
dake_dre_auth_generate_sigma(ec_public_key_t their_ecdh,
                             dh_mpi_t their_dh,
                             dake_dre_auth_t *dre_auth) {
  
  //TODO: pass as parameter
  size_t our_profile_len = 0, their_profile_len = 0;
  uint8_t *their_profile = NULL, *our_profile = NULL;
  
  size_t sigma_msg_len = our_profile_len      \
                         + their_profile_len  \
                         + sizeof(ec_public_key_t) \
                         + DH3072_MOD_LEN_BYTES \
                         + sizeof(dre_auth->gamma);
  
  uint8_t *sigma_msg = malloc(sigma_msg_len);
  if (sigma_msg == NULL) {
    return false;
  }
  
  uint8_t *target = sigma_msg;
  target += serialize_bytes_array(target, their_profile, their_profile_len);
  target += serialize_bytes_array(target, our_profile, our_profile_len);
  target += serialize_ec_public_key(target, their_ecdh);
  target += serialize_dh_public_key(target, their_dh);
  target += serialize_bytes_array(target, dre_auth->gamma, sizeof(dre_auth->gamma));

  ec_point_t their_ephemeral;
  if(!ec_point_deserialize(their_ephemeral, their_ecdh)) {
    return false;
  }

  //TODO: get this from somewhere else
  cs_keypair_t keypair;
  cs_public_key_t their_pub[1];
  ring_signature_auth(dre_auth->sigma, sigma_msg, keypair, their_pub, their_ephemeral);

  return true;
}

static bool
dake_dre_auth_generate_gamma_sigma(dake_dre_auth_t *dre_auth,
                                   ec_public_key_t their_ecdh,
                                   dh_mpi_t their_dh) {

  dr_cs_symmetric_key_t k;
  dake_dre_auth_generate_gamma(k, dre_auth);
  dake_dre_auth_generate_cipher(k, their_ecdh, their_dh, dre_auth);
  dake_dre_auth_generate_sigma(their_ecdh, their_dh, dre_auth);

  return true;
}

bool
dake_dre_auth_aprint(uint8_t **dst, size_t *nbytes, const dake_dre_auth_t *dre_auth) {
  size_t our_profile_len = 0, their_profile_len = 0;
  uint8_t *our_profile = NULL, *their_profile = NULL;
  if (!user_profile_aprint(&our_profile, &our_profile_len, dre_auth->our_profile)) {
    return false;
  }

  if (!user_profile_aprint(&their_profile, &their_profile_len, dre_auth->sender_profile)) {
    free(our_profile);
    return false;
  }

  size_t s = DRE_AUTH_MIN_BYTES + sizeof(cipher);
  *dst = malloc(s);
  if (*dst == NULL) {
    free(our_profile);
    free(their_profile);
    free(m);
    return false;
  }

  if (nbytes != NULL) { *nbytes = s; }

  //Here we finally do the serialization
  target = *dst;
  target += serialize_uint16(target, OTR_VERSION);
  target += serialize_uint8(target, OTR_DRE_AUTH_MSG_TYPE);
  target += serialize_uint32(target, dre_auth->sender_instance_tag);
  target += serialize_uint32(target, dre_auth->receiver_instance_tag);
  target += serialize_bytes_array(target, our_profile, our_profile_len);
  target += serialize_ec_public_key(target, dre_auth->X);
  target += serialize_dh_public_key(target, dre_auth->A);

  target += serialize_bytes_array(target, dre_auth->gamma, sizeof(dr_cs_encrypted_symmetric_key_t));
  target += serialize_bytes_array(target, dre_auth->sigma, sizeof(rs_auth_t));
  target += serialize_bytes_array(target, dre_auth->nonce, NONCE_BYTES);
  target += serialize_bytes_array(target, cipher, sizeof(cipher));

  free(our_profile);
  free(their_profile);
  free(m);
  free(sigma_msg);
  free(sigma);
  free(cipher);
  memset(nonce, 0, sizeof(nonce));
  memset(gamma, 0, sizeof(gamma));
  memset(enc_key, 0, sizeof(enc_key));

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

