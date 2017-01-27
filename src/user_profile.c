#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "user_profile.h"
#include "serialize.h"
#include "deserialize.h"
#include "mpi.h"
#include "str.h"
#include "random.h"

user_profile_t*
user_profile_new(const char* versions) {
  if (versions == NULL) {
    return NULL;
  }

  user_profile_t *profile = malloc(sizeof(user_profile_t));
  if (profile == NULL) {
    return NULL;
  }

  profile->versions = otrv4_strdup(versions);

  memset(profile->signature, 0, sizeof(ec_signature_t));
  otr_mpi_init(profile->transitional_signature);

  return profile;
}

void
user_profile_copy(user_profile_t *dst, const user_profile_t *src) {
  if (src == NULL) {
    //TODO should we set dst to a valid (but empty) profile?
    return;
  }

  cs_public_key_copy(dst->pub_key, src->pub_key);
  dst->versions = otrv4_strdup(src->versions);
  dst->expires = src->expires;

  memcpy(dst->signature, src->signature, sizeof(ec_signature_t));
  otr_mpi_copy(dst->transitional_signature, src->transitional_signature);
}

void
user_profile_free(user_profile_t *profile) {
  free(profile->versions);
  profile->versions = NULL;

  otr_mpi_free(profile->transitional_signature);

  free(profile);
}

static int
user_profile_serialize_body(uint8_t *dst, const user_profile_t *profile) {
  uint8_t *target = dst;

  target += serialize_cs_public_key(target, profile->pub_key);  
  target += serialize_bytes_array(target, (uint8_t*) profile->versions, strlen(profile->versions)+1);
  target += serialize_uint64(target, profile->expires);

  return target - dst;
}

//TODO this can overflow because serialize doesnt know how much it can write
int
user_profile_serialize(uint8_t *dst, const user_profile_t *profile) {
  uint8_t *target = dst;
  target += user_profile_serialize_body(dst, profile); //TODO: this could be cached in the data structure

  otr_mpi_t signature_mpi;
  otr_mpi_set(signature_mpi, profile->signature, sizeof(ec_signature_t));
  target += serialize_mpi(target, signature_mpi);

  target += serialize_mpi(target, profile->transitional_signature);

  return target - dst;
}

bool
user_profile_deserialize(user_profile_t *target, const uint8_t *buffer, size_t buflen, size_t *nread) {
  size_t read = 0;
  int walked = 0;

  if (!deserialize_cs_public_key(target->pub_key, buffer, buflen) ) {
    goto deserialize_error;
  }

  walked += 2+3*56; //TODO

  size_t versions_len = strlen((const char*) buffer+walked);
  if (versions_len > buflen - walked) {
    goto deserialize_error;
  }

  target->versions = malloc(versions_len+1);
  if (target->versions == NULL) {
    goto deserialize_error;
  }
  
  memcpy(target->versions, buffer+walked, versions_len+1);
  walked += versions_len+1;

  if (!deserialize_uint64(&target->expires, buffer+walked, buflen-walked, &read)) {
    goto deserialize_error;
  }
  walked += read;

  otr_mpi_t signature_mpi; // no need to free, because nothing is copied now
  if (!otr_mpi_deserialize_no_copy(signature_mpi, buffer+walked, buflen-walked, &read)) {
    goto deserialize_error;
  }

  walked += read;
  walked += otr_mpi_memcpy(target->signature, signature_mpi);

  if (!otr_mpi_deserialize(target->transitional_signature, buffer+walked, buflen-walked, &read)) {
    goto deserialize_error;
  }

  walked += read;

  if (nread != NULL) { *nread = walked; }
  return true;

deserialize_error:
  if (nread != NULL) { *nread = walked; }
  return false;
}

void
user_profile_sign(user_profile_t *profile, const cs_keypair_t keypair) {
  cs_public_key_copy(profile->pub_key, keypair->pub);

  size_t profile_body_len = 170+10+8;
  uint8_t *profile_body = malloc(profile_body_len);
  if (profile_body == NULL) { return; } //TODO: error
  user_profile_serialize_body(profile_body, profile);

  //unlike the decaf spec, we take a random symm for each signature
  ec_keypair_t sig_key;
  random_bytes(sig_key->sym, sizeof(ec_symmetric_key_t)); // TODO: use the "symmetric nonce"
  ec_scalar_copy(sig_key->secret_scalar, keypair->priv->z);
  ec_point_serialize(sig_key->pub, sizeof(ec_public_key_t), keypair->pub->h);

  ec_sign(profile->signature, sig_key, profile_body, profile_body_len);
  ec_keypair_destroy(sig_key);
  free(profile_body);
}

bool
user_profile_verify_signature(const user_profile_t *profile) {
  size_t profile_body_len = 170+10+8;
  uint8_t *profile_body = malloc(profile_body_len);
  if (profile_body == NULL) { return false; }
  user_profile_serialize_body(profile_body, profile);

  ec_public_key_t sign_pub_key;
  ec_point_serialize(sign_pub_key, sizeof(ec_public_key_t), profile->pub_key->h);
  bool ok = ec_verify(profile->signature, sign_pub_key, profile_body, profile_body_len);
  free(profile_body);

  return ok;
}

