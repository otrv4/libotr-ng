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
user_profile_new(const string_t versions) {
  if (versions == NULL) {
    return NULL;
  }

  user_profile_t *profile = malloc(sizeof(user_profile_t));
  if (profile == NULL) {
    return NULL;
  }

  profile->expires = 0;
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
  if (profile == NULL) {
    return;
  }

  //free the pubkey

  free(profile->versions);
  profile->versions = NULL;
  otr_mpi_free(profile->transitional_signature);

  free(profile);
}

static int
user_profile_body_serialize(uint8_t *dst, const user_profile_t *profile) {
  uint8_t *target = dst;

  target += serialize_cs_public_key(target, profile->pub_key);  
  target += serialize_bytes_array(target, (uint8_t*) profile->versions, strlen(profile->versions)+1);
  target += serialize_uint64(target, profile->expires);

  return target - dst;
}

#define EC_PUBLIC_KEY_BYTES (2+3*56)

bool
user_profile_body_aprint(uint8_t **dst, size_t *nbytes, const user_profile_t *profile) {
  size_t s = EC_PUBLIC_KEY_BYTES + strlen(profile->versions)+1 + 8;

  uint8_t *buff = malloc(s);
  if (buff == NULL) {
    return false;
  }

  user_profile_body_serialize(buff, profile);

  *dst = buff;
  if (nbytes != NULL) { *nbytes = s; }

  return true;
}

bool
user_profile_aprint(uint8_t **dst, size_t *nbytes, const user_profile_t *profile) {
  //TODO: should it check if the profile is signed?
  uint8_t *buff = NULL;

  otr_mpi_t signature_mpi;
  otr_mpi_set(signature_mpi, profile->signature, sizeof(ec_signature_t));

  size_t body_len = 0;
  uint8_t *body = NULL;
  if (!user_profile_body_aprint(&body, &body_len, profile)) {
    return false;
  }

  size_t s = body_len + 4+signature_mpi->len + 4+profile->transitional_signature->len;
  buff = malloc(s);
  if (buff == NULL) {
    free(body);
    return false;
  }

  uint8_t *cursor = buff;
  cursor += serialize_bytes_array(cursor, body, body_len);
  cursor += serialize_mpi(cursor, signature_mpi);
  cursor += serialize_mpi(cursor, profile->transitional_signature);

  *dst = buff;
  if (nbytes != NULL) { *nbytes = s; }

  free(body);
  return true;
}

bool
user_profile_deserialize(user_profile_t *target, const uint8_t *buffer, size_t buflen, size_t *nread) {
  size_t read = 0;
  int walked = 0;

  if (target == NULL) {
    return false;
  }

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

bool
user_profile_sign(user_profile_t *profile, const cs_keypair_t keypair) {
  cs_public_key_copy(profile->pub_key, keypair->pub);

  size_t body_len = 0;
  uint8_t *body = NULL;
  if (!user_profile_body_aprint(&body, &body_len, profile)) {
    return false;
  }

  //unlike the decaf spec, we take a random symm for each signature
  ec_keypair_t sig_key;
  random_bytes(sig_key->sym, sizeof(ec_symmetric_key_t)); // TODO: use the "symmetric nonce"
  ec_scalar_copy(sig_key->secret_scalar, keypair->priv->z);
  ec_point_serialize(sig_key->pub, sizeof(ec_public_key_t), keypair->pub->h);

  ec_sign(profile->signature, sig_key, body, body_len);
  ec_keypair_destroy(sig_key);

  return true;
}

//TODO: I dont think this needs the data structure. Could verify from the
//deserialized bytes.
bool
user_profile_verify_signature(const user_profile_t *profile) {
  size_t body_len = 0;
  uint8_t *body = NULL;
  if (!user_profile_body_aprint(&body, &body_len, profile)){
    return false;
  }

  ec_public_key_t sign_pub_key;
  ec_point_serialize(sign_pub_key, sizeof(ec_public_key_t), profile->pub_key->h);
  bool ok = ec_verify(profile->signature, sign_pub_key, body, body_len);

  free(body);

  return ok;
}

