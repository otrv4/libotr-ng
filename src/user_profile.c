#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "user_profile.h"
#include "serialize.h"
#include "deserialize.h"
#include "mpi.h"
#include "str.h"

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
user_profile_sign(user_profile_t *profile, const cs_keypair_t keypair) {
  // Cant be done like in the spec.
  // decaf_448_sign needs a private key (sym, secret_scalar and public) in
  // order to sign.
  cs_public_key_copy(profile->pub_key, keypair->pub);

  //TODO: actually sign and remove this
  memset(profile->signature, 0xFF, sizeof(ec_signature_t));
}

void
user_profile_verify_signature(const cs_public_key_t *pub, const ec_signature_t sig) {
    //TODO
}

void
user_profile_copy(user_profile_t *dst, const user_profile_t *src) {
  if (src == NULL) {
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

//TODO this can overflow because serialize doesnt know how much it can write
int
user_profile_serialize(uint8_t *dst, const user_profile_t *profile) {
  uint8_t *target = dst;

  target += serialize_cs_public_key(target, profile->pub_key);  
  target += serialize_bytes_array(target, (uint8_t*) profile->versions, strlen(profile->versions)+1);
  target += serialize_uint64(target, profile->expires);

  otr_mpi_t signature_mpi;
  otr_mpi_set(signature_mpi, profile->signature, sizeof(ec_signature_t));
  target += serialize_mpi(target, signature_mpi);

  target += serialize_mpi(target, profile->transitional_signature);

  return target - dst;
}

bool
user_profile_deserialize(user_profile_t *target, const uint8_t *serialized, size_t ser_len) {
  size_t read = 0;
  int walked = 0;

  //TODO error
  if (!deserialize_cs_public_key(target->pub_key, serialized, ser_len) ) {
    return false;
  }
  walked += 2+3*56; //TODO

  size_t versions_len = strlen((const char*) serialized+walked);
  if (versions_len > ser_len - walked) {
    return false; //TODO error
  }

  target->versions = malloc(versions_len+1);
  if (target->versions == NULL) {
    return false;
  }
  
  memcpy(target->versions, serialized+walked, versions_len+1);
  walked += versions_len+1;

  if (!deserialize_uint64(&target->expires, serialized+walked, ser_len-walked, &read)) {
    return false;
  }
  walked += read;

  otr_mpi_t signature_mpi;
  if (!otr_mpi_deserialize(signature_mpi, serialized+walked, ser_len-walked, &read)) {
    return false;
  }
  walked += read;

  //TODO this could be an otr_mpi_memcpy
  memcpy(target->signature, signature_mpi->data, signature_mpi->len);
  otr_mpi_free(signature_mpi);

  if (!otr_mpi_deserialize(target->transitional_signature, serialized+walked, ser_len-walked, &read)) {
    return false;
  }

  return true;
}

// TODO: implement signature validation.
bool
user_profile_signature_validate(const uint8_t signature[112]) {
  return false;
}
