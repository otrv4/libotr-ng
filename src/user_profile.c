#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "user_profile.h"
#include "serialize.h"
#include "deserialize.h"
#include "str.h"

user_profile_t*
user_profile_new() {
  user_profile_t *profile = malloc(sizeof(user_profile_t));
  if (profile == NULL) {
      return NULL;
  }

  profile->versions = NULL;
  profile->transitional_signature = NULL;

  return profile;
}

// TODO: need to review errors on this function.
// TODO: remove in a moment
user_profile_t *
user_profile_get_or_create_for(const char *handler) {
  if (handler == NULL) {
    fprintf(stderr, "Handler is required to create a profile");
    exit(EXIT_FAILURE);
  }

  return user_profile_new();
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

  //TODO: this should be an MPI and there should be no need to check this
  if (src->transitional_signature != NULL) {
    memcpy(dst->transitional_signature, src->transitional_signature,  40); // TODO
  }
}

void
user_profile_free(user_profile_t *profile) {
  free(profile->versions);
  profile->versions = NULL;

  free(profile->transitional_signature);
  profile->transitional_signature = NULL;

  free(profile);
}

int
user_profile_serialize(uint8_t *dst, const user_profile_t *profile) {
  uint8_t *target = dst;

  target += serialize_cs_public_key(target, profile->pub_key);  
  target += serialize_bytes_array(target, (uint8_t*) profile->versions, strlen(profile->versions)+1);
  target += serialize_uint64(target, profile->expires);
  target += serialize_mpi(target, profile->signature, 112);
  target += serialize_mpi(target, profile->transitional_signature, 40);

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

  if (sizeof(uint64_t) > ser_len - walked) {
    return false;
  }
  
  if (!deserialize_uint64(&target->expires, serialized+walked, ser_len-walked, &read)) {
      return false;
  }
  walked += read;

  uint8_t *signature = NULL;
  if (!deserialize_mpi(&signature, serialized+walked, ser_len-walked, &read)) {
      return false;
  }

  size_t signature_len = read-sizeof(uint32_t);
  if (signature_len > sizeof(ec_signature_t)) {
    free(signature);
    return false;
  }

  memcpy(target->signature, signature, signature_len);
  free(signature);
  walked += read;

  if (sizeof(uint32_t) > ser_len - walked) {
    return false;
  }
  
  if (!deserialize_mpi(&target->transitional_signature, serialized+walked, ser_len-walked, &read)) {
      return false;
  }

  return true;
}

// TODO: implement signature validation.
bool
user_profile_signature_validate(const uint8_t signature[112]) {
  return false;
}
