#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "user_profile.h"
#include "serialize.h"
#include "deserialize.h"
#include "str.h"

// TODO: Completely arbitrary expiration date. Should come from configuration.
static time_t
time_get_three_months_from_now() {
  time_t today = time(NULL);
  time_t secs_to_three_monts = 60 * 60 * 24 * 30;
  return today + secs_to_three_monts;
}

// TODO: need to review errors on this function.
user_profile_t *
user_profile_get_or_create_for(const char *handler) {
  if (handler == NULL) {
    fprintf(stderr, "Handler is required to create a profile");
    exit(EXIT_FAILURE);
  }

  user_profile_t *profile = malloc(sizeof(user_profile_t));
  if (profile == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }

  cs_public_key_t *pub_key = malloc(sizeof(cs_public_key_t));
  if (pub_key == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }

  profile->pub_key = pub_key;
  profile->versions = otrv4_strdup("4");
  profile->expires = time_get_three_months_from_now();
  memset(profile->signature, 0, EC_SIGNATURE_BYTES);
  profile->transitional_signature = NULL;

  return profile;
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

int
user_profile_deserialize(user_profile_t *target, const uint8_t *serialized, size_t ser_len) {
  int walked = 0;

  //TODO error
  if (!deserialize_cs_public_key(target->pub_key, serialized, ser_len) ) {
    return 1;
  }
  walked += 2+3*56; //TODO

  size_t versions_len = strlen((const char*) serialized+walked);
  if (versions_len > ser_len - walked) {
    return 1; //TODO error
  }

  target->versions = malloc(versions_len+1);
  if (target->versions == NULL) {
    return 1;
  }
  
  memcpy(target->versions, serialized+walked, versions_len+1);
  walked += versions_len+1;

  if (sizeof(uint64_t) > ser_len - walked) {
    return 1;
  }
  
  deserialize_uint64(&target->expires, serialized + walked);
  walked += sizeof(uint64_t);

  if (sizeof(uint32_t) > ser_len - walked) {
    return 1;
  }

  uint32_t sig_len = 0;
  deserialize_uint32(&sig_len, serialized+walked);
  walked += sizeof(uint32_t);
  
  if (sig_len != EC_SIGNATURE_BYTES) {
    return 1;
  }

  if (sig_len > ser_len - walked) {
    return 1;
  }
  
  memcpy(target->signature, serialized+walked, EC_SIGNATURE_BYTES);
  walked += EC_SIGNATURE_BYTES;

  if (sizeof(uint32_t) > ser_len - walked) {
    return 1;
  }
  
  uint32_t trans_sig_len = 0;
  deserialize_uint32(&trans_sig_len, serialized+walked);
  walked += sizeof(uint32_t);

  if (trans_sig_len > ser_len - walked) {
    return 1;
  }

  target->transitional_signature = NULL;
  if (trans_sig_len > 0) {
    target->transitional_signature = malloc(trans_sig_len);
    if (target->transitional_signature == NULL) {
      return 1;
    }
    memcpy(target->transitional_signature, serialized+walked, trans_sig_len);
  }

  return 0;
}

// TODO: implement signature validation.
int
user_profile_signature_validate(const uint8_t signature[112]) {
  return 0;
}
