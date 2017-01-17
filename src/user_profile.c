#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "user_profile.h"
#include "serialize.h"
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

  cramer_shoup_pub_key_t *pub_key = malloc(sizeof(cramer_shoup_pub_key_t));
  if (pub_key == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }
  pub_key->type = 0x10;
  memset(pub_key->c, 0, 56);
  memset(pub_key->d, 0, 56);
  memset(pub_key->h, 0, 56);

  profile->pub_key = pub_key;
  profile->versions = otrv4_strdup("4");
  profile->expires = time_get_three_months_from_now();
  memset(profile->signature, 0, 112);
  profile->transitional_signature = NULL;

  return profile;
}

void
user_profile_free(user_profile_t *profile) {
  free(profile->pub_key);
  profile->pub_key = NULL;

  free(profile->versions);
  profile->versions = NULL;

  free(profile->transitional_signature);
  profile->transitional_signature = NULL;

  free(profile);
}

int
user_profile_serialize(uint8_t *dst, const user_profile_t *profile) {
  uint8_t *target = dst;

  target += serialize_uint16(target, profile->pub_key->type);
  target += serialize_bytes_array(target, profile->pub_key->c, 56);
  target += serialize_bytes_array(target, profile->pub_key->d, 56);
  target += serialize_bytes_array(target, profile->pub_key->h, 56);
  target += serialize_bytes_array(target, (uint8_t*) profile->versions, strlen(profile->versions)+1);
  target += serialize_uint64(target, profile->expires);
  target += serialize_mpi(target, profile->signature, 112);
  target += serialize_mpi(target, profile->transitional_signature, 40);

  return target - dst;
}
