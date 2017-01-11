#include <stdlib.h>
#include <stdio.h>

#include "user_profile.h"

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
  pub_key->type = 0x0010;

  profile->pub_key = pub_key;
  profile->version = 0x0004;
  profile->expires = time_get_three_months_from_now();
  profile->signature[0] = '\0';
  // TODO: Add transitional signature

  return profile;
}

void
user_profile_free(user_profile_t *profile) {
  free(profile->pub_key);
  free(profile);
}
