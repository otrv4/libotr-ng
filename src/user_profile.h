#ifndef USER_PROFILE_H
#define USER_PROFILE_H

#include <stdint.h>

#include "mpi.h"
#include "cramer_shoup.h"

typedef struct {
  cs_public_key_t pub_key[1];
  char *versions;
  uint64_t expires;
  ec_signature_t signature;
  otr_mpi_t transitional_signature;
} user_profile_t;

user_profile_t*
user_profile_new(const char* versions);

bool
user_profile_sign(user_profile_t *profile, const cs_keypair_t keypair);

bool
user_profile_verify_signature(const user_profile_t *profile);

void
user_profile_copy(user_profile_t *dst, const user_profile_t *src);

void
user_profile_free(user_profile_t *profile);

bool
user_profile_deserialize(user_profile_t *target, const uint8_t *buffer, size_t buflen, size_t *nread);

bool
user_profile_body_aprint(uint8_t **dst, size_t *nbytes, const user_profile_t *profile);

bool
user_profile_aprint(uint8_t **dst, size_t *nbytes, const user_profile_t *profile);

#endif
