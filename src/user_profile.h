#ifndef USER_PROFILE_H
#define USER_PROFILE_H

#include <time.h>
#include <stdint.h>

#include "mpi.h"
#include "ed448.h"
#include "cramer_shoup.h"

typedef struct {
  /// ??? Spec does not keep relationship between profile and handler.
  /// ??? Should keep it or this would leak information?
  cs_public_key_t pub_key[1];
  char *versions;
  /// ??? Spec defines profile expiration as '8 bytes signed value'. time_t
  /// casts to long. Define new type and make convertions?
  uint64_t expires;
  ec_signature_t signature;
  otr_mpi_t transitional_signature;
} user_profile_t;

user_profile_t*
user_profile_new();

void
user_profile_copy(user_profile_t *dst, const user_profile_t *src);

user_profile_t *
user_profile_get_or_create_for(const char *handler);

void
user_profile_free(user_profile_t *profile);

int
user_profile_serialize(uint8_t *target, const user_profile_t *profile);

bool
user_profile_deserialize(user_profile_t *target, const uint8_t *serialized, size_t ser_len);

bool
user_profile_signature_validate(const uint8_t signature[112]);

#endif
