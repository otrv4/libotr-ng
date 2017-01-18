#ifndef USER_PROFILE_H
#define USER_PROFILE_H

#include <time.h>
#include <stdint.h>

typedef struct {
  uint16_t type;
  uint8_t c[56];
  uint8_t d[56];
  uint8_t h[56];
} cramer_shoup_pub_key_t;

typedef struct {
  /// ??? Spec does not keep relationship between profile and handler.
  /// ??? Should keep it or this would leak information?
  cramer_shoup_pub_key_t *pub_key;
  char *versions;
  /// ??? Spec defines profile expiration as '8 bytes signed value'. time_t
  /// casts to long. Define new type and make convertions?
  time_t expires;
  uint8_t signature[112];
  uint8_t *transitional_signature;
} user_profile_t;

user_profile_t *
user_profile_get_or_create_for(const char *handler);

void
user_profile_free(user_profile_t *profile);

int
user_profile_serialize(uint8_t *target, const user_profile_t *profile);

#endif
