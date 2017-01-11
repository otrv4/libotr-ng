#include <time.h>

typedef struct {
  short type;
} cramer_shoup_pub_key_t;

typedef struct {
  /// ??? Spec does not keep relationship between profile and handler.
  /// ??? Should keep it or this would leak information?
  cramer_shoup_pub_key_t *pub_key;
  char version;
  /// ??? Spec defines profile expiration as '8 bytes signed value'. time_t
  /// casts to long. Define new type and make convertions?
  time_t expires;
  char signature[112];
} user_profile_t;

user_profile_t *
user_profile_get_or_create_for(const char *handler);

void
user_profile_free(user_profile_t *profile);
