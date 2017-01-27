#include "../cramer_shoup.h"
#include "../user_profile.h"

typedef struct {
  cs_keypair_t keypair;
  user_profile_t *profile;
} pre_key_fixture_t;

static void
pre_key_fixture_setup(pre_key_fixture_t *fixture, gconstpointer user_data) {
  cs_generate_keypair(fixture->keypair);
  fixture->profile = user_profile_new("4");
  otrv4_assert(fixture->profile != NULL);
  user_profile_sign(fixture->profile, fixture->keypair);
}

static void
pre_key_fixture_teardown(pre_key_fixture_t *fixture, gconstpointer user_data) {
    //cs_keypair_destroy();
    user_profile_free(fixture->profile);
    fixture->profile = NULL;
}

