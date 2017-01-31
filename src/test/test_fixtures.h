#include "../otrv4.h"
#include "../cramer_shoup.h"
#include "../user_profile.h"

typedef struct {
  otrv4_t *otr;
  cs_keypair_t keypair;
} otrv4_fixture_t;

void
otrv4_fixture_set_up(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  cs_generate_keypair(otrv4_fixture->keypair);
  otrv4_t *otr = otrv4_new(otrv4_fixture->keypair);
  otrv4_start(otr);
  otrv4_fixture->otr = otr;
}

void
otrv4_fixture_teardown(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  //cs_keypair_destroy();
  otrv4_free(otrv4_fixture->otr);
}



typedef struct {
  cs_keypair_t keypair;
  user_profile_t *profile;
} pre_key_fixture_t;

static void
pre_key_fixture_setup(pre_key_fixture_t *fixture, gconstpointer user_data) {
  cs_generate_keypair(fixture->keypair);
  fixture->profile = user_profile_new("4");
  otrv4_assert(fixture->profile != NULL);
  otrv4_assert(user_profile_sign(fixture->profile, fixture->keypair));
}

static void
pre_key_fixture_teardown(pre_key_fixture_t *fixture, gconstpointer user_data) {
    //cs_keypair_destroy();
    user_profile_free(fixture->profile);
    fixture->profile = NULL;
}

