#include "../otrv4.h"
#include "../cramershoup_interface.h"
#include "../user_profile.h"

typedef struct {
  otrv4_t *otr;
  cs_keypair_t keypair;
} otrv4_fixture_t;

void
otrv4_fixture_set_up(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  cs_keypair_generate(otrv4_fixture->keypair);
  otrv4_t *otr = otrv4_new(otrv4_fixture->keypair);
  otrv4_start(otr);
  dh_init();
  otrv4_fixture->otr = otr;
}

void
otrv4_fixture_teardown(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  ec_keypair_destroy(otrv4_fixture->otr->our_ecdh);
  otrv4_free(otrv4_fixture->otr);
  cs_keypair_destroy(otrv4_fixture->keypair);
}



typedef struct {
  cs_keypair_t keypair;
  user_profile_t *profile;
} pre_key_fixture_t;

static void
pre_key_fixture_setup(pre_key_fixture_t *fixture, gconstpointer user_data) {
  cs_keypair_generate(fixture->keypair);
  fixture->profile = user_profile_new("4");
  otrv4_assert(fixture->profile != NULL);
  fixture->profile->expires = time(NULL) + 60 * 60;
  otrv4_assert(user_profile_sign(fixture->profile, fixture->keypair));
}

static void
pre_key_fixture_teardown(pre_key_fixture_t *fixture, gconstpointer user_data) {
  cs_keypair_destroy(fixture->keypair);
  user_profile_free(fixture->profile);
  fixture->profile = NULL;
}

