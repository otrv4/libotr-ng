#include <glib.h>
#include <time.h>

#include "../user_profile.h"

void
test_user_profile_create() {
  const char *handler = "handler@service.net";
  
  user_profile_t *profile = user_profile_get_or_create_for(handler);

  g_assert_cmpint(profile->pub_key->type, ==, 16);
  g_assert_cmpint(profile->version, ==, 4);
  g_assert_cmpint(profile->expires, >=, time(NULL) + 2592000);
  g_assert_cmpstr(profile->signature, !=, NULL);

  user_profile_free(profile);
}

int
main(int argc, char **argv) {
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/user_profile_create", test_user_profile_create);

  return g_test_run();
}
