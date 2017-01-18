#include <glib.h>

#include "test_otrv4.c"
#include "test_dake.c"
#include "test_user_profile.c"

int
main(int argc, char **argv) {
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/otrv4/starts_protocol", test_otrv4_starts_protocol);
  g_test_add("/otrv4/version_supports_v34", otrv4_fixture_t, NULL, otrv4_fixture_set_up, test_otrv4_version_supports_v34, otrv4_fixture_teardown );
  g_test_add("/otrv4/builds_query_message", otrv4_fixture_t, NULL, otrv4_fixture_set_up, test_otrv4_builds_query_message, otrv4_fixture_teardown );
  g_test_add("/otrv4/builds_query_message_v34", otrv4_fixture_t, NULL, otrv4_fixture_set_up, test_otrv4_builds_query_message_v34, otrv4_fixture_teardown );
  g_test_add("/otrv4/builds_whitespace_tag", otrv4_fixture_t, NULL, otrv4_fixture_set_up, test_otrv4_builds_whitespace_tag, otrv4_fixture_teardown );
  g_test_add("/otrv4/builds_whitespace_tag_v34", otrv4_fixture_t, NULL, otrv4_fixture_set_up, test_otrv4_builds_whitespace_tag_v34, otrv4_fixture_teardown );
  g_test_add("/otrv4/receives_plaintext_without_ws_tag_on_start", otrv4_fixture_t, NULL, otrv4_fixture_set_up, test_otrv4_receives_plaintext_without_ws_tag_on_start, otrv4_fixture_teardown );
  g_test_add("/otrv4/receives_plaintext_without_ws_tag_not_on_start", otrv4_fixture_t, NULL, otrv4_fixture_set_up, test_otrv4_receives_plaintext_without_ws_tag_not_on_start, otrv4_fixture_teardown );
  g_test_add("/otrv4/receives_plaintext_with_ws_tag", otrv4_fixture_t, NULL, otrv4_fixture_set_up, test_otrv4_receives_plaintext_with_ws_tag, otrv4_fixture_teardown );
  g_test_add("/otrv4/receives_plaintext_with_ws_tag_v3", otrv4_fixture_t, NULL, otrv4_fixture_set_up, test_otrv4_receives_plaintext_with_ws_tag_v3, otrv4_fixture_teardown );
  g_test_add("/otrv4/receives_query_message", otrv4_fixture_t, NULL, otrv4_fixture_set_up, test_otrv4_receives_query_message, otrv4_fixture_teardown);
  g_test_add("/otrv4/receives_query_message_v3", otrv4_fixture_t, NULL, otrv4_fixture_set_up, test_otrv4_receives_query_message_v3, otrv4_fixture_teardown);

  g_test_add_func("/dake/pre_key_new", test_dake_pre_key_new);
  g_test_add_func("/dake/pre_key_serializes", test_dake_pre_key_serializes);

  g_test_add_func("/user_profile/create", test_user_profile_create);
  g_test_add_func("/user_profile/serialize", test_user_profile_serializes);

  return g_test_run();
}