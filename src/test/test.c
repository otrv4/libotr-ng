#include <glib.h>
#include <string.h>
#include <libdecaf/decaf.h>
#include "../ed448.h"

static inline void
otrv4_assert_cmpmem(const void* expected, const void *actual, size_t len) {
  g_assert_cmpint(memcmp(expected, actual, len), ==, 0);
}

static inline void
otrv4_assert_point_equals(const ec_point_t expected, const ec_point_t actual) {
  g_assert_cmpint(decaf_448_point_eq(expected, actual), !=, 0);
}

#include "test_otrv4.c"
#include "test_dake.c"
#include "test_user_profile.c"
#include "test_ed448.c"
#include "test_dh.c"
#include "test_serialize.c"

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

  g_test_add_func("/dake/protocol", test_dake_protocol);
  g_test_add_func("/dake/pre_key/new", test_dake_pre_key_new);
  g_test_add_func("/dake/pre_key/serializes", test_dake_pre_key_serializes);
  g_test_add_func("/dake/pre_key/deserializes", test_dake_pre_key_deserializes);
  g_test_add_func("/dake/pre_key/valid", test_dake_pre_key_valid);

  g_test_add_func("/user_profile/create", test_user_profile_create);
  g_test_add_func("/user_profile/serialize", test_user_profile_serializes);
  g_test_add_func("/user_profile/deserializes", test_user_profile_deserializes);

  g_test_add_func("/ed448/api", ed448_test_ecdh);

  g_test_add_func("/dh/api", dh_test_api);
  g_test_add_func("/dh/serialize", dh_test_serialize);

  g_test_add_func("/serialize_and_deserialize/uint", test_ser_deser_uint);

  return g_test_run();
}
