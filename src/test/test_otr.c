#include <glib.h>
#include <string.h>

#include "../otr.h"

typedef struct {
  otr_t *otr;
} otr_fixture_t;

void
otr_fixture_set_up(otr_fixture_t *otr_fixture, gconstpointer data) {
  otr_t *otr = otr_new();
  otr_start(otr);
  otr_fixture->otr = otr;
}

void
otr_fixture_teardown(otr_fixture_t *otr_fixture, gconstpointer data) {
  otr_free(otr_fixture->otr);
}

void
test_otr_starts_protocol() {
  otr_t *otr = otr_new();

  int started = otr_start(otr);

  g_assert_cmpint(started, ==, 0);
  g_assert_cmpint(otr->state, ==, OTR_STATE_START);
  g_assert_cmpint(otr->supported_versions, ==, OTR_ALLOW_V4);

  otr_free(otr);
}

void
test_otr_version_supports_v34(otr_fixture_t *otr_fixture, gconstpointer data) {
  otr_version_support_v3(otr_fixture->otr);

  g_assert_cmpint(otr_fixture->otr->supported_versions, ==, OTR_ALLOW_V3 | OTR_ALLOW_V4);
}

void
test_otr_builds_query_message(otr_fixture_t *otr_fixture, gconstpointer data) {
  char *message = "And some random invitation text.";

  char query_message[41];
  otr_build_query_message(query_message, otr_fixture->otr, message);

  char *expected_qm = "?OTRv4? And some random invitation text.";
  g_assert_cmpstr(query_message, ==, expected_qm);
}

void
test_otr_builds_query_message_v34(otr_fixture_t *otr_fixture, gconstpointer data) {
  otr_version_support_v3(otr_fixture->otr);
  char *message = "And some random invitation text.";

  char query_message[41];
  otr_build_query_message(query_message, otr_fixture->otr, message);

  char *expected_qm = "?OTRv34? And some random invitation text.";
  g_assert_cmpstr(query_message, ==, expected_qm);
}

void
test_otr_builds_whitespace_tag(otr_fixture_t *otr_fixture, gconstpointer data) {
  char *expected_tag = " \t  \t\t\t\t \t \t \t    \t\t \t  And some random invitation text.";
  char *message = "And some random invitation text.";

  char whitespace_tag[strlen(expected_tag)];
  otr_build_whitespace_tag(whitespace_tag, otr_fixture->otr, message);
  g_assert_cmpstr(whitespace_tag, ==, expected_tag);
}

void
test_otr_builds_whitespace_tag_v34(otr_fixture_t *otr_fixture, gconstpointer data) {
  otr_version_support_v3(otr_fixture->otr);
  char *expected_tag = " \t  \t\t\t\t \t \t \t    \t\t \t    \t\t  \t\tAnd some random invitation text";
  char *message = "And some random invitation text";

  char whitespace_tag[strlen(expected_tag)];
  otr_build_whitespace_tag(whitespace_tag, otr_fixture->otr, message);
  g_assert_cmpstr(whitespace_tag, ==, expected_tag);
}

void
test_otr_receives_plaintext_without_ws_tag_on_start(otr_fixture_t *otr_fixture, gconstpointer data) {
  otr_receive_message(otr_fixture->otr, "Some random text.");

  g_assert_cmpstr(otr_fixture->otr->message_to_display, ==, "Some random text.");
}

void
test_otr_receives_plaintext_without_ws_tag_not_on_start(otr_fixture_t *otr_fixture, gconstpointer data) {
  otr_fixture->otr->state = OTR_STATE_AKE_IN_PROGRESS;
  otr_receive_message(otr_fixture->otr, "Some random text.");

  g_assert_cmpstr(otr_fixture->otr->message_to_display, ==, "Some random text.");
  g_assert_cmpstr(otr_fixture->otr->warning, ==, "The above message was received unencrypted.");
}

void
test_otr_receives_plaintext_with_ws_tag(otr_fixture_t *otr_fixture, gconstpointer data) {

  otr_receive_message(otr_fixture->otr, " \t  \t\t\t\t \t \t \t    \t\t \t  And some random invitation text.");

  g_assert_cmpstr(otr_fixture->otr->message_to_display, ==, "And some random invitation text.");
  g_assert_cmpint(otr_fixture->otr->state, ==, OTR_STATE_AKE_IN_PROGRESS);
  //TODO: How to assert the pointer is not null without g_assert_nonnull?
  //g_assert_cmpint(otr_fixture->otr->pre_key, >, 0);
  g_assert_cmpint(otr_fixture->otr->running_version, ==, V4);
}

/* void */
/* test_otr_receives_plaintext_with_ws_tag_v3(otr_fixture_t *otr_fixture, gconstpointer data) { */

/*   otr_receive_message(otr_fixture->otr, " \t  \t\t\t\t \t \t \t    \t\t  \t\tAnd some random invitation text."); */

/*   g_assert_cmpstr(otr_fixture->otr->message_to_display, ==, "And some random invitation text."); */
/*   g_assert_cmpint(otr_fixture->otr->state, ==, OTR_STATE_AKE_IN_PROGRESS); */
/*   g_assert_cmpint(otr_fixture->otr->running_version, ==, V3); */
/* } */

int
main(int argc, char **argv) {
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/otr_starts_protocol", test_otr_starts_protocol);
  g_test_add("/otr_version_supports_v34", otr_fixture_t, NULL, otr_fixture_set_up, test_otr_version_supports_v34, otr_fixture_teardown );
  g_test_add("/otr_builds_query_message", otr_fixture_t, NULL, otr_fixture_set_up, test_otr_builds_query_message, otr_fixture_teardown );
  g_test_add("/otr_builds_query_message_v34", otr_fixture_t, NULL, otr_fixture_set_up, test_otr_builds_query_message_v34, otr_fixture_teardown );
  g_test_add("/otr_builds_whitespace_tag", otr_fixture_t, NULL, otr_fixture_set_up, test_otr_builds_whitespace_tag, otr_fixture_teardown );
  g_test_add("/otr_builds_whitespace_tag_v34", otr_fixture_t, NULL, otr_fixture_set_up, test_otr_builds_whitespace_tag_v34, otr_fixture_teardown );
  g_test_add("/otr_receives_plaintext_without_ws_tag_on_start", otr_fixture_t, NULL, otr_fixture_set_up, test_otr_receives_plaintext_without_ws_tag_on_start, otr_fixture_teardown );
  g_test_add("/otr_receives_plaintext_without_ws_tag_not_on_start", otr_fixture_t, NULL, otr_fixture_set_up, test_otr_receives_plaintext_without_ws_tag_not_on_start, otr_fixture_teardown );
  g_test_add("/otr_receives_plaintext_with_ws_tag", otr_fixture_t, NULL, otr_fixture_set_up, test_otr_receives_plaintext_with_ws_tag, otr_fixture_teardown );
  /* g_test_add("/otr_receives_plaintext_with_ws_tag_v3", otr_fixture_t, NULL, otr_fixture_set_up, test_otr_receives_plaintext_with_ws_tag_v3, otr_fixture_teardown ); */

  return g_test_run();
}
