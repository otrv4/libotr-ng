#include <glib.h>

#include <stdio.h>
#include <string.h>

#include "../otr.h"

void
test_otr_starts_protocol() {
  otr *otr = otr_malloc();

  int started = otr_start(otr);

  g_assert_cmpint(started, ==, 0);
  g_assert_cmpint(otr->supported_versions, ==, OTR_ALLOW_V4);
  g_assert_cmpstr(otr->state, ==, OTRSTATE_START);

  otr_free(otr);
}

void
test_otr_version_support_v34() {
  otr *otr = otr_malloc();
  otr_start(otr);

  otr_version_support_v3(otr);

  g_assert_cmpint(otr->supported_versions, ==, OTR_ALLOW_V3 | OTR_ALLOW_V4);

  otr_free(otr);
}

void
test_otr_builds_query_message() {
  otr *otr = otr_malloc();
  otr_start(otr);
  char *message = "And some random invitation text.";

  char query_message[41];
  otr_build_query_message(query_message, otr, message);

  char *expected_qm = "?OTRv4? And some random invitation text.";
  g_assert_cmpstr(query_message, ==, expected_qm);

  otr_free(otr);
}

void
test_otr_builds_query_message_v34() {
  otr *otr = otr_malloc();
  otr_start(otr);
  otr_version_support_v3(otr);
  char *message = "And some random invitation text.";

  char query_message[41];
  otr_build_query_message(query_message, otr, message);

  char *expected_qm = "?OTRv34? And some random invitation text.";
  g_assert_cmpstr(query_message, ==, expected_qm);

  otr_free(otr);
}

void
test_otr_builds_whitespace_tag() {
  otr *otr = otr_malloc();
  otr_start(otr);

  char *expected_tag = " \t  \t\t\t\t \t \t \t    \t\t \t  And some random invitation text.";
  char *message = "And some random invitation text.";

  char whitespace_tag[strlen(expected_tag)];
  int error = otr_build_whitespace_tag(whitespace_tag, otr, message);
  g_assert_false(error);
  g_assert_cmpstr(whitespace_tag, ==, expected_tag);

  otr_free(otr);
}

void
test_otr_builds_whitespace_tag_v34() {
  otr *otr = otr_malloc();
  otr_start(otr);
  otr_version_support_v3(otr);

  char *expected_tag = " \t  \t\t\t\t \t \t \t    \t\t \t    \t\t  \t\tAnd some random invitation text";
  char *message = "And some random invitation text";

  char whitespace_tag[strlen(expected_tag)];
  int error = otr_build_whitespace_tag(whitespace_tag, otr, message);
  g_assert_false(error);
  g_assert_cmpstr(whitespace_tag, ==, expected_tag);

  otr_free(otr);
}

int
main(int argc, char **argv) {
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/otr_starts_protocol", test_otr_starts_protocol);
  g_test_add_func("/otr_version_support_v34", test_otr_version_support_v34);
  g_test_add_func("/otr_builds_query_message", test_otr_builds_query_message);
  g_test_add_func("/otr_builds_query_message_34", test_otr_builds_query_message_v34);
  g_test_add_func("/otr_builds_whitespace_tag", test_otr_builds_whitespace_tag);
  g_test_add_func("/otr_builds_whitespace_tag_v34", test_otr_builds_whitespace_tag_v34);

  return g_test_run();
}
