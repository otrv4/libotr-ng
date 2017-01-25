#include <glib.h>
#include <string.h>
#include <stdio.h>
#include "../otrv4.h"

typedef struct {
  otrv4_t *otr;
} otrv4_fixture_t;

void
otrv4_fixture_set_up(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  otrv4_t *otr = otrv4_new();
  otrv4_start(otr);
  otrv4_fixture->otr = otr;
}

void
otrv4_fixture_teardown(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  otrv4_free(otrv4_fixture->otr);
}

void
test_otrv4_starts_protocol() {
  otrv4_t *otr = otrv4_new();

  int started = otrv4_start(otr);

  g_assert_cmpint(started, ==, true);
  g_assert_cmpint(otr->state, ==, OTR_STATE_START);
  g_assert_cmpint(otr->supported_versions, ==, OTR_ALLOW_V4);

  otrv4_free(otr);
}

void
test_otrv4_version_supports_v34(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  otrv4_version_support_v3(otrv4_fixture->otr);

  g_assert_cmpint(otrv4_fixture->otr->supported_versions, ==, OTR_ALLOW_V3 | OTR_ALLOW_V4);
}

void
test_otrv4_builds_query_message(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  char *message = "And some random invitation text.";

  char query_message[41];
  otrv4_build_query_message(query_message, otrv4_fixture->otr, message);

  char *expected_qm = "?OTRv4? And some random invitation text.";
  g_assert_cmpstr(query_message, ==, expected_qm);
}

void
test_otrv4_builds_query_message_v34(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  otrv4_version_support_v3(otrv4_fixture->otr);
  char *message = "And some random invitation text.";

  char query_message[41];
  otrv4_build_query_message(query_message, otrv4_fixture->otr, message);

  char *expected_qm = "?OTRv34? And some random invitation text.";
  g_assert_cmpstr(query_message, ==, expected_qm);
}

void
test_otrv4_builds_whitespace_tag(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  char *expected_tag = " \t  \t\t\t\t \t \t \t    \t\t \t  And some random invitation text.";
  char *message = "And some random invitation text.";

  char whitespace_tag[strlen(expected_tag)];
  otrv4_build_whitespace_tag(whitespace_tag, otrv4_fixture->otr, message);
  g_assert_cmpstr(whitespace_tag, ==, expected_tag);
}

void
test_otrv4_builds_whitespace_tag_v34(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  otrv4_version_support_v3(otrv4_fixture->otr);
  char *expected_tag = " \t  \t\t\t\t \t \t \t    \t\t \t    \t\t  \t\tAnd some random invitation text";
  char *message = "And some random invitation text";

  char whitespace_tag[strlen(expected_tag)];
  otrv4_build_whitespace_tag(whitespace_tag, otrv4_fixture->otr, message);
  g_assert_cmpstr(whitespace_tag, ==, expected_tag);
}

void
test_otrv4_receives_plaintext_without_ws_tag_on_start(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  otrv4_receive_message(otrv4_fixture->otr, "Some random text.");

  g_assert_cmpstr(otrv4_fixture->otr->message_to_display, ==, "Some random text.");
}

void
test_otrv4_receives_plaintext_without_ws_tag_not_on_start(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  otrv4_fixture->otr->state = OTR_STATE_AKE_IN_PROGRESS;
  otrv4_receive_message(otrv4_fixture->otr, "Some random text.");

  g_assert_cmpstr(otrv4_fixture->otr->message_to_display, ==, "Some random text.");
  g_assert_cmpstr(otrv4_fixture->otr->warning, ==, "The above message was received unencrypted.");
}

void
test_otrv4_receives_plaintext_with_ws_tag(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {

  otrv4_receive_message(otrv4_fixture->otr, " \t  \t\t\t\t \t \t \t    \t\t \t  And some random invitation text.");

  g_assert_cmpstr(otrv4_fixture->otr->message_to_display, ==, "And some random invitation text.");
  g_assert_cmpint(otrv4_fixture->otr->state, ==, OTR_STATE_AKE_IN_PROGRESS);
  //TODO: How to assert the pointer is not null without g_assert_nonnull?
  //g_assert_cmpint(otrv4_fixture->otr->pre_key, >, 0);
  g_assert_cmpint(otrv4_fixture->otr->running_version, ==, V4);
}

void
test_otrv4_receives_plaintext_with_ws_tag_v3(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {

  otrv4_receive_message(otrv4_fixture->otr, " \t  \t\t\t\t \t \t \t    \t\t  \t\tAnd some random invitation text.");

  //g_assert_cmpstr(otrv4_fixture->otr->message_to_display, ==, "And some random invitation text.");
  g_assert_cmpint(otrv4_fixture->otr->state, ==, OTR_STATE_AKE_IN_PROGRESS);
  g_assert_cmpint(otrv4_fixture->otr->running_version, ==, V3);
}

void
test_otrv4_receives_query_message(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  otrv4_receive_message(otrv4_fixture->otr, "?OTRv4? And some random invitation text.");

  //TODO: How to assert the pointer is not null without g_assert_nonnull?
  g_assert_cmpint(otrv4_fixture->otr->state, ==, OTR_STATE_AKE_IN_PROGRESS);
  g_assert_cmpint(otrv4_fixture->otr->running_version, ==, V4);
}

void
test_otrv4_receives_query_message_v3(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  otrv4_receive_message(otrv4_fixture->otr, "?OTRv3? And some random invitation text.");

  //TODO: How to assert the pointer is not null without g_assert_nonnull?
  g_assert_cmpint(otrv4_fixture->otr->state, ==, OTR_STATE_AKE_IN_PROGRESS);
  g_assert_cmpint(otrv4_fixture->otr->running_version, ==, V3);
}

void
test_otrv4_receives_pre_key_on_start(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  dake_pre_key_t *pre_key = dake_pre_key_new("handler@service.net");
  uint8_t serialized[500] = { 0 };
  dake_pre_key_serialize(serialized, pre_key);
  char message[1000];
  strcpy(message, "?OTR:");
  printf("\nmsg = %s\nser = %lu\n", message, strlen((const char*)serialized));
  memcpy(message + 5, serialized, strlen((const char*)serialized) + 1);

  otrv4_receive_message(otrv4_fixture->otr, message);

  g_assert_cmpint(otrv4_fixture->otr->state, ==, OTR_STATE_ENCRYPTED_MESSAGES);
  g_assert_cmpint(otrv4_fixture->otr->running_version, ==, V4);
  g_assert_cmpstr(otrv4_fixture->otr->message_to_display, ==, NULL);
  dake_dre_auth_t *dre_auth = malloc(sizeof(dake_dre_auth_t));
  //TODO: should base64 decode the message to respond after ?OTR and then
  //deserialize
  dake_dre_auth_deserialize(dre_auth, (uint8_t*) otrv4_fixture->otr->message_to_respond);
  //TODO: How to assert the pointer is not null without g_assert_nonnull?
  //g_assert_cmpuint(dre_auth, >, 0);
}

void
test_otrv4_receives_pre_key_invalid_on_start(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  char *pre_key = "?OTR:";

  otrv4_receive_message(otrv4_fixture->otr, pre_key);

  g_assert_cmpint(otrv4_fixture->otr->state, ==, OTR_STATE_START);
  g_assert_cmpint(otrv4_fixture->otr->running_version, ==, V4);
  g_assert_cmpstr(otrv4_fixture->otr->message_to_display, ==, NULL);
  g_assert_cmpstr(otrv4_fixture->otr->message_to_respond, ==, NULL);
}

