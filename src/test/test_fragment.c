#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "../fragment.h"

void test_create_fragments(void) {
  int mms = 40;
  char *message = "one two tree";

  fragment_message_t *frag_message;
  frag_message = malloc(sizeof(fragment_message_t));

  otrv4_assert(otr4_fragment_message(mms, frag_message, 1, 2, message) ==
               OTR4_SUCCESS);

  g_assert_cmpstr(frag_message->pieces[0], ==,
                  "?OTR|00000001|00000002,00001,00004,one,");
  g_assert_cmpstr(frag_message->pieces[1], ==,
                  "?OTR|00000001|00000002,00002,00004, tw,");
  g_assert_cmpstr(frag_message->pieces[2], ==,
                  "?OTR|00000001|00000002,00003,00004,o t,");
  g_assert_cmpstr(frag_message->pieces[3], ==,
                  "?OTR|00000001|00000002,00004,00004,ree,");

  g_assert_cmpint(frag_message->total, ==, 4);

  fragment_message_free(frag_message);
}

void test_defragment_non_frag(void) {
  string_t message = "not a fragment";

  fragment_context_t *context;
  context = fragment_context_new();

  otrv4_assert(otr4_defragment_message(context, message) == OTR4_SUCCESS);

  g_assert_cmpint(context->N, ==, 0);
  g_assert_cmpint(context->K, ==, 0);
  g_assert_cmpstr(context->fragment, ==, message);
  otrv4_assert(context->status == OTR4_FRAGMENT_UNFRAGMENTED);

  fragment_context_free(context);
}

void test_defragment_valid_message(void) {
  string_t fragments[2];
  fragments[0] = "?OTR|00000001|00000002,00001,00002,one ,";
  fragments[1] = "?OTR|00000001|00000002,00002,00002,more,";

  fragment_context_t *context;
  context = fragment_context_new();

  otrv4_assert(otr4_defragment_message(context, fragments[0]) == OTR4_SUCCESS);

  g_assert_cmpint(context->N, ==, 2);
  g_assert_cmpint(context->K, ==, 1);
  g_assert_cmpstr(context->fragment, ==, "one ");
  g_assert_cmpint(context->fragment_len, ==, 4);
  otrv4_assert(context->status == OTR4_FRAGMENT_INCOMPLETE);

  otrv4_assert(otr4_defragment_message(context, fragments[1]) == OTR4_SUCCESS);

  g_assert_cmpint(context->N, ==, 2);
  g_assert_cmpint(context->K, ==, 2);
  g_assert_cmpstr(context->fragment, ==, "one more");
  g_assert_cmpint(context->fragment_len, ==, 8);
  otrv4_assert(context->status == OTR4_FRAGMENT_COMPLETE);

  fragment_context_free(context);
}

void test_defragment_plaintext_should_clean_context(void) {
  string_t fragments[2];
  fragments[0] = "?OTR|00000001|00000002,00001,00002,one ,";
  fragments[1] = "?OTR|00000001|00000002,00002,00002,more,";

  fragment_context_t *context;
  context = fragment_context_new();

  otrv4_assert(otr4_defragment_message(context, fragments[0]) == OTR4_SUCCESS);

  g_assert_cmpint(context->N, ==, 2);
  g_assert_cmpint(context->K, ==, 1);
  g_assert_cmpstr(context->fragment, ==, "one ");
  g_assert_cmpint(context->fragment_len, ==, 4);
  otrv4_assert(context->status == OTR4_FRAGMENT_INCOMPLETE);

  char *plaintext = "Anything else";
  otrv4_assert(otr4_defragment_message(context, plaintext) == OTR4_SUCCESS);

  g_assert_cmpint(context->N, ==, 0);
  g_assert_cmpint(context->K, ==, 0);
  g_assert_cmpstr(context->fragment, ==, plaintext);
  g_assert_cmpint(context->fragment_len, ==, strlen(plaintext));
  otrv4_assert(context->status == OTR4_FRAGMENT_UNFRAGMENTED);

  fragment_context_free(context);
}

void test_defragment_single_fragment(void) {
  string_t msg = "?OTR|00000001|00000002,00001,00001,small lol,";

  fragment_context_t *context;
  context = fragment_context_new();

  otrv4_assert(otr4_defragment_message(context, msg) == OTR4_SUCCESS);

  g_assert_cmpint(context->N, ==, 1);
  g_assert_cmpint(context->K, ==, 1);
  g_assert_cmpstr(context->fragment, ==, "small lol");
  g_assert_cmpint(context->fragment_len, ==, 9);
  otrv4_assert(context->status == OTR4_FRAGMENT_COMPLETE);

  fragment_context_free(context);
}

void test_defragment_clean_context_for_frag_out_of_order(void) {
  string_t fragments[3];
  fragments[0] = "?OTR|00000001|00000002,00001,00003,one more ,";
  fragments[1] = "?OTR|00000001|00000002,00003,00003,send,";
  fragments[2] = "?OTR|00000001|00000002,00002,00003,fragment ,";

  fragment_context_t *context;
  context = fragment_context_new();

  otrv4_assert(otr4_defragment_message(context, fragments[0]) == OTR4_SUCCESS);
  otrv4_assert(context->status == OTR4_FRAGMENT_INCOMPLETE);
  g_assert_cmpint(context->N, ==, 3);
  g_assert_cmpint(context->K, ==, 1);
  g_assert_cmpstr(context->fragment, ==, "one more ");
  g_assert_cmpint(context->fragment_len, ==, 9);

  otrv4_assert(otr4_defragment_message(context, fragments[1]) == OTR4_SUCCESS);
  otrv4_assert(context->status == OTR4_FRAGMENT_UNFRAGMENTED);
  g_assert_cmpstr(context->fragment, ==, "");
  g_assert_cmpint(context->N, ==, 0);
  g_assert_cmpint(context->K, ==, 0);

  otrv4_assert(otr4_defragment_message(context, fragments[2]) == OTR4_SUCCESS);
  otrv4_assert(context->status == OTR4_FRAGMENT_UNFRAGMENTED);
  g_assert_cmpstr(context->fragment, ==, "");
  g_assert_cmpint(context->N, ==, 0);
  g_assert_cmpint(context->K, ==, 0);

  fragment_context_free(context);
}
