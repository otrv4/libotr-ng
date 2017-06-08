#include <glib.h>
#include <stdlib.h>

#include "../fragment.h"

void test_create_fragments(void) {
  int mms = 40;
  char *message = "one two tree";

  fragment_message_t *frag_message;
  frag_message = malloc(sizeof(fragment_message_t));

  otrv4_assert(
      otr4_fragment_message(mms, frag_message, 1, 2, message)
      ==
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
}
