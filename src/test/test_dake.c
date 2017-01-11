#include <glib.h>

#include "../dake.h"

void
test_dake_pre_key_new() {
  dake_pre_key_t *pre_key = dake_pre_key_new("handler@service.net");

  g_assert_cmpint(pre_key->protocol_version, ==, 4);
  g_assert_cmpint(pre_key->message_type, ==, 15);
  g_assert_cmpint(pre_key->sender_instance_tag, >, 0);
  g_assert_cmpint(pre_key->receiver_instance_tag, ==, 0);
  // TODO: How to assert a pointer was set without using nonnull?
  // Comparing to 0 fires a warning on making a int from a pointer
  // even when NULL is a representation of 0
  // g_assert_cmpint(pre_key->Y, >, 0);
  // g_assert_cmpint(pre_key->B, >, 0);

  dake_pre_key_free(pre_key);
}

int
main(int argc, char **argv) {
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/dake_pre_key_new", test_dake_pre_key_new);

  return g_test_run();
}
