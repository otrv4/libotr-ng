#include <glib.h>
#include <stdio.h>

#include "../otr.h"

void
test_otr_starts_protocol() {
  otr *otr = otr_malloc();

  int started = otr_start(otr);

  g_assert_cmpint(started, ==, 1);
  g_assert_cmpint(otr->version, ==, OTR_V4);
  g_assert_cmpstr(otr->state, ==, OTRSTATE_START);

  otr_free(otr);
}

int
main(int argc, char **argv) {
  g_test_init(&argc, &argv, NULL);
  g_test_add_func("/otr_starts_protocol", test_otr_starts_protocol);
  return g_test_run();
}
