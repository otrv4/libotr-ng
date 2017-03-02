#include <glib.h>

#include "../protocol.h"

void
test_protocol_starts() {
  otrv4_protocol_t *protocol = protocol_start(1, OTRV4_ALLOW_V4);

  otrv4_assert(protocol);
  g_assert_cmpint(protocol->state, ==, OTRV4_STATE_START);
  g_assert_cmpint(protocol->supported_versions, ==, OTRV4_ALLOW_V4);

  free(protocol);
}

void
test_protocol_starts_with_v34() {
  otrv4_protocol_t *protocol = protocol_start(2, OTRV4_ALLOW_V3, OTRV4_ALLOW_V4);

  otrv4_assert(protocol);
  g_assert_cmpint(protocol->state, ==, OTRV4_STATE_START);
  g_assert_cmpint(protocol->supported_versions, ==, OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4);

  free(protocol);
}
