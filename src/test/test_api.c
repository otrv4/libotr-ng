#include <string.h>

#include "../protocol.h"
#include "../str.h"

void
test_api_conversation(void) {
  OTR4_INIT;

  cs_keypair_t cs_alice, cs_bob;

  cs_generate_keypair(cs_alice);
  otrv4_t *alice = otrv4_new(cs_alice);

  cs_generate_keypair(cs_bob);
  otrv4_t *bob = otrv4_new(cs_bob);

  string_t query_message = NULL;
  otrv4_build_query_message(&query_message, alice, "");

  response_t *response_to_bob, *response_to_alice;
  response_to_alice = otrv4_receive_message(bob, query_message);

  otrv4_assert(response_to_alice);
  otrv4_assert(response_to_alice->to_display == NULL);
  otrv4_assert(response_to_alice->to_send != NULL);

  response_to_bob = otrv4_receive_message(alice, response_to_alice->to_send);

  otrv4_assert(response_to_bob);
  otrv4_assert(response_to_bob->to_display == NULL);
  otrv4_assert(response_to_bob->to_send != NULL);

  otrv4_free(alice);
  otrv4_free(bob);
}

