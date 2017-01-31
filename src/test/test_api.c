#include "../protocol.h"

void
test_api_conversation(void) {
  OTR4_INIT;

  cs_keypair_t cs_alice, cs_bob;

  cs_generate_keypair(cs_alice);
  otrv4_t *alice = otrv4_new(cs_alice);

  cs_generate_keypair(cs_bob);
  otrv4_t *bob = otrv4_new(cs_bob);

  char *to_send = NULL;
  otrv4_build_query_message(&to_send, alice, "");

  response_t *response;
  response = otrv4_receive_message(bob, to_send);

  otrv4_assert(response);
  otrv4_assert(response->to_display == NULL);
  //otrv4_assert(response->to_send != NULL);

  otrv4_free(alice);
  otrv4_free(bob);
}

