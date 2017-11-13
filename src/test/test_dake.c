#include <glib.h>
#include <string.h>

#include "../auth.h"
#include "../dake.h"
#include "../serialize.h"
#include "../str.h"

void test_snizkpk_auth() {
  snizkpk_proof_t dst[1];
  snizkpk_keypair_t pair1[1], pair2[1], pair3[1];
  const char *msg = "hi";

  snizkpk_keypair_generate(pair1);
  snizkpk_keypair_generate(pair2);
  snizkpk_keypair_generate(pair3);

  snizkpk_authenticate(dst, pair1, pair2->pub, pair3->pub, (unsigned char *)msg,
                       strlen(msg));

  otrv4_assert(snizkpk_verify(dst, pair1->pub, pair2->pub, pair3->pub,
                              (unsigned char *)msg,
                              strlen(msg)) == OTR4_SUCCESS);

  // Serialize and deserialize things.
  otrv4_keypair_t p1[1], p2[1], p3[1];
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1}, sym2[ED448_PRIVATE_BYTES] = {2},
          sym3[ED448_PRIVATE_BYTES] = {3};

  otrv4_keypair_generate(p1, sym1);
  otrv4_keypair_generate(p2, sym2);
  otrv4_keypair_generate(p3, sym3);

  snizkpk_proof_t dst2[1];
  snizkpk_authenticate(dst2, p1, p2->pub, p3->pub, (unsigned char *)msg,
                       strlen(msg));

  otrv4_assert(snizkpk_verify(dst2, p1->pub, p2->pub, p3->pub,
                              (unsigned char *)msg,
                              strlen(msg)) == OTR4_SUCCESS);
}

// TODO: remove me when the time comes
void test_non_interactive_auth_snizkpk() {
  OTR4_INIT;

  otr4_client_state_t *bob_state = otr4_client_state_new(NULL);
  bob_state->pad = true;

  uint8_t bob_sym[ED448_PRIVATE_BYTES] = {
      2}; // non-random private key on purpose
  otr4_client_state_add_private_key_v4(bob_state, bob_sym);

  otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4};
  otrv4_t *bob = otrv4_new(bob_state, policy);

  otrv4_response_t *response = otrv4_response_new();
  response->to_send = malloc(500); // may not be needed
  otr4_err_t err = reply_with_non_interactive_auth_msg(response, bob);

  otrv4_assert(err == OTR4_SUCCESS);
}
