#include <string.h>

#include "../protocol.h"
#include "../str.h"

void
test_api_conversation(void) {
  OTR4_INIT;

  cs_keypair_t cs_alice, cs_bob;
  cs_keypair_generate(cs_alice);
  cs_keypair_generate(cs_bob);

  otrv4_t *alice = otrv4_new(cs_alice);
  otrv4_t *bob = otrv4_new(cs_bob);

  otrv4_response_t *response_to_bob = otrv4_response_new();
  otrv4_response_t *response_to_alice = otrv4_response_new();
  string_t query_message = NULL;

  otrv4_build_query_message(&query_message, alice, "");
  otrv4_assert_cmpmem("?OTRv4", query_message, 6);

  //Bob receives query message
  otrv4_assert(otrv4_receive_message(response_to_alice, bob, query_message));

  //Should reply with a pre-key
  otrv4_assert(bob->state == OTR_STATE_AKE_IN_PROGRESS);
  otrv4_assert(response_to_alice->to_display == NULL);
  otrv4_assert(response_to_alice->to_send);
  otrv4_assert_cmpmem("?OTR:AAQP", response_to_alice->to_send, 9);

  //Alice receives pre-key
  otrv4_assert(otrv4_receive_message(response_to_bob, alice, response_to_alice->to_send));

  //Alice has Bob's ephemeral keys
  otrv4_assert_ec_public_key_eq(alice->their_ecdh, bob->our_ecdh->pub);
  otrv4_assert_dh_public_key_eq(alice->their_dh, bob->our_dh->pub);

  //Should reply with a dre-auth
  otrv4_assert(response_to_bob->to_display == NULL);
  otrv4_assert(response_to_bob->to_send);
  otrv4_assert_cmpmem("?OTR:AAQA", response_to_bob->to_send, 9);

  //Check double ratchet is initialized
  otrv4_assert(alice->state == OTR_STATE_ENCRYPTED_MESSAGES);
  otrv4_assert(alice->keys->current);
  g_assert_cmpint(alice->keys->current->root_key[0], !=, 0);

  //Bob receives DRE-auth
  otrv4_assert(otrv4_receive_message(response_to_alice, bob, response_to_bob->to_send));

  //Bob has Alice's ephemeral keys
  otrv4_assert_ec_public_key_eq(bob->their_ecdh, alice->our_ecdh->pub);
  otrv4_assert_dh_public_key_eq(bob->their_dh, alice->our_dh->pub);

  //There is no reply
  otrv4_assert(response_to_alice->to_display == NULL);
  otrv4_assert(response_to_alice->to_send == NULL);

  //Check double ratchet is initialized
  otrv4_assert(bob->state == OTR_STATE_ENCRYPTED_MESSAGES);
  otrv4_assert(bob->keys->current);
  g_assert_cmpint(bob->keys->current->root_key[0], !=, 0);

  otrv4_assert_cmpmem(alice->keys->current->root_key, bob->keys->current->root_key, sizeof(root_key_t));

  otrv4_response_free(response_to_alice);
  otrv4_response_free(response_to_bob);
  otrv4_free(alice);
  otrv4_free(bob);
}

