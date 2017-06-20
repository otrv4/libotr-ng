#include <libotr/privkey.h>

typedef struct {
  otrv4_t *otr;
  otrv4_t *otrv3;
  otrv4_t *otrv34;
  otr4_client_state_t *state;
} otrv4_fixture_t;

void otrv4_fixture_set_up(otrv4_fixture_t *otrv4_fixture, gconstpointer data) {
  OTR4_INIT;

  otrv4_fixture->state = otr4_client_state_new(NULL); // No callbacks
  otrv4_fixture->state->userstate = otrl_userstate_create();
  otrv4_fixture->state->protocol_name = otrv4_strdup("protocol");
  otrv4_fixture->state->account_name = otrv4_strdup("account@protocol");

  uint8_t sym[ED448_PRIVATE_BYTES] = {1}; // non-random private key on purpose
  otr4_client_state_add_private_key_v4(otrv4_fixture->state, sym);

  otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V4};
  otrv4_fixture->otr = otrv4_new(otrv4_fixture->state, policy);

  otrv4_policy_t policyv3 = {.allows = OTRV4_ALLOW_V3};
  otrv4_fixture->otrv3 = otrv4_new(otrv4_fixture->state, policyv3);
  otrv4_fixture->otrv3->otr3_conn =
      otr3_conn_new(otrv4_fixture->state, "they_are_bob");

  otrv4_policy_t policyv34 = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4};
  otrv4_fixture->otrv34 = otrv4_new(otrv4_fixture->state, policyv34);
  otrv4_fixture->otrv34->otr3_conn =
      otr3_conn_new(otrv4_fixture->state, "they_are_alice");

  // TODO: This should be done automatically
  FILE *tmpFILEp;
  tmpFILEp = tmpfile();
  otrv4_assert(!otrl_privkey_generate_FILEp(
      otrv4_fixture->state->userstate, tmpFILEp,
      otrv4_fixture->state->account_name, otrv4_fixture->state->protocol_name));
  fclose(tmpFILEp);

  // Generate instance tag
  otr4_client_state_add_instance_tag(otrv4_fixture->state, 0x100 + 1);
}

void otrv4_fixture_teardown(otrv4_fixture_t *otrv4_fixture,
                            gconstpointer data) {
  otrl_userstate_free(otrv4_fixture->state->userstate);

  otr4_client_state_free(otrv4_fixture->state);
  otrv4_fixture->state = NULL;

  otrv4_free(otrv4_fixture->otr);
  otrv4_fixture->otr = NULL;

  otrv4_free(otrv4_fixture->otrv3);
  otrv4_fixture->otrv3 = NULL;

  otrv4_free(otrv4_fixture->otrv34);
  otrv4_fixture->otrv34 = NULL;

  dh_free();
}

typedef struct {
  otrv4_keypair_t *keypair;
  user_profile_t *profile;
} identity_message_fixture_t;

static void identity_message_fixture_setup(identity_message_fixture_t *fixture,
                                           gconstpointer user_data) {
  fixture->keypair = otrv4_keypair_new();

  uint8_t sym[ED448_PRIVATE_BYTES] = {1}; // non-random private key on purpose
  otrv4_keypair_generate(fixture->keypair, sym);
  otrv4_assert(ec_point_valid(fixture->keypair->pub));

  fixture->profile = user_profile_new("4");
  otrv4_assert(fixture->profile != NULL);
  fixture->profile->expires = time(NULL) + 60 * 60;
  otrv4_assert(user_profile_sign(fixture->profile, fixture->keypair) ==
               OTR4_SUCCESS);
}

static void
identity_message_fixture_teardown(identity_message_fixture_t *fixture,
                                  gconstpointer user_data) {
  otrv4_keypair_free(fixture->keypair);
  fixture->keypair = NULL;

  user_profile_free(fixture->profile);
  fixture->profile = NULL;
}

void do_ake_fixture(otrv4_t *alice, otrv4_t *bob) {
  otrv4_response_t *response_to_bob = otrv4_response_new();
  otrv4_response_t *response_to_alice = otrv4_response_new();

  // Alice sends query message
  string_t query_message = NULL;
  otrv4_assert(otrv4_build_query_message(&query_message, "", alice) ==
               OTR4_SUCCESS);
  otrv4_assert_cmpmem("?OTRv4", query_message, 6);

  // Bob receives query message
  otrv4_assert(otrv4_receive_message(response_to_alice, query_message, bob) ==
               OTR4_SUCCESS);
  free(query_message);
  query_message = NULL;

  // Should reply with a identity message
  otrv4_assert(bob->state == OTRV4_STATE_WAITING_AUTH_R);
  otrv4_assert(response_to_alice->to_display == NULL);
  otrv4_assert(response_to_alice->to_send);
  otrv4_assert_cmpmem("?OTR:AAQI", response_to_alice->to_send, 9);

  // Alice receives identity message
  otrv4_assert(otrv4_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == OTR4_SUCCESS);
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // Alice has Bob's ephemeral keys
  otrv4_assert(alice->state == OTRV4_STATE_WAITING_AUTH_I);
  otrv4_assert_ec_public_key_eq(alice->keys->their_ecdh,
                                bob->keys->our_ecdh->pub);
  otrv4_assert_dh_public_key_eq(alice->keys->their_dh, bob->keys->our_dh->pub);
  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 0);

  // Should reply with an auth receiver
  otrv4_assert(response_to_bob->to_display == NULL);
  otrv4_assert(response_to_bob->to_send);
  otrv4_assert_cmpmem("?OTR:AASR", response_to_bob->to_send, 9);

  // Bob receives an auth receiver
  otrv4_assert(otrv4_receive_message(response_to_alice,
                                     response_to_bob->to_send,
                                     bob) == OTR4_SUCCESS);
  free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  // Bob has Alice's ephemeral keys
  otrv4_assert_ec_public_key_eq(bob->keys->their_ecdh,
                                alice->keys->our_ecdh->pub);
  otrv4_assert_dh_public_key_eq(bob->keys->their_dh, alice->keys->our_dh->pub);
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);

  // Bob should replay with an auth initiator
  otrv4_assert(response_to_alice->to_display == NULL);
  otrv4_assert(response_to_alice->to_send);
  otrv4_assert_cmpmem("?OTR:AASI", response_to_alice->to_send, 9);

  // Check double ratchet is initialized
  otrv4_assert(bob->state == OTRV4_STATE_ENCRYPTED_MESSAGES);
  otrv4_assert(bob->keys->current);

  // Alice receives an auth initiator
  otrv4_assert(otrv4_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == OTR4_SUCCESS);
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  //otrv4_assert(alice->keys->our_dh->priv != NULL);
  //otrv4_assert(bob->keys->our_dh->priv == NULL);

  // Alice should not reply
  otrv4_assert(response_to_bob->to_display == NULL);
  otrv4_assert(!response_to_bob->to_send);

  // Check double ratchet is initialized
  otrv4_assert(alice->state == OTRV4_STATE_ENCRYPTED_MESSAGES);
  otrv4_assert(alice->keys->current);

  // Alice ratchets
  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 1);

  // Both have the same shared secret
  otrv4_assert_root_key_eq(alice->keys->current->root_key,
                           bob->keys->current->root_key);
  otrv4_assert_chain_key_eq(alice->keys->current->chain_a->key,
                            bob->keys->current->chain_a->key);
  otrv4_assert_chain_key_eq(bob->keys->current->chain_b->key,
                            alice->keys->current->chain_b->key);

  chain_key_t bob_sending_key, alice_receiving_key;
  key_manager_get_sending_chain_key(bob_sending_key, bob->keys);
  otrv4_assert(key_manager_get_receiving_chain_key(
                   alice_receiving_key, 0, alice->keys) == OTR4_SUCCESS);
  otrv4_assert_chain_key_eq(bob_sending_key, alice_receiving_key);

  otrv4_response_free(response_to_alice);
  otrv4_response_free(response_to_bob);
}
