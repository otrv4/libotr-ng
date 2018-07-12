/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libotr/privkey.h>

typedef struct otrng_fixture_s {
  otrng_s *otr;
  otrng_s *v3;
  otrng_s *v34;
  otrng_client_state_s *state;
} otrng_fixture_s, otrng_fixture_p[1];

int dh_mpi_cmp(const dh_mpi_p m1, const dh_mpi_p m2) {
  return gcry_mpi_cmp(m1, m2);
}

static otrng_shared_session_state_s
get_shared_session_state_cb(const otrng_client_conversation_s *conv) {
  otrng_shared_session_state_s ret = {
      .identifier1 = otrng_strdup("alice"),
      .identifier2 = otrng_strdup("bob"),
      .password = NULL,
  };

  return ret;
}

static int get_account_and_protocol_cb(char **account_name,
                                       char **protocol_name,
                                       const void *client_id) {
  const char *account = client_id; // tests use client_name as client_id.

  if (!client_id) {
    return 1;
  }

  *account_name = otrng_strdup(account);
  *protocol_name = otrng_strdup("otr");
  return 0;
}

static otrng_client_callbacks_p test_callbacks = {{
    &get_account_and_protocol_cb, // get_account_and_protocol
    NULL,                         // create_privkey
    NULL,                         // create_shared_prekey
    NULL,                         // create_instag
    NULL,                         // gone_secure
    NULL,                         // gone_insecure
    NULL,                         // fingerprint_seen
    NULL,                         // fingerprint_seen_v3
    NULL,                         // smp_ask_for_secret
    NULL,                         // smp_ask_for_answer
    NULL,                         // smp_update
    NULL,                         // received_extra_symm_key
    &get_shared_session_state_cb, // get_shared_session_state
}};

void otrng_fixture_set_up(otrng_fixture_s *otrng_fixture, gconstpointer data) {
  otrng_fixture->state = otrng_client_state_new("account");
  otrng_fixture->state->callbacks = test_callbacks;
  otrng_fixture->state->user_state = otrl_userstate_create();

  uint8_t sym[ED448_PRIVATE_BYTES] = {1}; // non-random private key on purpose
  otrng_client_state_add_private_key_v4(otrng_fixture->state, sym);

  otrng_client_state_add_shared_prekey_v4(otrng_fixture->state, sym);

  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V4};
  otrng_fixture->otr = otrng_new(otrng_fixture->state, policy);

  otrng_policy_s policyv3 = {.allows = OTRNG_ALLOW_V3};
  otrng_fixture->v3 = otrng_new(otrng_fixture->state, policyv3);
  otrng_fixture->v3->v3_conn =
      otrng_v3_conn_new(otrng_fixture->state, "they_are_bob");

  otrng_policy_s policyv34 = {.allows = OTRNG_ALLOW_V3 | OTRNG_ALLOW_V4};
  otrng_fixture->v34 = otrng_new(otrng_fixture->state, policyv34);
  otrng_fixture->v34->v3_conn =
      otrng_v3_conn_new(otrng_fixture->state, "they_are_alice");

  // TODO: @refactoring This should be done automatically
  FILE *tmpFILEp;
  tmpFILEp = tmpfile();
  otrng_assert(!otrl_privkey_generate_FILEp(otrng_fixture->state->user_state,
                                            tmpFILEp, "account", "otr"));
  fclose(tmpFILEp);

  // Generate instance tag
  otrng_client_state_add_instance_tag(otrng_fixture->state, 0x100 + 1);
}

void otrng_fixture_teardown(otrng_fixture_s *otrng_fixture,
                            gconstpointer data) {
  otrl_userstate_free(otrng_fixture->state->user_state);

  otrng_client_state_free(otrng_fixture->state);
  otrng_fixture->state = NULL;

  otrng_free(otrng_fixture->otr);
  otrng_fixture->otr = NULL;

  otrng_free(otrng_fixture->v3);
  otrng_fixture->v3 = NULL;

  otrng_free(otrng_fixture->v34);
  otrng_fixture->v34 = NULL;
}

typedef struct dake_fixture_s {
  otrng_keypair_s *keypair;
  otrng_shared_prekey_pair_s *shared_prekey;
  client_profile_s *profile;
} dake_fixture_s, dake_fixture_p[1];

static void dake_fixture_setup(dake_fixture_s *f, gconstpointer user_data) {
  f->keypair = otrng_keypair_new();

  uint8_t sym[ED448_PRIVATE_BYTES] = {1}; // non-random private key on purpose
  otrng_keypair_generate(f->keypair, sym);
  otrng_assert(otrng_ec_point_valid(f->keypair->pub));

  f->profile = client_profile_new("4");

  f->shared_prekey = otrng_shared_prekey_pair_new();
  otrng_shared_prekey_pair_generate(f->shared_prekey, sym);
  otrng_assert(otrng_ec_point_valid(f->shared_prekey->pub));

  otrng_assert(f->profile != NULL);
  f->profile->expires = time(NULL) + 60 * 60;
  otrng_assert_is_success(client_profile_sign(f->profile, f->keypair));
}

static void dake_fixture_teardown(dake_fixture_s *f, gconstpointer user_data) {
  otrng_keypair_free(f->keypair);
  f->keypair = NULL;

  otrng_shared_prekey_pair_free(f->shared_prekey);
  f->shared_prekey = NULL;

  otrng_client_profile_free(f->profile);
  f->profile = NULL;
}

#define identity_message_fixture_setup dake_fixture_setup
#define identity_message_fixture_teardown dake_fixture_teardown

void do_dake_fixture(otrng_s *alice, otrng_s *bob) {
  otrng_response_s *response_to_bob = otrng_response_new();
  otrng_response_s *response_to_alice = otrng_response_new();
  string_p query_message = NULL;
  otrng_notif notif = OTRNG_NOTIF_NONE;

  otrng_assert(alice->state == OTRNG_STATE_START);
  otrng_assert(bob->state == OTRNG_STATE_START);

  // Alice sends a query message
  otrng_assert_is_success(otrng_build_query_message(&query_message, "", alice));
  otrng_assert(alice->state == OTRNG_STATE_START);
  otrng_assert_cmpmem("?OTRv4", query_message, 6);

  // Bob receives a query message
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, notif, query_message, bob));
  free(query_message);

  // Bob replies with an identity message
  otrng_assert(bob->state == OTRNG_STATE_WAITING_AUTH_R);
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAQ1", response_to_alice->to_send, 9);

  // Alice receives an identity message
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, notif, response_to_alice->to_send, alice));
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // Alice has Bob's ephemeral keys
  otrng_assert_ec_public_key_eq(alice->keys->their_ecdh,
                                bob->keys->our_ecdh->pub);
  otrng_assert_dh_public_key_eq(alice->keys->their_dh, bob->keys->our_dh->pub);
  otrng_assert_not_zero(alice->keys->ssid, sizeof(alice->keys->ssid));
  otrng_assert_not_zero(alice->keys->shared_secret, sizeof(shared_secret_p));

  // Alice replies with an auth-r message
  otrng_assert(alice->state == OTRNG_STATE_WAITING_AUTH_I);
  otrng_assert(response_to_bob->to_display == NULL);
  otrng_assert(response_to_bob->to_send);
  otrng_assert_cmpmem("?OTR:AAQ2", response_to_bob->to_send, 9);

  // Bob receives an auth-r message
  otrng_assert_is_success(otrng_receive_message(response_to_alice, notif,
                                                response_to_bob->to_send, bob));
  free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  // Bob has Alice's ephemeral keys
  otrng_assert_ec_public_key_eq(bob->keys->their_ecdh,
                                alice->keys->our_ecdh->pub);
  otrng_assert_dh_public_key_eq(bob->keys->their_dh, alice->keys->our_dh->pub);
  otrng_assert_not_zero(bob->keys->ssid, sizeof(alice->keys->ssid));
  otrng_assert_zero(bob->keys->shared_secret, sizeof(shared_secret_p));
  otrng_assert_not_zero(bob->keys->current->root_key, sizeof(root_key_p));

  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 0);

  // Bob replies with an auth-i message
  otrng_assert(bob->state == OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE);
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAQ3", response_to_alice->to_send, 9);

  // The double ratchet is initialized
  otrng_assert(bob->keys->current);

  // Alice receives an auth-i message
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, notif, response_to_alice->to_send, alice));
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // The double ratchet is initialized
  otrng_assert(alice->keys->current);

  // Both have the same shared secret
  otrng_assert_root_key_eq(alice->keys->shared_secret,
                           bob->keys->shared_secret);

  // Alice replies with initial data message "Data-0"
  otrng_assert(alice->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert_cmpmem("?OTR:AAQD", response_to_bob->to_send, 9);
  otrng_assert(response_to_bob->to_display == NULL);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 0);

  // Bob receives the initial data message
  otrng_assert_is_success(otrng_receive_message(response_to_alice, notif,
                                                response_to_bob->to_send, bob));
  free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  otrng_assert(bob->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(response_to_alice->to_send == NULL);
  otrng_assert(response_to_alice->to_display == NULL);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  otrng_response_free(response_to_alice);
  otrng_response_free(response_to_bob);
}
