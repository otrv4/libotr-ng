#include "../otrv4.h"
#include "../cramershoup_interface.h"
#include "../user_profile.h"

typedef struct {
	otrv4_t *otr;
	otrv4_t *otrv3;
	otrv4_t *otrv34;
	cs_keypair_t keypair;
} otrv4_fixture_t;

void otrv4_fixture_set_up(otrv4_fixture_t * otrv4_fixture, gconstpointer data)
{
	dh_init();

	cs_keypair_generate(otrv4_fixture->keypair);

	otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V4 };
	otrv4_fixture->otr = otrv4_new(otrv4_fixture->keypair, policy);

	otrv4_policy_t policyv3 = {.allows = OTRV4_ALLOW_V3 };
	otrv4_fixture->otrv3 = otrv4_new(otrv4_fixture->keypair, policyv3);

	otrv4_policy_t policyv34 = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4 };
	otrv4_fixture->otrv34 = otrv4_new(otrv4_fixture->keypair, policyv34);
}

void otrv4_fixture_teardown(otrv4_fixture_t * otrv4_fixture, gconstpointer data)
{
	cs_keypair_destroy(otrv4_fixture->keypair);
	otrv4_free(otrv4_fixture->otr);
	otrv4_free(otrv4_fixture->otrv3);
	otrv4_free(otrv4_fixture->otrv34);

	dh_free();
}

typedef struct {
	cs_keypair_t keypair;
	user_profile_t *profile;
} identity_message_fixture_t;

static void
identity_message_fixture_setup(identity_message_fixture_t * fixture,
			       gconstpointer user_data)
{
	cs_keypair_generate(fixture->keypair);
	fixture->profile = user_profile_new("4");
	otrv4_assert(fixture->profile != NULL);
	fixture->profile->expires = time(NULL) + 60 * 60;
	otrv4_assert(user_profile_sign(fixture->profile, fixture->keypair));
}

static void
identity_message_fixture_teardown(identity_message_fixture_t * fixture,
				  gconstpointer user_data)
{
	cs_keypair_destroy(fixture->keypair);
	user_profile_free(fixture->profile);
	fixture->profile = NULL;
}

	void
do_ake_fixture(otrv4_t * alice, otrv4_t * bob)
{
	otrv4_response_t *response_to_bob = otrv4_response_new();
	otrv4_response_t *response_to_alice = otrv4_response_new();

	//Alice sends query message
	string_t query_message = NULL;
	otrv4_build_query_message(&query_message, "", alice);
	otrv4_assert_cmpmem("?OTRv4", query_message, 6);

	//Bob receives query message
	otrv4_assert(otrv4_receive_message
			(response_to_alice, query_message, 6, bob));
	free(query_message);

	//Should reply with a pre-key
	otrv4_assert(bob->state == OTRV4_STATE_AKE_IN_PROGRESS);
	otrv4_assert(response_to_alice->to_display == NULL);
	otrv4_assert(response_to_alice->to_send);
	otrv4_assert_cmpmem("?OTR:AAQP", response_to_alice->to_send, 9);

	//Alice receives pre-key
	otrv4_assert(otrv4_receive_message
			(response_to_bob, response_to_alice->to_send,
			 strlen(response_to_alice->to_send), alice));
	free(response_to_alice->to_send);

	//Alice has Bob's ephemeral keys
	otrv4_assert_ec_public_key_eq(alice->keys->their_ecdh,
			bob->keys->our_ecdh->pub);
	otrv4_assert_dh_public_key_eq(alice->keys->their_dh,
			bob->keys->our_dh->pub);
	g_assert_cmpint(alice->keys->i, ==, 0);
	g_assert_cmpint(alice->keys->j, ==, 0);

	//Should reply with a dre-auth
	otrv4_assert(response_to_bob->to_display == NULL);
	otrv4_assert(response_to_bob->to_send);
	otrv4_assert_cmpmem("?OTR:AAQA", response_to_bob->to_send, 9);

	//Check double ratchet is initialized
	otrv4_assert(alice->state == OTRV4_STATE_ENCRYPTED_MESSAGES);
	otrv4_assert(alice->keys->current);

	//Bob receives DRE-auth
	otrv4_assert(otrv4_receive_message
			(response_to_alice, response_to_bob->to_send,
			 strlen(response_to_bob->to_send), bob));
	free(response_to_bob->to_send);
	response_to_bob->to_send = NULL;

	//Bob has Alice's ephemeral keys
	otrv4_assert_ec_public_key_eq(bob->keys->their_ecdh,
			alice->keys->our_ecdh->pub);
	otrv4_assert_dh_public_key_eq(bob->keys->their_dh,
			alice->keys->our_dh->pub);
	g_assert_cmpint(bob->keys->i, ==, 0);
	g_assert_cmpint(bob->keys->j, ==, 1);

	//There is no reply
	otrv4_assert(response_to_alice->to_display == NULL);
	otrv4_assert(response_to_alice->to_send == NULL);

	//Check double ratchet is initialized
	otrv4_assert(bob->state == OTRV4_STATE_ENCRYPTED_MESSAGES);
	otrv4_assert(bob->keys->current);

	//Both have the same shared secret
	otrv4_assert_root_key_eq(alice->keys->current->root_key,
			bob->keys->current->root_key);
	otrv4_assert_chain_key_eq(alice->keys->current->chain_a->key,
			bob->keys->current->chain_a->key);
	otrv4_assert_chain_key_eq(bob->keys->current->chain_b->key,
			alice->keys->current->chain_b->key);

	chain_key_t bob_sending_key, alice_receiving_key;
	key_manager_get_sending_chain_key(bob_sending_key, bob->keys);
	key_manager_get_receiving_chain_key_by_id(alice_receiving_key, 0, 0,
			alice->keys);
	otrv4_assert_chain_key_eq(bob_sending_key, alice_receiving_key);

	otrv4_response_free(response_to_alice);
	otrv4_response_free(response_to_bob);
}
