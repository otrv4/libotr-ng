#include <string.h>

#include "../otrv4.h"
#include "../str.h"

void do_ake(otrv4_t * alice, otrv4_t * bob)
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

void test_api_conversation(void)
{
	OTR4_INIT;

	cs_keypair_t cs_alice, cs_bob;
	cs_keypair_generate(cs_alice);
	cs_keypair_generate(cs_bob);

	otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4 };
	otrv4_t *alice = otrv4_new(cs_alice, policy);
	otrv4_t *bob = otrv4_new(cs_bob, policy);

	//AKE HAS FINISHED.
	do_ake(alice, bob);

	//int ratchet_id;
	int message_id;
	otrv4_response_t *response_to_bob = NULL;
	otrv4_response_t *response_to_alice = NULL;

	//Bob sends a data message
	string_t to_send = NULL;

	for (message_id = 2; message_id < 5; message_id++) {
		otrv4_assert(otrv4_send_message(&to_send, "hi", NULL, bob));
		otrv4_assert(to_send);
		otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9);

		//This is a follow up message.
		g_assert_cmpint(bob->keys->i, ==, 0);
		g_assert_cmpint(bob->keys->j, ==, message_id);

		//Alice receives a data message
		response_to_bob = otrv4_response_new();
		otrv4_assert(otrv4_receive_message
			     (response_to_bob, (string_t) to_send,
			      strlen((char *)to_send), alice));
		free(to_send);
		to_send = NULL;

		otrv4_assert_cmpmem("hi", response_to_bob->to_display, 3);
		otrv4_assert(response_to_bob->to_send == NULL);
		otrv4_response_free(response_to_bob);
		response_to_bob = NULL;

		//Next message alice sends is a new "ratchet"
		g_assert_cmpint(alice->keys->i, ==, 0);
		g_assert_cmpint(alice->keys->j, ==, 0);
	}

	for (message_id = 1; message_id < 4; message_id++) {
		//Alice sends a data message
		otrv4_assert(otrv4_send_message
			     (&to_send, "hello", NULL, alice));
		otrv4_assert(to_send);
		otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9);

		//New ratchet hapenned
		g_assert_cmpint(alice->keys->i, ==, 1);
		g_assert_cmpint(alice->keys->j, ==, message_id);

		//Bob receives a data message
		response_to_alice = otrv4_response_new();
		otrv4_assert(otrv4_receive_message
			     (response_to_alice, (string_t) to_send,
			      strlen((char *)to_send), bob));
		free(to_send);
		to_send = NULL;

		otrv4_assert_cmpmem("hello", response_to_alice->to_display, 6);
		otrv4_assert(response_to_alice->to_send == NULL);
		otrv4_response_free(response_to_alice);
		response_to_alice = NULL;

		//Bob follows the ratchet 1 (and prepares to a new "ratchet")
		g_assert_cmpint(bob->keys->i, ==, 1);
		g_assert_cmpint(bob->keys->j, ==, 0);
	}

	tlv_t *tlvs = otrv4_padding_tlv_new(10);
	otrv4_assert(tlvs);

	//Bob sends a message with TLV
	otrv4_assert(otrv4_send_message(&to_send, "hi", tlvs, bob));
	otrv4_assert(to_send);
	otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9);
	otrv4_tlv_free(tlvs);

	//Alice receives a data message with TLV
	response_to_bob = otrv4_response_new();
	otrv4_assert(otrv4_receive_message
		     (response_to_bob, (string_t) to_send,
		      strlen((char *)to_send), alice));
	free(to_send);
	to_send = NULL;

	otrv4_assert(response_to_bob->tlvs);
	g_assert_cmpint(response_to_bob->tlvs->type, ==, OTRV4_TLV_PADDING);
	g_assert_cmpint(response_to_bob->tlvs->len, ==, 10);
	otrv4_response_free(response_to_bob);
	response_to_bob = NULL;

	otrv4_free(alice);
	otrv4_free(bob);
	cs_keypair_destroy(cs_alice);
	cs_keypair_destroy(cs_bob);

	OTR4_FREE;
}
