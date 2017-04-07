#include <string.h>

#include "../otrv4.h"
#include "../str.h"

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
	do_ake_fixture(alice, bob);

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
