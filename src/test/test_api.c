#include <string.h>

#include "../otrv4.h"
#include "../str.h"
#include "../list.h"

void test_api_conversation(void)
{
	OTR4_INIT;

	otrv4_keypair_t alice_keypair[1], bob_keypair[1];
	uint8_t alice_sym[ED448_PRIVATE_BYTES] = { 1 };	// non-random private key on purpose
	otrv4_keypair_generate(alice_keypair, alice_sym);

	uint8_t bob_sym[ED448_PRIVATE_BYTES] = { 2 };	// non-random private key on purpose
	otrv4_keypair_generate(bob_keypair, bob_sym);

	otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4 };
	otrv4_t *alice = otrv4_new(alice_keypair, policy);
	otrv4_t *bob = otrv4_new(bob_keypair, policy);

	//AKE HAS FINISHED.
	do_ake_fixture(alice, bob);

	//int ratchet_id;
	int message_id;
	otrv4_response_t *response_to_bob = NULL;
	otrv4_response_t *response_to_alice = NULL;

	//Bob sends a data message
	string_t to_send = NULL;

	for (message_id = 2; message_id < 5; message_id++) {
		otrv4_assert(otrv4_send_message(&to_send, "hi", NULL, alice));
		otrv4_assert(to_send);
		otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9);

		//This is a follow up message.
		g_assert_cmpint(alice->keys->i, ==, 0);
		g_assert_cmpint(alice->keys->j, ==, message_id);

		//Bob receives a data message
		response_to_alice = otrv4_response_new();
		otrv4_assert(otrv4_receive_message
			     (response_to_alice, to_send,
			      strlen((char *)to_send), bob));
		free(to_send);
		to_send = NULL;

		otrv4_assert_cmpmem("hi", response_to_alice->to_display, 3);
		g_assert_cmpint(list_len(bob->keys->old_mac_keys), ==, message_id-1);
		otrv4_assert(response_to_alice->to_send == NULL);
		otrv4_response_free(response_to_alice);
		response_to_alice = NULL;

		//Next message Bob  sends is a new "ratchet"
		g_assert_cmpint(bob->keys->i, ==, 0);
		g_assert_cmpint(bob->keys->j, ==, 0);
	}

	for (message_id = 1; message_id < 4; message_id++) {
		//Bob sends a data message
		otrv4_assert(otrv4_send_message(&to_send, "hello", NULL, bob));
		otrv4_assert(to_send);
		otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9);
		//g_assert_cmpint(list_len(bob->keys->old_mac_keys), ==, 0);

		//New ratchet hapenned
		g_assert_cmpint(bob->keys->i, ==, 1);
		g_assert_cmpint(bob->keys->j, ==, message_id);

		//Alice receives a data message
		response_to_bob = otrv4_response_new();
		otrv4_assert(otrv4_receive_message
			     (response_to_bob, (string_t) to_send,
			      strlen((char *)to_send), alice));
		free(to_send);
		to_send = NULL;

		otrv4_assert_cmpmem("hello", response_to_bob->to_display, 6);
		otrv4_assert(response_to_bob->to_send == NULL);
		otrv4_response_free(response_to_bob);
		response_to_bob = NULL;

		//Alice follows the ratchet 1 (and prepares to a new "ratchet")
		g_assert_cmpint(alice->keys->i, ==, 1);
		g_assert_cmpint(alice->keys->j, ==, 0);
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
	otrv4_keypair_destroy(alice_keypair);
	otrv4_keypair_destroy(bob_keypair);

	OTR4_FREE;
}

void test_api_smp(void)
{
	OTR4_INIT;

	otrv4_keypair_t alice_keypair[1], bob_keypair[1];
	uint8_t alice_sym[ED448_PRIVATE_BYTES] = { 1 };	// non-random private key on purpose
	otrv4_keypair_generate(alice_keypair, alice_sym);

	uint8_t bob_sym[ED448_PRIVATE_BYTES] = { 2 };	// non-random private key on purpose
	otrv4_keypair_generate(bob_keypair, bob_sym);

	otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4 };
	otrv4_t *alice = otrv4_new(alice_keypair, policy);
	otrv4_t *bob = otrv4_new(bob_keypair, policy);

	//AKE HAS FINISHED.
	do_ake_fixture(alice, bob);

	otrv4_response_t *response_to_bob = NULL;
	otrv4_response_t *response_to_alice = NULL;
	string_t to_send = NULL;
        char *secret = "secret";
        bool ok = false;

        // Alice sends SMP1
        ok = otrv4_smp_start(&to_send, NULL, (uint8_t *) secret, strlen(secret), alice);
        otrv4_assert(ok);
        otrv4_assert(to_send);
        otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP1

        //Bob receives SMP1
        response_to_alice = otrv4_response_new();
        ok = otrv4_receive_message(response_to_alice, to_send, strlen(to_send), bob);
        free(to_send);
        to_send = NULL;

        otrv4_assert(ok);
        otrv4_assert(!response_to_alice->to_send);
        otrv4_response_free(response_to_alice);
        response_to_alice = NULL;

        //This will be called by bob when the OTRV4_SMPEVENT_ASK_FOR_SECRET is
        //triggered.
        ok = otrv4_smp_continue(&to_send, (uint8_t *) secret, strlen(secret), bob);
        otrv4_assert(ok);
        otrv4_assert(to_send);
        otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP2

        //Alice receives SMP2
        response_to_bob = otrv4_response_new();
        ok = otrv4_receive_message(response_to_bob, to_send, strlen(to_send), alice);
        free(to_send);
        to_send = NULL;

        otrv4_assert(ok);
        otrv4_assert(response_to_bob->to_send);
        otrv4_assert_cmpmem("?OTR:AAQD", response_to_bob->to_send, 9); // SMP3

        //Bob receives SMP3
        response_to_alice = otrv4_response_new();
        ok = otrv4_receive_message(response_to_alice, response_to_bob->to_send, strlen(response_to_bob->to_send), bob);
        otrv4_response_free(response_to_bob);
        response_to_bob = NULL;

        otrv4_assert(ok);
        //TODO: Should be in the corect state
        otrv4_assert(response_to_alice->to_send);
        otrv4_assert_cmpmem("?OTR:AAQD", response_to_alice->to_send, 9); // SMP4

        //Alice receives SMP4
        response_to_bob = otrv4_response_new();
        ok = otrv4_receive_message(response_to_bob, response_to_alice->to_send, strlen(response_to_alice->to_send), alice);
        otrv4_response_free(response_to_alice);
        response_to_alice = NULL;

        otrv4_assert(ok);
        //TODO: Should be in the corect state
        otrv4_assert(!response_to_bob->to_send);


	otrv4_free(alice);
	otrv4_free(bob);
	otrv4_keypair_destroy(alice_keypair);
	otrv4_keypair_destroy(bob_keypair);

	OTR4_FREE;
}
