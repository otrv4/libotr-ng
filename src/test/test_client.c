#include "../client.h"

#include "../sha3.h"
#include "../serialize.h"

#define ALICE_IDENTITY "alice@otr.example"
#define BOB_IDENTITY "bob@otr.example"
#define CHARLIE_IDENTITY "charlie@otr.example"

void
test_client_conversation_api() {
  OTR4_INIT;

  otr4_client_t *alice = otr4_client_new();
  otrv4_assert(!alice->conversations);
  cs_keypair_generate(alice->keypair);

  otr4_conversation_t* alice_to_bob = otr4_client_get_conversation(0, BOB_IDENTITY, alice);
  otr4_conversation_t* alice_to_charlie = otr4_client_get_conversation(0, CHARLIE_IDENTITY, alice);

  otrv4_assert(!alice->conversations);
  otrv4_assert(!alice_to_bob);
  otrv4_assert(!alice_to_charlie);

  alice_to_bob = otr4_client_get_conversation(1, BOB_IDENTITY, alice);
  alice_to_charlie = otr4_client_get_conversation(1, CHARLIE_IDENTITY, alice);

  otrv4_assert(alice_to_bob);
  otrv4_assert(alice_to_bob->conn);
  otrv4_assert(alice_to_charlie);
  otrv4_assert(alice_to_charlie->conn);

  alice_to_bob = otr4_client_get_conversation(0, BOB_IDENTITY, alice);
  alice_to_charlie = otr4_client_get_conversation(0, CHARLIE_IDENTITY, alice);

  otrv4_assert(alice_to_bob);
  otrv4_assert(alice_to_bob->conn);
  otrv4_assert(alice_to_charlie);
  otrv4_assert(alice_to_charlie->conn);

  // Free memory
  cs_keypair_destroy(alice->keypair);
  otr4_client_free(alice);
}

void
test_client_api() {
  OTR4_INIT;

  otr4_client_t *alice = NULL,
                *bob = NULL,
                *charlie = NULL;

  alice = otr4_client_new();
  bob = otr4_client_new();
  charlie = otr4_client_new();

  cs_keypair_generate(alice->keypair);
  cs_keypair_generate(bob->keypair);
  cs_keypair_generate(charlie->keypair);

  char *query_msg_to_bob = otr4_client_query_message(BOB_IDENTITY, "Hi bob", alice); 
  otrv4_assert(query_msg_to_bob);

  char *query_msg_to_charlie = otr4_client_query_message(CHARLIE_IDENTITY, "Hi charlie", alice); 
  otrv4_assert(query_msg_to_charlie);

  int ignore = 0;
  char *from_alice_to_bob = NULL,
       *from_alice_to_charlie = NULL,
       *frombob = NULL,
       *fromcharlie = NULL,
       *todisplay = NULL;

  //Bob receives query message, sends identity msg
  ignore = otr4_client_receive(&frombob, &todisplay, query_msg_to_bob, ALICE_IDENTITY, bob);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);
  free(query_msg_to_bob);

  //Charlie receives query message, sends identity msg
  ignore = otr4_client_receive(&fromcharlie, &todisplay, query_msg_to_charlie, ALICE_IDENTITY, charlie);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);
  free(query_msg_to_charlie);

  otr4_conversation_t* alice_to_bob = otr4_client_get_conversation(0, BOB_IDENTITY, alice);
  otr4_conversation_t* alice_to_charlie = otr4_client_get_conversation(0, CHARLIE_IDENTITY, alice);

  otrv4_assert(alice_to_bob->conn->state == OTRV4_STATE_START);
  otrv4_assert(alice_to_charlie->conn->state == OTRV4_STATE_START);

  //Alice receives identity message (from Bob), sends DRE auth msg
  ignore = otr4_client_receive(&from_alice_to_bob, &todisplay, frombob, BOB_IDENTITY, alice);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);
  free(frombob);
  frombob = NULL;

  //Alice receives identity message (from Charlie), sends DRE auth msg
  ignore = otr4_client_receive(&from_alice_to_charlie, &todisplay, fromcharlie, CHARLIE_IDENTITY, alice);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);
  free(fromcharlie);
  fromcharlie = NULL;

  //Bob receives DRE auth message.
  ignore = otr4_client_receive(&frombob, &todisplay, from_alice_to_bob, ALICE_IDENTITY, bob);
  otrv4_assert(ignore);
  otrv4_assert(!frombob);
  otrv4_assert(!todisplay);
  free(from_alice_to_bob);

  //Charlie receives DRE auth message.
  ignore = otr4_client_receive(&fromcharlie, &todisplay, from_alice_to_charlie, ALICE_IDENTITY, charlie);
  otrv4_assert(ignore);
  otrv4_assert(!fromcharlie);
  otrv4_assert(!todisplay);
  free(from_alice_to_charlie);

  // Free memory
  cs_keypair_destroy(charlie->keypair);
  cs_keypair_destroy(bob->keypair);
  cs_keypair_destroy(alice->keypair);

  otr4_client_free(charlie);
  otr4_client_free(bob);
  otr4_client_free(alice);
}

void
test_client_get_our_fingerprint() {
  OTR4_INIT;

  otr4_client_t *client = otr4_client_new();

  cs_keypair_generate(client->keypair);

  uint8_t *our_fp = otr4_client_get_our_fingerprint(client);
  otrv4_assert(our_fp);

  uint8_t serialized[170] = { 0 };
  g_assert_cmpint(serialize_cs_public_key(serialized, client->keypair->pub), ==, 170);

  uint8_t expected_fp[64] = {0};
  bool ok = sha3_512(expected_fp, sizeof(expected_fp), serialized, sizeof(serialized));
  otrv4_assert(ok == TRUE);
  otrv4_assert_cmpmem(expected_fp, our_fp, sizeof(expected_fp));

  free(our_fp);
  otr4_client_free(client);
}
