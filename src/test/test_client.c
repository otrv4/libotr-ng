#include "../client.h"

#include "../client.h"
#include "../instance_tag.h"
#include "../serialize.h"
#include "../sha3.h"

#define ALICE_IDENTITY "alice@otr.example"
#define BOB_IDENTITY "bob@otr.example"
#define CHARLIE_IDENTITY "charlie@otr.example"
#define DONT_FORCE_CREATE_CONVO 0
#define FORCE_CREATE_CONVO 1

void test_client_conversation_api() {
  OTR4_INIT;
  otrv4_keypair_t alice_keypair[1];
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrv4_keypair_generate(alice_keypair, sym);

  char *account = "";
  char *protocol = "";

  otr4_client_t *alice =
      otr4_client_new(alice_keypair, NULL, protocol, account, NULL);
  otrv4_assert(!alice->conversations);

  otr4_conversation_t *alice_to_bob = otr4_client_get_conversation(
      DONT_FORCE_CREATE_CONVO, BOB_IDENTITY, alice);
  otr4_conversation_t *alice_to_charlie = otr4_client_get_conversation(
      DONT_FORCE_CREATE_CONVO, CHARLIE_IDENTITY, alice);

  otrv4_assert(!alice->conversations);
  otrv4_assert(!alice_to_bob);
  otrv4_assert(!alice_to_charlie);

  alice_to_bob =
      otr4_client_get_conversation(FORCE_CREATE_CONVO, BOB_IDENTITY, alice);
  alice_to_charlie =
      otr4_client_get_conversation(FORCE_CREATE_CONVO, CHARLIE_IDENTITY, alice);

  otrv4_assert(alice_to_bob);
  otrv4_assert(alice_to_bob->conn);
  otrv4_assert(alice_to_charlie);
  otrv4_assert(alice_to_charlie->conn);

  alice_to_bob = otr4_client_get_conversation(DONT_FORCE_CREATE_CONVO,
                                              BOB_IDENTITY, alice);
  alice_to_charlie = otr4_client_get_conversation(DONT_FORCE_CREATE_CONVO,
                                                  CHARLIE_IDENTITY, alice);

  otrv4_assert(alice_to_bob);
  otrv4_assert(alice_to_bob->conn);
  otrv4_assert(alice_to_charlie);
  otrv4_assert(alice_to_charlie->conn);

  // Free memory
  otrv4_keypair_destroy(alice_keypair);
  otr4_client_free(alice);

  dh_free();
}

void test_client_api() {
  OTR4_INIT;

  otrv4_keypair_t alice_keypair[1], bob_keypair[1], charlie_keypair[1];
  uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};
  uint8_t charlie_sym[ED448_PRIVATE_BYTES] = {3};
  otrv4_keypair_generate(alice_keypair, alice_sym);
  otrv4_keypair_generate(bob_keypair, bob_sym);
  otrv4_keypair_generate(charlie_keypair, charlie_sym);

  otr4_client_t *alice = NULL, *bob = NULL, *charlie = NULL;

  char *account = "";
  char *protocol = "";

  alice = otr4_client_new(alice_keypair, NULL, protocol, account, NULL);
  bob = otr4_client_new(bob_keypair, NULL, protocol, account, NULL);
  charlie = otr4_client_new(charlie_keypair, NULL, protocol, account, NULL);

  char *query_msg_to_bob =
      otr4_client_query_message(BOB_IDENTITY, "Hi bob", alice);
  otrv4_assert(query_msg_to_bob);

  char *query_msg_to_charlie =
      otr4_client_query_message(CHARLIE_IDENTITY, "Hi charlie", alice);
  otrv4_assert(query_msg_to_charlie);

  int ignore = 0;
  char *from_alice_to_bob = NULL, *from_alice_to_charlie = NULL,
       *frombob = NULL, *fromcharlie = NULL, *todisplay = NULL;

  // Bob receives query message, sends identity msg
  ignore = otr4_client_receive(&frombob, &todisplay, query_msg_to_bob,
                               ALICE_IDENTITY, bob);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);
  free(query_msg_to_bob);

  // Charlie receives query message, sends identity message
  ignore = otr4_client_receive(&fromcharlie, &todisplay, query_msg_to_charlie,
                               ALICE_IDENTITY, charlie);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);
  free(query_msg_to_charlie);

  otr4_conversation_t *alice_to_bob = otr4_client_get_conversation(
      DONT_FORCE_CREATE_CONVO, BOB_IDENTITY, alice);
  otr4_conversation_t *alice_to_charlie = otr4_client_get_conversation(
      DONT_FORCE_CREATE_CONVO, CHARLIE_IDENTITY, alice);

  otrv4_assert(alice_to_bob->conn->state == OTRV4_STATE_START);
  otrv4_assert(alice_to_charlie->conn->state == OTRV4_STATE_START);

  // Alice receives identity message (from Bob), sends Auth-R message
  ignore = otr4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  otrv4_assert(from_alice_to_bob);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);
  free(frombob);
  frombob = NULL;

  // Alice receives identity message (from Charlie), sends Auth-R message
  ignore = otr4_client_receive(&from_alice_to_charlie, &todisplay, fromcharlie,
                               CHARLIE_IDENTITY, alice);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);
  free(fromcharlie);
  fromcharlie = NULL;

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otr4_client_receive(&frombob, &todisplay, from_alice_to_bob,
                               ALICE_IDENTITY, bob);
  otrv4_assert(ignore);
  otrv4_assert(frombob);
  otrv4_assert(!todisplay);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Charlie receives Auth-R message, sends Auth-I message
  ignore = otr4_client_receive(&fromcharlie, &todisplay, from_alice_to_charlie,
                               ALICE_IDENTITY, charlie);
  otrv4_assert(ignore);
  otrv4_assert(fromcharlie);
  otrv4_assert(!todisplay);
  free(from_alice_to_charlie);
  from_alice_to_charlie = NULL;

  // Alice receives Auth-I message (from Bob)
  ignore = otr4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  otrv4_assert(!from_alice_to_bob);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);
  free(frombob);
  frombob = NULL;

  // Alice receives Auth-I message (from Charlie)
  ignore = otr4_client_receive(&from_alice_to_charlie, &todisplay, fromcharlie,
                               CHARLIE_IDENTITY, alice);
  otrv4_assert(!from_alice_to_charlie);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);
  free(fromcharlie);
  fromcharlie = NULL;

  // Alice sends a disconnected to Bob
  int err = otr4_client_disconnect(&from_alice_to_bob, BOB_IDENTITY, alice);
  otrv4_assert(!err);
  otrv4_assert(from_alice_to_bob);

  // We've deleted the conversation
  otrv4_assert(!otr4_client_get_conversation(DONT_FORCE_CREATE_CONVO,
                                             BOB_IDENTITY, alice));
  // TODO: Should we keep the conversation and set state to start instead?
  // g_assert_cmpint(alice_to_bob->conn->state, ==, OTRV4_STATE_START);

  // Bob receives the disconnected from Alice
  ignore = otr4_client_receive(&frombob, &todisplay, from_alice_to_bob,
                               ALICE_IDENTITY, bob);
  otrv4_assert(ignore);
  otrv4_assert(!frombob);
  otrv4_assert(!todisplay);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrv4_keypair_destroy(alice_keypair);
  otrv4_keypair_destroy(bob_keypair);
  otrv4_keypair_destroy(charlie_keypair);

  // Free memory
  otr4_client_free(charlie);
  otr4_client_free(bob);
  otr4_client_free(alice);

  OTR4_FREE
}

void test_client_get_our_fingerprint() {
  OTR4_INIT;

  otrv4_keypair_t client_keypair[1];
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrv4_keypair_generate(client_keypair, sym);

  char *account = "";
  char *protocol = "";

  otr4_client_t *client =
      otr4_client_new(client_keypair, NULL, protocol, account, NULL);

  otrv4_fingerprint_t our_fp = {0};
  otrv4_assert(!otr4_client_get_our_fingerprint(our_fp, client));

  uint8_t serialized[ED448_PUBKEY_BYTES] = {0};
  g_assert_cmpint(serialize_otrv4_public_key(serialized, client->keypair->pub),
                  ==, ED448_PUBKEY_BYTES);

  otrv4_fingerprint_t expected_fp = {0};
  bool ok = sha3_512(expected_fp, sizeof(otrv4_fingerprint_t), serialized,
                     sizeof(serialized));
  otrv4_assert(ok == TRUE);
  otrv4_assert_cmpmem(expected_fp, our_fp, sizeof(otrv4_fingerprint_t));

  otrv4_keypair_destroy(client_keypair);

  otr4_client_free(client);

  dh_free();
}

void test_fingerprint_hash_to_human() {
  char *expected_fp = "00010203 04050607 08090A0B 0C0D0E0F "
                      "10111213 14151617 18191A1B 1C1D1E1F "
                      "20212223 24252627 28292A2B 2C2D2E2F "
                      "30313233 34353637 38393A3B 3C3D3E3F";

  uint8_t fp_hash[OTR4_FPRINT_LEN_BYTES] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,

      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,

      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,

      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
      0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
  };

  char fp_human[OTR4_FPRINT_HUMAN_LEN];
  memset(fp_human, 0, OTR4_FPRINT_HUMAN_LEN);

  otr4_fingerprint_hash_to_human(fp_human, fp_hash);

  g_assert_cmpint(0, ==, strncmp(expected_fp, fp_human, OTR4_FPRINT_HUMAN_LEN));
}

void test_conversation_data_message_with_multiple_locations() {
  OTR4_INIT;

  otrv4_keypair_t alice_keypair[1], bob_keypair[1];
  uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};
  otrv4_keypair_generate(alice_keypair, alice_sym);
  otrv4_keypair_generate(bob_keypair, bob_sym);

  otr4_client_t *alice = NULL, *bob = NULL;

  char *account = "";
  char *protocol = "";

  alice = otr4_client_new(alice_keypair, NULL, protocol, account, NULL);
  bob = otr4_client_new(bob_keypair, NULL, protocol, account, NULL);

  // Clients should have an instance tag
  otrv4_assert(alice->instag);
  otrv4_assert(bob->instag);

  char *query_msg = otr4_client_query_message(BOB_IDENTITY, "Hi bob", alice);

  int ignore = 0;
  char *from_alice_to_bob = NULL, *frombob = NULL, *todisplay = NULL;

  // Bob receives query message, sends identity msg
  ignore =
      otr4_client_receive(&frombob, &todisplay, query_msg, ALICE_IDENTITY, bob);
  free(query_msg);

  // Alice receives identity message (from Bob), sends Auth-R message
  ignore = otr4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  free(frombob);
  frombob = NULL;

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otr4_client_receive(&frombob, &todisplay, from_alice_to_bob,
                               ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Alice receives Auth-I message (from Bob)
  ignore = otr4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  free(frombob);
  frombob = NULL;

  // Bob sends a message with orginal intance tag
  otr4_client_send(&frombob, "hello", ALICE_IDENTITY, bob);

  // Alice receives the message.
  ignore = otr4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  free(frombob);
  frombob = NULL;

  otrv4_assert(!ignore);
  otrv4_assert(!from_alice_to_bob);
  otrv4_assert(todisplay);

  free(todisplay);

  // Bob sends a message with a different instance tag
  alice->instag->value = alice->instag->value + 1;
  otr4_client_send(&frombob, "hello again", ALICE_IDENTITY, bob);

  // Alice receives and ignores the message.
  ignore = otr4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);

  free(frombob);
  frombob = NULL;

  // Alice sends a disconnected to Bob
  otr4_client_disconnect(&from_alice_to_bob, BOB_IDENTITY, alice);

  // Bob receives the disconnected from Alice
  ignore = otr4_client_receive(&frombob, &todisplay, from_alice_to_bob,
                               ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrv4_keypair_destroy(alice_keypair);
  otrv4_keypair_destroy(bob_keypair);

  // Free memory
  otr4_client_free(bob);
  otr4_client_free(alice);

  OTR4_FREE
}

void test_conversation_with_multiple_locations() {
  OTR4_INIT;

  otrv4_keypair_t alice_keypair[1], bob_keypair[1];
  uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};
  otrv4_keypair_generate(alice_keypair, alice_sym);
  otrv4_keypair_generate(bob_keypair, bob_sym);

  FILE *tmpFILEp;
  tmpFILEp = tmpfile();

  char *icq_alice_account = "alice_icq";
  char *icq_protocol = "ICQ";
  unsigned int icq_instag_value = 0x9abcdef0;

  fprintf(tmpFILEp, "%s\t%s\t%08x\n", icq_alice_account, icq_protocol,
          icq_instag_value);
  rewind(tmpFILEp);

  char *protocol = "";
  char *account = "";

  otr4_client_t *alice = NULL, *bob = NULL;

  alice = otr4_client_new(alice_keypair, NULL, icq_protocol, icq_alice_account,
                          tmpFILEp);
  bob = otr4_client_new(bob_keypair, NULL, protocol, account, tmpFILEp);

  // Clients should have an instance tag
  otrv4_assert(alice->instag);
  otrv4_assert(bob->instag);

  char sone[9];
  snprintf(sone, sizeof(sone), "%08x", alice->instag->value);

  g_assert_cmpstr(sone, ==, "9abcdef0");

  // Alice sends a query message to bob
  char *query_msg = otr4_client_query_message(BOB_IDENTITY, "Hi bob", alice);

  int ignore = 0;
  char *from_alice_to_bob = NULL, *frombob = NULL, *todisplay = NULL;

  // Bob receives query message, sends identity msg
  ignore =
      otr4_client_receive(&frombob, &todisplay, query_msg, ALICE_IDENTITY, bob);
  free(query_msg);

  // Alice receives identity message (from Bob), sends Auth-R message
  ignore = otr4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  free(frombob);
  frombob = NULL;

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otr4_client_receive(&frombob, &todisplay, from_alice_to_bob,
                               ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Alice receives Auth-I message (from Bob)
  ignore = otr4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  free(frombob);
  frombob = NULL;

  // Bob sends a message with orginal intance tag
  otr4_client_send(&frombob, "hello", ALICE_IDENTITY, bob);

  // Alice receives the message.
  ignore = otr4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  free(frombob);
  frombob = NULL;

  otrv4_assert(!ignore);
  otrv4_assert(!from_alice_to_bob);
  otrv4_assert(todisplay);

  free(todisplay);

  // Bob sends a message with a different instance tag
  alice->instag->value = alice->instag->value + 1;
  otr4_client_send(&frombob, "hello again", ALICE_IDENTITY, bob);

  // Alice receives and ignores the message.
  ignore = otr4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);

  free(frombob);
  frombob = NULL;

  // Alice sends a disconnected to Bob
  otr4_client_disconnect(&from_alice_to_bob, BOB_IDENTITY, alice);

  // Bob receives the disconnected from Alice
  ignore = otr4_client_receive(&frombob, &todisplay, from_alice_to_bob,
                               ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrv4_keypair_destroy(alice_keypair);
  otrv4_keypair_destroy(bob_keypair);

  // Free memory
  otr4_client_free(bob);
  otr4_client_free(alice);

  OTR4_FREE
}
