#include "../messaging.h"

void test_api_messaging(void) {
  char *alice_account = "alice@xmpp";
  char *bob_account = "bob@xmpp";
  otr4_userstate_t *state = otr4_user_state_new();

  otr4_messaging_client_t *alice =
      otr4_messaging_client_new(state, alice_account);
  otrv4_assert(alice);

  otr4_messaging_client_t *bob = otr4_messaging_client_new(state, bob_account);
  otrv4_assert(bob);

  otr4_user_state_free(state);
}
