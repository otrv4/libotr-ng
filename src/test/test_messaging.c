#include "../messaging.h"

// These must be fixed pointers managed by the messaging app
static char *alice_account = "alice@xmpp";
static char *bob_account = "bob@xmpp";
static char *charlie_account = "charlie@xmpp";

static void *read_client_id_for_privf(FILE *privf) {
  // Uses the file pointer to read and locate the appropriate client_id in your
  // mesaging app
  fseek(privf, strlen(charlie_account) + 1, SEEK_CUR);
  return charlie_account;
}

void test_userstate_key_management(void) {
  OTR4_INIT;

  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};

  otr4_userstate_t *state = otr4_user_state_new(NULL);
  otr4_user_state_add_private_key_v4(state, alice_account, alice_sym);
  otr4_user_state_add_private_key_v4(state, bob_account, bob_sym);

  otrv4_assert(otr4_user_state_get_private_key_v4(state, alice_account));
  otrv4_assert(otr4_user_state_get_private_key_v4(state, bob_account));
  otrv4_assert(!otr4_user_state_get_private_key_v4(state, charlie_account));

  // Generate file
  FILE *keys = tmpfile();
  fputs("charlie@xmpp:"
        "RQ8MfhJljp+d1KUybu73Hj+Bve8lYTxE1wL5WDLyy+"
        "pLryYcPUYGIODpKqfEtrRH2d6fgbpBGmhA\n",
        keys);
  rewind(keys);

  int err = otr4_user_state_private_key_v4_read_FILEp(state, keys,
                                                      read_client_id_for_privf);
  g_assert_cmpint(err, ==, 0);
  fclose(keys);

  // TODO: Assert it is equal to deserializing the symkey
  // RQ8MfhJljp+d1KUybu73Hj+Bve8lYTxE1wL5WDLyy+pLryYcPUYGIODpKqfEtrRH2d6fgbpBGmhA"
  otrv4_assert(otr4_user_state_get_private_key_v4(state, charlie_account));

  otr4_user_state_free(state);
}

/*
 * Create callbacks for testing the callbacks API
 */

static otr4_userstate_t *test_state = NULL;

static void create_privkey_cb(void *client_id) {
  const uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otr4_user_state_add_private_key_v4(test_state, client_id, sym);
}

static otrv4_client_callbacks_t test_calbacks = {
    create_privkey_cb, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};

void test_api_messaging(void) {
  OTR4_INIT;

  test_state = otr4_user_state_new(&test_calbacks);

  // This will invoke create_privkey_cb() to create the private keys
  otrv4_assert(otr4_user_state_get_private_key_v4(test_state, alice_account));
  otrv4_assert(otr4_user_state_get_private_key_v4(test_state, bob_account));

  otr4_user_state_free(test_state);
  test_state = NULL;
}
