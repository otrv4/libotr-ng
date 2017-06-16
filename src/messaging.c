#include "messaging.h"
#include "keys.h"

#include <libotr/privkey.h>

otr4_userstate_t *otr4_user_state_new(const otrv4_client_callbacks_t *cb) {
  otr4_userstate_t *state = malloc(sizeof(otr4_userstate_t));
  if (!state)
    return NULL;

  state->states = NULL;
  state->clients = NULL;
  state->callbacks = cb;

  state->userstate_v3 = otrl_userstate_create();

  return state;
}

static void free_client_state(void *data) { otr4_client_state_free(data); }

static void free_client(void *data) { otr4_client_free(data); }

void otr4_user_state_free(otr4_userstate_t *state) {
  if (!state)
    return;

  list_free(state->states, free_client_state);
  state->states = NULL;

  list_free(state->clients, free_client);
  state->clients = NULL;

  state->callbacks = NULL;

  otrl_userstate_free(state->userstate_v3);
  state->userstate_v3 = NULL;

  free(state);
}

static int find_state_by_client_id(const void *current, const void *wanted) {
  const otr4_client_state_t *s = current;
  return s->client_id == wanted;
}

static otr4_client_state_t *get_client_state(otr4_userstate_t *state,
                                             void *client_id) {
  list_element_t *el =
      list_get(client_id, state->states, find_state_by_client_id);
  if (el)
    return el->data;

  otr4_client_state_t *s = otr4_client_state_new(client_id);
  if (!s)
    return NULL;

  s->callbacks = state->callbacks;
  state->states = list_add(s, state->states);
  return s;
}

void otr4_user_state_add_private_key_v4(
    otr4_userstate_t *state, void *clientop,
    const uint8_t sym[ED448_PRIVATE_BYTES]) {
  otr4_client_state_add_private_key_v4(get_client_state(state, clientop), sym);
}

otr4_messaging_client_t *otr4_messaging_client_new(otr4_userstate_t *state,
                                                   void *client_id) {
  // TODO: Should not create if theres already a client for this client_id
  //(What if it is null?)

  otr4_client_state_t *s = get_client_state(state, client_id);
  if (!s)
    return NULL;

  // TODO: Replace protocol, account by a function called on the client_id
  otr4_client_t *c = otr4_client_new(s, "", "", NULL);
  if (!c)
    return NULL;

  state->clients = list_add(c, state->clients);

  return c;
}

static int find_client_by_client_id(const void *current, const void *wanted) {
  const otr4_client_t *s = current;
  return s && s->state && s->state->client_id == wanted;
}

otr4_messaging_client_t *otr4_messaging_client_get(otr4_userstate_t *state,
                                                   void *client_id) {
  list_element_t *el =
      list_get(client_id, state->clients, find_client_by_client_id);
  if (el)
    return el->data;

  return otr4_messaging_client_new(state, client_id);
}

otrv4_keypair_t *otr4_user_state_get_private_key_v4(otr4_userstate_t *state,
                                                    void *client_id) {
  return otr4_client_state_get_private_key_v4(
      get_client_state(state, client_id));
}

int otr4_user_state_private_key_v4_read_FILEp(
    otr4_userstate_t *state, FILE *privf,
    void *(*read_client_id_for_key)(FILE *filep)) {
  void *client_id = NULL;

  if (!privf)
    return 1;

  while (!feof(privf)) {
    client_id = read_client_id_for_key(privf);
    if (!client_id)
      continue;

    if (otr4_client_state_private_key_v4_read_FILEp(
            get_client_state(state, client_id), privf))
      continue;
  }

  return 0;
}

int otr4_user_state_private_key_v3_read_FILEp(otr4_userstate_t *state,
                                              FILE *keys) {
  return otrl_privkey_read_FILEp(state->userstate_v3, keys);
}

int otr4_user_state_instance_tags_read_FILEp(otr4_userstate_t *state,
                                             FILE *instag) {
  // TODO: Read for OTR4
  return otrl_instag_read_FILEp(state->userstate_v3, instag);
}
