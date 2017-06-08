#include "messaging.h"

#include <libotr/userstate.h>

otr4_userstate_t *otr4_user_state_new(void) {
  otr4_userstate_t *state = malloc(sizeof(otr4_userstate_t));
  if (!state)
    return NULL;

  state->userstate_v3 = otrl_userstate_create();
  // state->keypairs_v3 = NULL;
  state->keypairs_v4 = NULL;
  state->instance_tags = NULL;
  state->clients = NULL;

  return state;
}

static void free_keypair_v4(void *data) {}

static void free_instance_tag(void *data) {}

static void free_client(void *data) { otr4_client_free(data); }

void otr4_user_state_free(otr4_userstate_t *state) {
  if (!state)
    return;

  // list_free(state->keypairs_v3, otrl_privkey_forget);
  // state->keypairs_v3 = NULL;

  list_free(state->keypairs_v4, free_keypair_v4);
  state->keypairs_v4 = NULL;

  list_free(state->instance_tags, free_instance_tag);
  state->instance_tags = NULL;

  list_free(state->clients, free_client);
  state->clients = NULL;

  otrl_userstate_free(state->userstate_v3);
  state->userstate_v3 = NULL;

  free(state);
}

otr4_messaging_client_t *otr4_messaging_client_new(otr4_userstate_t *state,
                                                   void *opdata) {
  // TODO: Should not create if theres already a client for this opdata
  //(What if it is null?)

  // TODO: Replace protocol, account by a function called on the opdata
  otr4_client_t *c = otr4_client_new(NULL, state->userstate_v3, "", "");
  if (!c)
    return NULL;

  c->opdata = opdata;
  state->clients = list_add(c, state->clients);

  return c;
}
