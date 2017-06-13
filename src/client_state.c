#include "client_state.h"

#include "deserialize.h"

otr4_client_state_t *otr4_client_state_new(void *client_id) {
  otr4_client_state_t *state = malloc(sizeof(otr4_client_state_t));
  if (!state)
    return NULL;

  state->client_id = client_id;
  state->userstate = NULL;
  state->keypair = NULL;
  state->instag = NULL;
  state->callbacks = NULL;

  return state;
}

void otr4_client_state_free(otr4_client_state_t *state) {
  state->client_id = NULL;

  otrv4_keypair_free(state->keypair);
  state->keypair = NULL;

  otr4_instag_free(state->instag);
  state->instag = NULL;

  state->callbacks = NULL;

  free(state);
}

otrv4_keypair_t *
otr4_client_state_get_private_key_v4(otr4_client_state_t *state) {
  if (!state)
    return NULL;

  if (!state->keypair && state->callbacks && state->callbacks->create_privkey)
    state->callbacks->create_privkey(state->client_id);

  return state->keypair;
}

void otr4_client_state_add_private_key_v4(
    otr4_client_state_t *state, const uint8_t sym[ED448_PRIVATE_BYTES]) {
  if (!state)
    return;

  if (state->keypair)
    return;

  state->keypair = otrv4_keypair_new();
  if (!state->keypair)
    return;

  otrv4_keypair_generate(state->keypair, sym);
}

int otr4_client_state_private_key_v4_read_FILEp(otr4_client_state_t *state,
                                                FILE *privf) {
  char *line = NULL;
  size_t cap = 0;
  int len = 0;
  int err = 0;

  if (!privf)
    return -1;

  if (feof(privf))
      return 1;

  if (!state->keypair)
    state->keypair = otrv4_keypair_new();

  if (!state->keypair)
    return -2;

  len = getline(&line, &cap, privf);
  if (len < 0) {
    free(line);
    return -3;
  }

  err = otrv4_symmetric_key_deserialize(state->keypair, line, len - 1);
  free(line);

  if (err) {
    otrv4_keypair_free(state->keypair);
    state->keypair = NULL;
  }

  return err;
}
