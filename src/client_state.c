#include "client_state.h"

#include <libotr/privkey.h>
#include <stdio.h>

#include "deserialize.h"
#include "instance_tag.h"
#include "str.h"

heartbeat_t *otrv4_set_heartbeat(int wait) {
  heartbeat_t *heartbeat = malloc(sizeof(heartbeat_t));
  if (!heartbeat)
    return NULL;
  heartbeat->time = wait;
  heartbeat->last_msg_sent = time(0);
  return heartbeat;
}

otr4_client_state_t *otr4_client_state_new(void *client_id) {
  otr4_client_state_t *state = malloc(sizeof(otr4_client_state_t));
  if (!state)
    return NULL;

  state->client_id = client_id;
  state->protocol_name = NULL;
  state->account_name = NULL;
  state->callbacks = NULL;
  state->userstate = NULL;
  state->keypair = NULL;
  state->shared_prekey_pair = NULL;
  state->phi = NULL;
  state->heartbeat = otrv4_set_heartbeat(300);

  return state;
}

void otr4_client_state_free(otr4_client_state_t *state) {
  state->client_id = NULL;
  state->userstate = NULL;

  free(state->protocol_name);
  state->protocol_name = NULL;
  free(state->account_name);
  state->account_name = NULL;

  state->callbacks = NULL;

  otrv4_keypair_free(state->keypair);
  state->keypair = NULL;

  otrv4_shared_prekey_pair_free(state->shared_prekey_pair);
  state->shared_prekey_pair = NULL;

  free(state->phi);
  state->phi = NULL;

  state->pad = false;

  free(state->heartbeat);
  state->heartbeat = NULL;

  free(state);
  state = NULL;
}

// TODO: There's no API that allows us to simply write all private keys to the
// file.
// We might want to extract otrl_privkey_generate_finish_FILEp into 2 functions.
int otr4_client_state_private_key_v3_generate_FILEp(
    const otr4_client_state_t *state, FILE *privf) {
  return otrl_privkey_generate_FILEp(state->userstate, privf,
                                     state->account_name, state->protocol_name);
}

otrv4_keypair_t *
otr4_client_state_get_private_key_v4(otr4_client_state_t *state) {
  if (!state)
    return NULL;

  if (!state->keypair && state->callbacks && state->callbacks->create_privkey)
    state->callbacks->create_privkey(state->client_id);

  return state->keypair;
}

int otr4_client_state_add_private_key_v4(
    otr4_client_state_t *state, const uint8_t sym[ED448_PRIVATE_BYTES]) {
  if (!state)
    return 1;

  if (state->keypair)
    return 0;

  state->keypair = otrv4_keypair_new();
  if (!state->keypair)
    return 2;

  otrv4_keypair_generate(state->keypair, sym);
  return 0;
}

int otr4_client_state_private_key_v4_write_FILEp(otr4_client_state_t *state,
                                                 FILE *privf) {
  if (!state->protocol_name || !state->account_name)
    return 1;

  char *key =
      malloc(strlen(state->protocol_name) + strlen(state->account_name) + 2);
  sprintf(key, "%s:%s", state->protocol_name, state->account_name);

  char *buff = NULL;
  size_t s = 0;
  int err = 0;

  if (!privf)
    return -1;

  if (!state->keypair)
    return -2;

  err = otrv4_symmetric_key_serialize(&buff, &s, state->keypair->sym);
  if (err)
    return err;

  err = fputs(key, privf);
  free(key);
  key = NULL;

  if (EOF == err)
    return -3;

  if (EOF == fputs("\n", privf))
    return -3;

  if (1 != fwrite(buff, s, 1, privf))
    return -3;

  if (EOF == fputs("\n", privf))
    return -3;

  return 0;
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
    line = NULL;
    return -3;
  }

  err = otrv4_symmetric_key_deserialize(state->keypair, line, len - 1);
  free(line);
  line = NULL;

  if (err) {
    otrv4_keypair_free(state->keypair);
    state->keypair = NULL;
  }

  return err;
}

int otr4_client_state_add_shared_prekey_v4(
    otr4_client_state_t *state, const uint8_t sym[ED448_PRIVATE_BYTES]) {
  if (!state)
    return 1;

  if (state->shared_prekey_pair)
    return 0;

  state->shared_prekey_pair = otrv4_shared_prekey_pair_new();
  if (!state->shared_prekey_pair)
    return 2;

  otrv4_shared_prekey_pair_generate(state->shared_prekey_pair, sym);
  return 0;
}

static OtrlInsTag *otrl_instance_tag_new(const char *protocol,
                                         const char *account,
                                         unsigned int instag) {
  if (instag < OTR4_MIN_VALID_INSTAG)
    return NULL;

  OtrlInsTag *p = malloc(sizeof(OtrlInsTag));
  if (!p)
    return NULL;

  p->accountname = otrv4_strdup(account);
  p->protocol = otrv4_strdup(protocol);
  p->instag = instag;

  return p;
}

static void otrl_userstate_instance_tag_add(OtrlUserState us, OtrlInsTag *p) {
  // This comes from libotr3
  p->next = us->instag_root;
  if (p->next) {
    p->next->tous = &(p->next);
  }

  p->tous = &(us->instag_root);
  us->instag_root = p;
}

int otr4_client_state_add_instance_tag(otr4_client_state_t *state,
                                       unsigned int instag) {
  OtrlInsTag *p =
      otrl_instance_tag_new(state->protocol_name, state->account_name, instag);
  if (!p)
    return -1;

  otrl_userstate_instance_tag_add(state->userstate, p);
  return 0;
}

unsigned int otr4_client_state_get_instance_tag(otr4_client_state_t *state) {
  if (!state->userstate)
    return 0;

  OtrlInsTag *instag = otrl_instag_find(state->userstate, state->account_name,
                                        state->protocol_name);
  if (!instag)
    return 0;

  return instag->instag;
}

int otr4_client_state_instance_tag_read_FILEp(otr4_client_state_t *state,
                                              FILE *instag) {
  if (!state->userstate)
    return 1;

  return otrl_instag_read_FILEp(state->userstate, instag);
}
