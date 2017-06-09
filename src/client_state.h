#ifndef _OTR4_CLIENT_STATE_H
#define _OTR4_CLIENT_STATE_H

#include <gcrypt.h>

#include <libotr/userstate.h>

#include "client_callbacks.h"
#include "instance_tag.h"
#include "keys.h"

typedef struct otr4_client_state_t {
  void *client_id; // Data in the messaging application context that represents
                   // a client and should map directly to it. For example, in
                   // libpurple-based apps (like Pidgin) this could be a
                   // PurpleAccount*

  const struct otrv4_client_callbacks_t *callbacks;

  // OtrlPrivKey *privkeyv3; // ???
  OtrlUserState userstate;
  otrv4_keypair_t *keypair;
  otrv4_instag_t *instag;
} otr4_client_state_t;

otr4_client_state_t *otr4_client_state_new(void *client_id);
void otr4_client_state_free(otr4_client_state_t *);

otrv4_keypair_t *
otr4_client_state_get_private_key_v4(otr4_client_state_t *state);

void otr4_client_state_add_private_key_v4(
    otr4_client_state_t *state, const uint8_t sym[ED448_PRIVATE_BYTES]);

int otr4_client_state_private_key_v4_read_FILEp(otr4_client_state_t *state,
                                                FILE *privf);

#endif
