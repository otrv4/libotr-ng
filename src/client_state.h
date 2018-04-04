#ifndef OTRNG_CLIENT_STATE_H
#define OTRNG_CLIENT_STATE_H

#include <stdbool.h>

#include <gcrypt.h>

#include <libotr/userstate.h>

#include "client_callbacks.h"
#include "keys.h"
#include "shared.h"

typedef struct heartbeat_t {
  int time;
  time_t last_msg_sent;
} heartbeat_t;

typedef struct otrng_client_state_t {
  void *client_id; /* Data in the messaging application context that represents
                    a client and should map directly to it. For example, in
                    libpurple-based apps (like Pidgin) this could be a
                    PurpleAccount */

  // TODO: Replace with a callback that knows how to get these from the
  // client_id.
  char *account_name;
  char *protocol_name;

  const struct otrng_client_callbacks_t *callbacks;

  // TODO: We could point it directly to the user state and have access to the
  // callback and v3 user state
  OtrlUserState userstate;
  otrng_keypair_t *keypair;
  otrng_shared_prekey_pair_t *shared_prekey_pair; // TODO: is this something the
                                                  // client will generate? The
                                                  // spec does not specify.
  char *phi; // this is the shared session state
  bool pad;  // TODO: this can be replaced by length
  heartbeat_t *heartbeat;

  // OtrlPrivKey *privkeyv3; // ???
  // otrng_instag_t *instag; // TODO: Store the instance tag here rather than
  // use v3 User State as a store for instance tags
} otrng_client_state_t;

API int otrng_client_state_instance_tag_read_FILEp(otrng_client_state_t *state,
                                                   FILE *instag);

INTERNAL unsigned int
otrng_client_state_get_instance_tag(otrng_client_state_t *state);

INTERNAL int otrng_client_state_add_instance_tag(otrng_client_state_t *state,
                                                 unsigned int instag);

INTERNAL int
otrng_client_state_add_shared_prekey_v4(otrng_client_state_t *state,
                                        const uint8_t sym[ED448_PRIVATE_BYTES]);

INTERNAL int
otrng_client_state_private_key_v4_read_FILEp(otrng_client_state_t *state,
                                             FILE *privf);

INTERNAL int
otrng_client_state_private_key_v4_write_FILEp(otrng_client_state_t *state,
                                              FILE *privf);

INTERNAL int otrng_client_state_private_key_v3_generate_FILEp(
    const otrng_client_state_t *state, FILE *privf);

INTERNAL otrng_keypair_t *
otrng_client_state_get_private_key_v4(otrng_client_state_t *state);

INTERNAL int
otrng_client_state_add_private_key_v4(otrng_client_state_t *state,
                                      const uint8_t sym[ED448_PRIVATE_BYTES]);

INTERNAL void otrng_client_state_free(otrng_client_state_t *);

INTERNAL otrng_client_state_t *otrng_client_state_new(void *client_id);

#ifdef OTRNG_CLIENT_STATE_PRIVATE

tstatic heartbeat_t *set_heartbeat(int wait);

#endif

#endif
