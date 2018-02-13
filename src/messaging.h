#ifndef OTRV4_MESSAGING_H_
#define OTRV4_MESSAGING_H_

/* Defines an API to be used by an IM-plugin, like pidgin-otr4 */

/*
 * state = otrv4_user_state_new();
 * otrv4_user_state_private_key_v4_read_FILEp(state, priv4);
 * otr4_user_state_private_key_v4_write_FILEp(state, priv4);
 * otr4_user_state_private_key_v3_read_FILEp(state, priv3);
 * otr4_user_state_private_key_v3_write_FILEp(state, priv3);
 * otrv4_user_state_add_private_key_v4(state, alice_xmpp, alice_priv4);
 * otr4_user_state_add_private_key_v3(state, alice_xmpp, alice_priv3);
 *
 * PurpleAccount *alice_xmpp;
 * client = otr4_messaging_client_new(state, alice_xmpp);
 *
 * client = otr4_messaging_client_get(alice_xmpp);
 *
 * PurpleConversation *alice_talking_to_bob;
 * otr4_messaging_client_sending(client, alice_talking_to_bob, instance, "hi");
 * otr4_messaging_client_receiving(client, alice_talking_to_bob);
 */

#include "shared.h"
#include "client.h"
#include "list.h"

// TODO: Remove?
typedef otrv4_client_t otr4_messaging_client_t;

typedef struct {
  list_element_t *states;
  list_element_t *clients;

  const otrv4_client_callbacks_t *callbacks;
  void *userstate_v3; /* OtrlUserState */
} otrv4_userstate_t;


/* int otr4_user_state_private_key_v3_generate_FILEp(otrv4_userstate_t *state, */
/*                                                   void *client_id, FILE *privf); */

/* int otr4_user_state_private_key_v3_read_FILEp(otrv4_userstate_t *state, */
/*                                               FILE *keys); */

/* int otr4_user_state_generate_private_key(otrv4_userstate_t *state, */
/*                                          void *client_id); */

/* int otr4_user_state_private_key_v4_write_FILEp(const otrv4_userstate_t *state, */
/*                                                FILE *privf); */

/* int otr4_user_state_add_instance_tag(otrv4_userstate_t *state, void *client_id, */
/*                                      unsigned int instag); */

/* unsigned int otr4_user_state_get_instance_tag(otrv4_userstate_t *state, */
/*                                               void *client_id); */

/* int otr4_user_state_instance_tags_read_FILEp(otrv4_userstate_t *state, */
/*                                              FILE *instag); */

/* otr4_messaging_client_t *otr4_messaging_client_get(otrv4_userstate_t *state, */
/*                                                    void *client_id); */


API int otrv4_user_state_private_key_v4_read_FILEp(
    otrv4_userstate_t *state, FILE *keys,
    void *(*read_client_id_for_key)(FILE *filep));

API otrv4_keypair_t *otrv4_user_state_get_private_key_v4(otrv4_userstate_t *state,
                                                    void *client_id);

API int otrv4_user_state_add_private_key_v4(otrv4_userstate_t *state, void *client_id,
                                       const uint8_t sym[ED448_PRIVATE_BYTES]);

API otrv4_userstate_t *otrv4_user_state_new(const otrv4_client_callbacks_t *cb);

API void otrv4_user_state_free(otrv4_userstate_t *);

#ifdef OTRV4_MESSAGING_PRIVATE

/* tstatic otr4_messaging_client_t *otr4_messaging_client_new(otrv4_userstate_t *state, */
/*                                                    void *client_id); */

#endif

#endif
