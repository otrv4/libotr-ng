#ifndef _OTR4_MESSAGING_H_
#define _OTR4_MESSAGING_H_

/* Defines an API to be used by an IM-plugin, like pidgin-otr4 */

/*
 * state = otr4_user_state_new();
 * otr4_user_state_private_key_v4_read_FILEp(state, priv4);
 * otr4_user_state_private_key_v4_write_FILEp(state, priv4);
 * otr4_user_state_private_key_v3_read_FILEp(state, priv3);
 * otr4_user_state_private_key_v3_write_FILEp(state, priv3);
 * otr4_user_state_add_private_key_v4(state, alice_xmpp, alice_priv4);
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

#include "client.h"
#include "list.h"

typedef otr4_client_t otr4_messaging_client_t;

typedef struct {
  list_element_t *keypairs_v4;
  list_element_t *instance_tags;
  list_element_t *clients;

  void *userstate_v3; // OtrlUserState
} otr4_userstate_t;

otr4_userstate_t *otr4_user_state_new(void);
void otr4_user_state_free(otr4_userstate_t *);

otr4_messaging_client_t *otr4_messaging_client_new(otr4_userstate_t *state,
                                                   void *opdata);

#endif