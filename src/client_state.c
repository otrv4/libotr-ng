/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libotr/privkey.h>
#include <stdio.h>

#define OTRNG_CLIENT_STATE_PRIVATE

#include "client_callbacks.h"
#include "client_state.h"
#include "deserialize.h"
#include "instance_tag.h"
#include "str.h"

#define HEARTBEAT_INTERVAL 60

tstatic otrng_bool should_heartbeat(int last_sent) {
  time_t now = time(NULL);
  if (last_sent < (now - HEARTBEAT_INTERVAL)) {
    return otrng_true;
  }
  return otrng_false;
}

tstatic otrng_result get_account_and_protocol_cb(
    char **account, char **protocol, const otrng_client_state_s *client_state) {
  if (!client_state->callbacks ||
      !client_state->callbacks->get_account_and_protocol) {
    return OTRNG_ERROR;
  }

  return client_state->callbacks->get_account_and_protocol(
      account, protocol, client_state->client_id);
}

INTERNAL otrng_result otrng_client_state_get_account_and_protocol(
    char **account, char **protocol, const otrng_client_state_s *client_state) {
  return get_account_and_protocol_cb(account, protocol, client_state);
}

INTERNAL otrng_client_state_s *otrng_client_state_new(const void *client_id) {
  otrng_client_state_s *client_state = malloc(sizeof(otrng_client_state_s));
  if (!client_state) {
    return NULL;
  }

  client_state->client_id = client_id;
  client_state->callbacks = NULL;
  client_state->user_state = NULL;
  client_state->keypair = NULL;
  client_state->our_prekeys = NULL;
  client_state->client_profile = NULL;
  client_state->prekey_profile = NULL;
  client_state->shared_prekey_pair = NULL;
  client_state->max_stored_msg_keys = 1000;
  client_state->max_published_prekey_msg = 100;
  client_state->minimum_stored_prekey_msg = 20;
  client_state->should_heartbeat = should_heartbeat;
  client_state->padding = 0;

  return client_state;
}

INTERNAL void otrng_client_state_free(otrng_client_state_s *client_state) {
  otrng_keypair_free(client_state->keypair);
  otrng_list_free(client_state->our_prekeys, stored_prekeys_free_from_list);
  otrng_client_profile_free(client_state->client_profile);
  otrng_prekey_profile_free(client_state->prekey_profile);
  otrng_shared_prekey_pair_free(client_state->shared_prekey_pair);

  free(client_state);
}

INTERNAL OtrlPrivKey *otrng_client_state_get_private_key_v3(
    const otrng_client_state_s *client_state) {
  OtrlPrivKey *ret = NULL;

  // TODO: We could use a "get storage key" callback and use it as
  // account_name plus an arbitrary "libotrng-storage" protocol.
  char *account_name = NULL;
  char *protocol_name = NULL;
  if (!get_account_and_protocol_cb(&account_name, &protocol_name,
                                   client_state)) {
    return ret;
  }

  ret =
      otrl_privkey_find(client_state->user_state, account_name, protocol_name);

  free(account_name);
  free(protocol_name);
  return ret;
}

INTERNAL otrng_keypair_s *
otrng_client_state_get_keypair_v4(otrng_client_state_s *client_state) {
  if (!client_state) {
    return NULL;
  }

  if (client_state->keypair) {
    return client_state->keypair;
  }

  /* @secret_information: the long-term key pair lives for as long the client
     decides */
  otrng_client_callbacks_create_privkey_v4(client_state->callbacks,
                                           client_state->client_id);

  return client_state->keypair;
}

INTERNAL otrng_result
otrng_client_state_add_private_key_v4(otrng_client_state_s *client_state,
                                      const uint8_t sym[ED448_PRIVATE_BYTES]) {
  if (!client_state) {
    return OTRNG_ERROR;
  }

  if (client_state->keypair) {
    return OTRNG_ERROR;
  }

  /* @secret_information: the long-term key pair lives for as long the client
     decides */
  client_state->keypair = otrng_keypair_new();
  if (!client_state->keypair) {
    return OTRNG_ERROR;
  }

  otrng_keypair_generate(client_state->keypair, sym);
  return OTRNG_SUCCESS;
}

API const client_profile_s *
otrng_client_state_get_client_profile(otrng_client_state_s *client_state) {
  if (!client_state) {
    return NULL;
  }

  if (client_state->client_profile) {
    return client_state->client_profile;
  }

  otrng_client_callbacks_create_client_profile(
      client_state->callbacks, client_state, client_state->client_id);

  return client_state->client_profile;
}

API client_profile_s *otrng_client_state_build_default_client_profile(
    otrng_client_state_s *client_state) {
  // TODO: Get allowed versions from the policy
  if (!client_state) {
    return NULL;
  }

  const char *allowed_versions = "34";
  return otrng_client_profile_build(
      otrng_client_state_get_instance_tag(client_state), allowed_versions,
      otrng_client_state_get_keypair_v4(client_state));
}

API otrng_result otrng_client_state_add_client_profile(
    otrng_client_state_s *client_state, const client_profile_s *profile) {
  if (!client_state) {
    return OTRNG_ERROR;
  }

  if (client_state->client_profile) {
    return OTRNG_ERROR;
  }

  client_state->client_profile = malloc(sizeof(client_profile_s));
  if (!client_state->client_profile) {
    return OTRNG_ERROR;
  }

  otrng_client_profile_copy(client_state->client_profile, profile);
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_state_add_shared_prekey_v4(
    otrng_client_state_s *client_state,
    const uint8_t sym[ED448_PRIVATE_BYTES]) {
  if (!client_state) {
    return OTRNG_ERROR;
  }

  if (client_state->shared_prekey_pair) {
    return OTRNG_ERROR;
  }

  /* @secret_information: the shared keypair lives for as long the client
     decides */
  client_state->shared_prekey_pair = otrng_shared_prekey_pair_new();
  if (!client_state->shared_prekey_pair) {
    return OTRNG_ERROR;
  }

  otrng_shared_prekey_pair_generate(client_state->shared_prekey_pair, sym);
  return OTRNG_SUCCESS;
}

static const otrng_shared_prekey_pair_s *
get_shared_prekey_pair(otrng_client_state_s *client_state) {
  if (!client_state) {
    return NULL;
  }

  if (client_state->shared_prekey_pair) {
    return client_state->shared_prekey_pair;
  }

  otrng_client_callbacks_create_shared_prekey(
      client_state->callbacks, client_state, client_state->client_id);

  return client_state->shared_prekey_pair;
}

API otrng_prekey_profile_s *otrng_client_state_build_default_prekey_profile(
    otrng_client_state_s *client_state) {
  if (!client_state) {
    return NULL;
  }

  /* @secret: the shared prekey should be deleted once the prekey profile
   * expires */
  return otrng_prekey_profile_build(
      otrng_client_state_get_instance_tag(client_state),
      otrng_client_state_get_keypair_v4(client_state),
      get_shared_prekey_pair(client_state));
}

API const otrng_prekey_profile_s *
otrng_client_state_get_prekey_profile(otrng_client_state_s *client_state) {
  if (!client_state) {
    return NULL;
  }

  if (client_state->prekey_profile) {
    return client_state->prekey_profile;
  }

  otrng_client_callbacks_create_prekey_profile(
      client_state->callbacks, client_state, client_state->client_id);

  return client_state->prekey_profile;
}

API otrng_result otrng_client_state_add_prekey_profile(
    otrng_client_state_s *client_state, const otrng_prekey_profile_s *profile) {
  if (!client_state) {
    return OTRNG_ERROR;
  }

  if (client_state->prekey_profile) {
    return OTRNG_ERROR;
  }

  client_state->prekey_profile = malloc(sizeof(otrng_prekey_profile_s));
  if (!client_state->prekey_profile) {
    return OTRNG_ERROR;
  }

  otrng_prekey_profile_copy(client_state->prekey_profile, profile);
  return OTRNG_SUCCESS;
}

tstatic OtrlInsTag *otrng_instance_tag_new(const char *protocol,
                                           const char *account,
                                           unsigned int instag) {
  if (instag < OTRNG_MIN_VALID_INSTAG) {
    return NULL;
  }

  OtrlInsTag *p = malloc(sizeof(OtrlInsTag));
  if (!p) {
    return NULL;
  }

  p->accountname = otrng_strdup(account);
  p->protocol = otrng_strdup(protocol);
  p->instag = instag;

  return p;
}

tstatic void otrl_userstate_instance_tag_add(OtrlUserState us, OtrlInsTag *p) {
  // This comes from libotr
  p->next = us->instag_root;
  if (p->next) {
    p->next->tous = &(p->next);
  }

  p->tous = &(us->instag_root);
  us->instag_root = p;
}

INTERNAL otrng_result otrng_client_state_add_instance_tag(
    otrng_client_state_s *client_state, unsigned int instag) {
  if (!client_state) {
    return OTRNG_ERROR;
  }

  if (!client_state->user_state) {
    return OTRNG_ERROR;
  }

  // TODO: We could use a "get storage key" callback and use it as
  // account_name plus an arbitrary "libotrng-storage" protocol.
  char *account_name = NULL;
  char *protocol_name = NULL;
  if (!get_account_and_protocol_cb(&account_name, &protocol_name,
                                   client_state)) {
    return OTRNG_ERROR;
  }

  OtrlInsTag *p =
      otrl_instag_find(client_state->user_state, account_name, protocol_name);
  if (p) {
    free(account_name);
    free(protocol_name);
    return OTRNG_ERROR;
  }

  p = otrng_instance_tag_new(protocol_name, account_name, instag);

  free(account_name);
  free(protocol_name);
  if (!p) {
    return OTRNG_ERROR;
  }

  otrl_userstate_instance_tag_add(client_state->user_state, p);
  return OTRNG_SUCCESS;
}

INTERNAL unsigned int
otrng_client_state_get_instance_tag(const otrng_client_state_s *client_state) {
  if (!client_state->user_state) {
    return (unsigned int)0;
  }

  // TODO: We could use a "get storage key" callback and use it as
  // account_name plus an arbitrary "libotrng-storage" protocol.
  char *account_name = NULL;
  char *protocol_name = NULL;
  if (!get_account_and_protocol_cb(&account_name, &protocol_name,
                                   client_state)) {
    return (unsigned int)1;
  }

  OtrlInsTag *instag =
      otrl_instag_find(client_state->user_state, account_name, protocol_name);

  free(account_name);
  free(protocol_name);

  if (!instag) {
    otrng_client_callbacks_create_instag(client_state->callbacks,
                                         client_state->client_id);
  }

  if (!instag) {
    return (unsigned int)0;
  }

  return instag->instag;
}

tstatic list_element_s *get_stored_prekey_node_by_id(uint32_t id,
                                                     list_element_s *l) {
  while (l) {
    const otrng_stored_prekeys_s *s = l->data;
    if (!s) {
      continue;
    }

    if (s->id == id) {
      return l;
    }

    l = l->next;
  }

  return NULL;
}

INTERNAL void store_my_prekey_message(uint32_t id, uint32_t instance_tag,
                                      const ecdh_keypair_p ecdh_pair,
                                      const dh_keypair_p dh_pair,
                                      otrng_client_state_s *client_state) {
  if (!client_state) {
    return;
  }

  otrng_stored_prekeys_s *s = malloc(sizeof(otrng_stored_prekeys_s));
  s->id = id;
  s->sender_instance_tag = instance_tag;

  /* @secret the keypairs should be deleted once the double ratchet gets
   * initialized */
  otrng_ec_scalar_copy(s->our_ecdh->priv, ecdh_pair->priv);
  otrng_ec_point_copy(s->our_ecdh->pub, ecdh_pair->pub);
  s->our_dh->priv = otrng_dh_mpi_copy(dh_pair->priv);
  s->our_dh->pub = otrng_dh_mpi_copy(dh_pair->pub);

  client_state->our_prekeys = otrng_list_add(s, client_state->our_prekeys);
}

INTERNAL void
delete_my_prekey_message_by_id(uint32_t id,
                               otrng_client_state_s *client_state) {
  list_element_s *node =
      get_stored_prekey_node_by_id(id, client_state->our_prekeys);
  if (!node) {
    return;
  }

  client_state->our_prekeys =
      otrng_list_remove_element(node, client_state->our_prekeys);
  otrng_list_free(node, stored_prekeys_free_from_list);
}

INTERNAL const otrng_stored_prekeys_s *
get_my_prekeys_by_id(uint32_t id, const otrng_client_state_s *client_state) {
  list_element_s *node =
      get_stored_prekey_node_by_id(id, client_state->our_prekeys);
  if (!node) {
    return NULL;
  }

  return node->data;
}

API void otrng_client_state_set_padding(size_t granularity,
                                        otrng_client_state_s *client_state) {
  client_state->padding = granularity;
}

API void
otrng_client_state_set_max_stored_msg_keys(unsigned int max_stored_msg_keys,
                                           otrng_client_state_s *client_state) {
  client_state->max_stored_msg_keys = max_stored_msg_keys;
}

API void otrng_client_state_set_max_published_prekey_msg(
    unsigned int max_published_prekey_msg, otrng_client_state_s *client_state) {
  client_state->max_published_prekey_msg = max_published_prekey_msg;
}

API otrng_result otrng_client_state_get_max_published_prekey_msg(
    otrng_client_state_s *client_state) {
  if (!client_state) {
    return OTRNG_ERROR;
  }

  return client_state->max_published_prekey_msg;
}

API void otrng_client_state_set_minimum_stored_prekey_msg(
    unsigned int minimum_stored_prekey_msg,
    otrng_client_state_s *client_state) {
  client_state->minimum_stored_prekey_msg = minimum_stored_prekey_msg;
}

API otrng_result otrng_client_state_get_minimum_stored_prekey_msg(
    otrng_client_state_s *client_state) {
  if (!client_state) {
    return OTRNG_ERROR;
  }

  return client_state->minimum_stored_prekey_msg;
}

#ifdef DEBUG_API

#include "debug.h"

API void otrng_stored_prekeys_debug_print(FILE *f, int indent,
                                          otrng_stored_prekeys_s *s) {
  if (otrng_debug_print_should_ignore("stored_prekeys")) {
    return;
  }

  otrng_print_indent(f, indent);
  fprintf(f, "stored_prekeys(");
  otrng_debug_print_pointer(f, s);
  fprintf(f, ") {\n");

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("stored_prekeys->id")) {
    fprintf(f, "id = IGNORED\n");
  } else {
    fprintf(f, "id = %x\n", s->id);
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("stored_prekeys->sender_instance_tag")) {
    fprintf(f, "sender_instance_tag = IGNORED\n");
  } else {
    fprintf(f, "sender_instance_tag = %x\n", s->sender_instance_tag);
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("stored_prekeys->our_ecdh")) {
    fprintf(f, "our_ecdh = IGNORED\n");
  } else {
    fprintf(f, "our_ecdh = {\n");
    otrng_ecdh_keypair_debug_print(f, indent + 4, s->our_ecdh);
    otrng_print_indent(f, indent + 2);
    fprintf(f, "} // our_ecdh\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("stored_prekeys->our_dh")) {
    fprintf(f, "our_dh = IGNORED\n");
  } else {
    fprintf(f, "our_dh = {\n");
    otrng_dh_keypair_debug_print(f, indent + 4, s->our_dh);
    otrng_print_indent(f, indent + 2);
    fprintf(f, "} // our_dh\n");
  }

  otrng_print_indent(f, indent);
  fprintf(f, "} // stored_prekeys\n");
}

API void otrng_client_state_debug_print(FILE *f, int indent,
                                        otrng_client_state_s *state) {
  int ix;
  list_element_s *curr;

  if (otrng_debug_print_should_ignore("client_state")) {
    return;
  }

  otrng_print_indent(f, indent);
  fprintf(f, "client_state(");
  otrng_debug_print_pointer(f, state);
  fprintf(f, ") {\n");

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_state->client_id")) {
    fprintf(f, "client_id = IGNORED\n");
  } else {
    fprintf(f, "client_id = ");
    otrng_client_id_debug_print(f, state->client_id);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_state->callbacks")) {
    fprintf(f, "callbacks = IGNORED\n");
  } else {
    fprintf(f, "callbacks = {\n");
    otrng_client_callbacks_debug_print(f, indent + 4, state->callbacks);
    otrng_print_indent(f, indent + 2);
    fprintf(f, "} // callbacks\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_state->v3_user_state")) {
    fprintf(f, "v3_user_state = IGNORED\n");
  } else {
    fprintf(f, "v3_user_state = ");
    otrng_debug_print_pointer(f, state->user_state);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_state->keypair")) {
    fprintf(f, "keypair = IGNORED\n");
  } else {
    fprintf(f, "keypair = {\n");
    otrng_keypair_debug_print(f, indent + 4, state->keypair);
    otrng_print_indent(f, indent + 2);
    fprintf(f, "} // keypair\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_state->client_profile")) {
    fprintf(f, "client_profile = IGNORED\n");
  } else {
    fprintf(f, "client_profile = {\n");
    otrng_client_profile_debug_print(f, indent + 4, state->client_profile);
    otrng_print_indent(f, indent + 2);
    fprintf(f, "} // client_profile\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_state->prekey_profile")) {
    fprintf(f, "prekey_profile = IGNORED\n");
  } else {
    fprintf(f, "prekey_profile = {\n");
    otrng_prekey_profile_debug_print(f, indent + 4, state->prekey_profile);
    otrng_print_indent(f, indent + 2);
    fprintf(f, "} // prekey_profile\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_state->our_prekeys")) {
    fprintf(f, "our_prekeys = IGNORED\n");
  } else {
    fprintf(f, "our_prekeys = {\n");
    ix = 0;
    curr = state->our_prekeys;
    while (curr) {
      otrng_print_indent(f, indent + 4);
      fprintf(f, "[%d] = {\n", ix);
      otrng_stored_prekeys_debug_print(f, indent + 6, curr->data);
      otrng_print_indent(f, indent + 4);
      fprintf(f, "} // [%d]\n", ix);
      curr = curr->next;
      ix++;
    }
    otrng_print_indent(f, indent + 2);
    fprintf(f, "} // our_prekeys\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_state->shared_prekey_pair")) {
    fprintf(f, "shared_prekey_pair = IGNORED\n");
  } else {
    fprintf(f, "shared_prekey_pair = {\n");
    otrng_shared_prekey_pair_debug_print(f, indent + 4,
                                         state->shared_prekey_pair);
    otrng_print_indent(f, indent + 2);
    fprintf(f, "} // shared_prekey_pair\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_state->max_stored_msg_keys")) {
    fprintf(f, "max_stored_msg_keys = IGNORED\n");
  } else {
    fprintf(f, "max_stored_msg_keys = %u\n", state->max_stored_msg_keys);
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore(
          "client_state->max_published_prekey_msg")) {
    fprintf(f, "max_published_prekey_msg = IGNORED\n");
  } else {
    fprintf(f, "max_published_prekey_msg = %u\n",
            state->max_published_prekey_msg);
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore(
          "client_state->minimum_stored_prekey_msg")) {
    fprintf(f, "minimum_stored_prekey_msg = IGNORED\n");
  } else {
    fprintf(f, "minimum_stored_prekey_msg = %u\n",
            state->minimum_stored_prekey_msg);
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_state->should_heartbeat")) {
    fprintf(f, "should_heartbeat = IGNORED\n");
  } else {
    fprintf(f, "should_heartbeat = ");
    otrng_debug_print_pointer(f, state->should_heartbeat);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_state->padding")) {
    fprintf(f, "padding = IGNORED\n");
  } else {
    fprintf(f, "padding = %ld\n", state->padding);
  }

  otrng_print_indent(f, indent);
  fprintf(f, "} // client_state\n");
}

#endif /* DEBUG */
