/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
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

#include "client_state.h"
#include "deserialize.h"
#include "instance_tag.h"
#include "str.h"

#define HEARTBEAT_INTERVAL 60

tstatic int should_heartbeat(int last_sent) {
  time_t now = time(NULL);
  if (last_sent < (now - HEARTBEAT_INTERVAL)) {
    return 1;
  }
  return 0;
}

tstatic otrng_err get_account_and_protocol_cb(
    char **account, char **protocol, const otrng_client_state_s *state) {
  if (!state->callbacks || !state->callbacks->get_account_and_protocol) {
    return OTRNG_ERROR;
  }

  int err = state->callbacks->get_account_and_protocol(account, protocol,
                                                       state->client_id);
  if (err) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_err otrng_client_state_get_account_and_protocol(
    char **account, char **protocol, const otrng_client_state_s *state) {
  return get_account_and_protocol_cb(account, protocol, state);
}

INTERNAL otrng_client_state_s *otrng_client_state_new(const void *client_id) {
  otrng_client_state_s *state = malloc(sizeof(otrng_client_state_s));
  if (!state) {
    return NULL;
  }

  state->client_id = client_id;
  state->callbacks = NULL;
  state->user_state = NULL;
  state->keypair = NULL;
  state->our_prekeys = NULL;
  state->client_profile = NULL;
  state->prekey_profile = NULL;
  state->shared_prekey_pair = NULL;
  state->max_stored_msg_keys = 1000; // TODO: is this good enough default?
  state->max_published_prekey_msg = 100;
  state->minimum_stored_prekey_msg = 20;
  state->should_heartbeat = should_heartbeat;
  state->padding = 0;

  return state;
}

INTERNAL void otrng_client_state_free(otrng_client_state_s *state) {
  otrng_keypair_free(state->keypair);
  otrng_list_free(state->our_prekeys, stored_prekeys_free_from_list);
  otrng_client_profile_free(state->client_profile);
  otrng_prekey_profile_free(state->prekey_profile);
  otrng_shared_prekey_pair_free(state->shared_prekey_pair);

  free(state);
}

INTERNAL OtrlPrivKey *
otrng_client_state_get_private_key_v3(const otrng_client_state_s *state) {
  OtrlPrivKey *ret = NULL;

  // TODO: We could use a "get storage key" callback and use it as
  // account_name plus an arbitrary "libotrng-storage" protocol.
  char *account_name = NULL;
  char *protocol_name = NULL;
  if (!get_account_and_protocol_cb(&account_name, &protocol_name, state)) {
    return ret;
  }

  ret = otrl_privkey_find(state->user_state, account_name, protocol_name);

  free(account_name);
  free(protocol_name);
  return ret;
}

INTERNAL otrng_keypair_s *
otrng_client_state_get_keypair_v4(otrng_client_state_s *state) {
  if (!state) {
    return NULL;
  }

  if (state->keypair) {
    return state->keypair;
  }

  /* @secret_information: the long-term key pair lives for as long the client
     decides */
  otrng_client_callbacks_create_privkey_v4(state->callbacks, state->client_id);

  return state->keypair;
}

INTERNAL int
otrng_client_state_add_private_key_v4(otrng_client_state_s *state,
                                      const uint8_t sym[ED448_PRIVATE_BYTES]) {
  if (!state) {
    return 1;
  }

  if (state->keypair) {
    return 1;
  }

  /* @secret_information: the long-term key pair lives for as long the client
     decides */
  state->keypair = otrng_keypair_new();
  if (!state->keypair) {
    return 1;
  }

  otrng_keypair_generate(state->keypair, sym);
  return 0;
}

API const client_profile_s *
otrng_client_state_get_client_profile(otrng_client_state_s *state) {
  if (!state) {
    return NULL;
  }

  if (state->client_profile) {
    return state->client_profile;
  }

  otrng_client_callbacks_create_client_profile(state->callbacks, state,
                                               state->client_id);

  return state->client_profile;
}

API client_profile_s *
otrng_client_state_build_default_client_profile(otrng_client_state_s *state) {
  // TODO: Get allowed versions from the policy
  const char *allowed_versions = "34";
  return otrng_client_profile_build(otrng_client_state_get_instance_tag(state),
                                    allowed_versions,
                                    otrng_client_state_get_keypair_v4(state));
}

API int otrng_client_state_add_client_profile(otrng_client_state_s *state,
                                              const client_profile_s *profile) {
  if (!state) {
    return 1;
  }

  if (state->client_profile) {
    return 1;
  }

  state->client_profile = malloc(sizeof(client_profile_s));
  if (!state->client_profile) {
    return 1;
  }

  otrng_client_profile_copy(state->client_profile, profile);
  return 0;
}

INTERNAL int otrng_client_state_add_shared_prekey_v4(
    otrng_client_state_s *state, const uint8_t sym[ED448_PRIVATE_BYTES]) {
  if (!state) {
    return 1;
  }

  if (state->shared_prekey_pair) {
    return 1;
  }

  state->shared_prekey_pair = otrng_shared_prekey_pair_new();
  if (!state->shared_prekey_pair) {
    return 1;
  }

  otrng_shared_prekey_pair_generate(state->shared_prekey_pair, sym);
  return 0;
}

static const otrng_shared_prekey_pair_s *
get_shared_prekey_pair(otrng_client_state_s *state) {
  if (state->shared_prekey_pair) {
    return state->shared_prekey_pair;
  }

  otrng_client_callbacks_create_shared_prekey(state->callbacks,
                                              state->client_id);

  return state->shared_prekey_pair;
}

API otrng_prekey_profile_s *
otrng_client_state_build_default_prekey_profile(otrng_client_state_s *state) {
  /* @secret: the shared prekey should be deleted once the prekey profile
   * expires */
  return otrng_prekey_profile_build(otrng_client_state_get_instance_tag(state),
                                    otrng_client_state_get_keypair_v4(state),
                                    get_shared_prekey_pair(state));
}

API const otrng_prekey_profile_s *
otrng_client_state_get_prekey_profile(otrng_client_state_s *state) {
  if (!state) {
    return NULL;
  }

  if (state->prekey_profile) {
    return state->prekey_profile;
  }

  // TODO: @client invoke This should be done in a callback, but
  // client_callbacks_s does not have any.
  otrng_prekey_profile_s *p =
      otrng_client_state_build_default_prekey_profile(state);
  otrng_client_state_add_prekey_profile(state, p);
  otrng_prekey_profile_free(p);

  return state->prekey_profile;
}

API int
otrng_client_state_add_prekey_profile(otrng_client_state_s *state,
                                      const otrng_prekey_profile_s *profile) {
  if (!state) {
    return 1;
  }

  if (state->prekey_profile) {
    return 1;
  }

  state->prekey_profile = malloc(sizeof(otrng_prekey_profile_s));
  if (!state->prekey_profile) {
    return 1;
  }

  otrng_prekey_profile_copy(state->prekey_profile, profile);
  return 0;
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

INTERNAL int otrng_client_state_add_instance_tag(otrng_client_state_s *state,
                                                 unsigned int instag) {
  if (!state) {
    return 1;
  }

  if (!state->user_state) {
    return 1;
  }

  // TODO: We could use a "get storage key" callback and use it as
  // account_name plus an arbitrary "libotrng-storage" protocol.
  char *account_name = NULL;
  char *protocol_name = NULL;
  if (!get_account_and_protocol_cb(&account_name, &protocol_name, state)) {
    return 1;
  }

  OtrlInsTag *p =
      otrl_instag_find(state->user_state, account_name, protocol_name);
  if (p) {
    free(account_name);
    free(protocol_name);
    return 1;
  }

  p = otrng_instance_tag_new(protocol_name, account_name, instag);

  free(account_name);
  free(protocol_name);
  if (!p) {
    return 1;
  }

  otrl_userstate_instance_tag_add(state->user_state, p);
  return 0;
}

INTERNAL unsigned int
otrng_client_state_get_instance_tag(const otrng_client_state_s *state) {
  if (!state->user_state) {
    return 0;
  }

  // TODO: We could use a "get storage key" callback and use it as
  // account_name plus an arbitrary "libotrng-storage" protocol.
  char *account_name = NULL;
  char *protocol_name = NULL;
  if (!get_account_and_protocol_cb(&account_name, &protocol_name, state)) {
    return 1;
  }

  OtrlInsTag *instag =
      otrl_instag_find(state->user_state, account_name, protocol_name);

  free(account_name);
  free(protocol_name);

  if (!instag) {
    otrng_client_callbacks_create_instag(state->callbacks, state->client_id);
  }

  if (!instag) {
    return 0;
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
                                      otrng_client_state_s *state) {
  otrng_stored_prekeys_s *s = malloc(sizeof(otrng_stored_prekeys_s));
  s->id = id;
  s->sender_instance_tag = instance_tag;

  /* @secret the keypairs should be deleted once the double ratchet gets
   * initialized */
  otrng_ec_scalar_copy(s->our_ecdh->priv, ecdh_pair->priv);
  otrng_ec_point_copy(s->our_ecdh->pub, ecdh_pair->pub);
  s->our_dh->priv = otrng_dh_mpi_copy(dh_pair->priv);
  s->our_dh->pub = otrng_dh_mpi_copy(dh_pair->pub);

  state->our_prekeys = otrng_list_add(s, state->our_prekeys);
}

INTERNAL void delete_my_prekey_message_by_id(uint32_t id,
                                             otrng_client_state_s *state) {
  list_element_s *node = get_stored_prekey_node_by_id(id, state->our_prekeys);
  if (!node) {
    return;
  }

  state->our_prekeys = otrng_list_remove_element(node, state->our_prekeys);
  otrng_list_free(node, stored_prekeys_free_from_list);
}

INTERNAL const otrng_stored_prekeys_s *
get_my_prekeys_by_id(uint32_t id, const otrng_client_state_s *state) {
  list_element_s *node = get_stored_prekey_node_by_id(id, state->our_prekeys);
  if (!node) {
    return NULL;
  }

  return node->data;
}

API void otrng_client_state_set_padding(size_t granularity,
                                        otrng_client_state_s *state) {
  state->padding = granularity;
}

API void
otrng_client_state_set_max_stored_msg_keys(unsigned int max_stored_msg_keys,
                                           otrng_client_state_s *state) {
  state->max_stored_msg_keys = max_stored_msg_keys;
}

API void otrng_client_state_set_max_published_prekey_msg(
    unsigned int max_published_prekey_msg, otrng_client_state_s *state) {
  state->max_published_prekey_msg = max_published_prekey_msg;
}

API unsigned int
otrng_client_state_get_max_published_prekey_msg(otrng_client_state_s *state) {
  if (!state) {
    return 0;
  }

  return state->max_published_prekey_msg;
}

// TODO: move this to only prekey client
API void otrng_client_state_set_minimum_stored_prekey_msg(
    unsigned int minimum_stored_prekey_msg, otrng_client_state_s *state) {
  state->minimum_stored_prekey_msg = minimum_stored_prekey_msg;
}

API unsigned int
otrng_client_state_get_minimum_stored_prekey_msg(otrng_client_state_s *state) {
  if (!state) {
    return 0;
  }

  return state->minimum_stored_prekey_msg;
}
