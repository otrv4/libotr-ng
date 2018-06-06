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

tstatic heartbeat_s *set_heartbeat(int wait) {
  heartbeat_s *heartbeat = malloc(sizeof(heartbeat_s));
  if (!heartbeat)
    return NULL;
  heartbeat->time = wait;
  heartbeat->last_msg_sent = time(0);
  return heartbeat;
}

INTERNAL otrng_client_state_s *otrng_client_state_new(const void *client_id) {
  otrng_client_state_s *state = malloc(sizeof(otrng_client_state_s));
  if (!state)
    return NULL;

  state->client_id = client_id;
  state->account_name = NULL;
  state->protocol_name = NULL;
  state->callbacks = NULL;
  state->user_state = NULL;
  state->keypair = NULL;
  state->our_prekeys = NULL;
  state->client_profile = NULL;
  state->prekey_profile = NULL;
  state->shared_prekey_pair = NULL;
  state->phi = NULL;
  state->max_stored_msg_keys = 100;
  state->pad = false; // TODO: why is this a bool?
  state->heartbeat = set_heartbeat(
      300); // TODO: why is this set here, and not from the client?

  return state;
}

INTERNAL void otrng_client_state_free(otrng_client_state_s *state) {
  state->client_id = NULL;
  state->user_state = NULL;

  free(state->protocol_name);
  state->protocol_name = NULL;
  free(state->account_name);
  state->account_name = NULL;

  state->callbacks = NULL;

  otrng_keypair_free(state->keypair);
  state->keypair = NULL;

  otrng_list_free(state->our_prekeys, stored_prekeys_free_from_list);
  state->our_prekeys = NULL;

  otrng_client_profile_free(state->client_profile);
  state->client_profile = NULL;

  otrng_prekey_profile_free(state->prekey_profile);
  state->prekey_profile = NULL;

  otrng_shared_prekey_pair_free(state->shared_prekey_pair);
  state->shared_prekey_pair = NULL;

  free(state->phi);
  state->phi = NULL;

  state->pad = false;
  state->max_stored_msg_keys = 0;

  free(state->heartbeat);
  state->heartbeat = NULL;

  free(state);
  state = NULL;
}

// TODO: There's no API that allows us to simply write all private keys to the
// file.
// We might want to extract otrl_privkey_generate_finish_FILEp into 2 functions.
INTERNAL int otrng_client_state_private_key_v3_generate_FILEp(
    const otrng_client_state_s *state, FILE *privf) {
  return otrl_privkey_generate_FILEp(state->user_state, privf,
                                     state->account_name, state->protocol_name);
}

INTERNAL otrng_keypair_s *
otrng_client_state_get_private_key_v4(otrng_client_state_s *state) {
  if (!state)
    return NULL;

  if (!state->keypair && state->callbacks && state->callbacks->create_privkey)
    state->callbacks->create_privkey(state->client_id);

  return state->keypair;
}

INTERNAL int
otrng_client_state_add_private_key_v4(otrng_client_state_s *state,
                                      const uint8_t sym[ED448_PRIVATE_BYTES]) {
  if (!state)
    return 1;

  if (state->keypair)
    return 0;

  state->keypair = otrng_keypair_new();
  if (!state->keypair)
    return 2;

  otrng_keypair_generate(state->keypair, sym);
  return 0;
}

INTERNAL int
otrng_client_state_private_key_v4_write_FILEp(otrng_client_state_s *state,
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

  if (!otrng_symmetric_key_serialize(&buff, &s, state->keypair->sym)) {
    return 1;
  }

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

INTERNAL int
otrng_client_state_private_key_v4_read_FILEp(otrng_client_state_s *state,
                                             FILE *privf) {
  char *line = NULL;
  size_t cap = 0;
  int len = 0;

  if (!privf)
    return -1;

  if (feof(privf))
    return 1;

  if (!state->keypair)
    state->keypair = otrng_keypair_new();

  if (!state->keypair)
    return -2;

  len = getline(&line, &cap, privf);
  if (len < 0) {
    free(line);
    line = NULL;
    return -3;
  }

  if (!otrng_symmetric_key_deserialize(state->keypair, line, len - 1)) {
    free(line);
    line = NULL;
    otrng_keypair_free(state->keypair);
    state->keypair = NULL;

    return 1;
  }

  free(line);
  line = NULL;

  return 0;
}

API const client_profile_s *
otrng_client_state_get_client_profile(otrng_client_state_s *state) {
  if (!state)
    return NULL;

  // TODO: Invoke callbacks?

  return state->client_profile;
}

API int otrng_client_state_add_client_profile(otrng_client_state_s *state,
                                              const client_profile_s *profile) {
  if (!state)
    return 1;

  if (state->client_profile)
    return 2;

  state->client_profile = malloc(sizeof(client_profile_s));
  if (!state->client_profile)
    return 3;

  otrng_client_profile_copy(state->client_profile, profile);
  return 0;
}

INTERNAL int otrng_client_state_add_shared_prekey_v4(
    otrng_client_state_s *state, const uint8_t sym[ED448_PRIVATE_BYTES]) {
  if (!state)
    return 1;

  if (state->shared_prekey_pair)
    return 0;

  state->shared_prekey_pair = otrng_shared_prekey_pair_new();
  if (!state->shared_prekey_pair)
    return 2;

  otrng_shared_prekey_pair_generate(state->shared_prekey_pair, sym);
  return 0;
}

API const otrng_prekey_profile_s *
otrng_client_state_get_prekey_profile(otrng_client_state_s *state) {
  if (!state)
    return NULL;

  // TODO: invoke callback to generate if profile is NULL

  return state->prekey_profile;
}

API int
otrng_client_state_add_prekey_profile(otrng_client_state_s *state,
                                      const otrng_prekey_profile_s *profile) {
  if (!state)
    return 1;

  if (state->prekey_profile)
    return 2;

  state->prekey_profile = malloc(sizeof(otrng_prekey_profile_s));
  if (!state->prekey_profile)
    return 3;

  otrng_prekey_profile_copy(state->prekey_profile, profile);
  return 0;
}

tstatic OtrlInsTag *otrl_instance_tag_new(const char *protocol,
                                          const char *account,
                                          unsigned int instag) {
  if (instag < OTRNG_MIN_VALID_INSTAG)
    return NULL;

  OtrlInsTag *p = malloc(sizeof(OtrlInsTag));
  if (!p)
    return NULL;

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
  if (!state)
    return 1;

  if (!state->user_state)
    return 1;

  OtrlInsTag *p =
      otrl_instance_tag_new(state->protocol_name, state->account_name, instag);
  if (!p)
    return -1;

  otrl_userstate_instance_tag_add(state->user_state, p);
  return 0;
}

INTERNAL unsigned int
otrng_client_state_get_instance_tag(otrng_client_state_s *state) {
  if (!state->user_state)
    return 0;

  OtrlInsTag *instag = otrl_instag_find(state->user_state, state->account_name,
                                        state->protocol_name);
  if (!instag)
    return 0;

  return instag->instag;
}

API int otrng_client_state_instance_tag_read_FILEp(otrng_client_state_s *state,
                                                   FILE *instag) {
  if (!state->user_state)
    return 1;

  return otrl_instag_read_FILEp(state->user_state, instag);
}

INTERNAL const client_profile_s *
otrng_client_state_get_client_profile_by_id(uint32_t id,
                                            otrng_client_state_s *state) {
  const client_profile_s *ret = otrng_client_state_get_client_profile(state);

  if (ret && ret->id == id)
    return ret;

  return NULL;
}

INTERNAL const client_profile_s *
otrng_client_state_get_or_create_client_profile(otrng_client_state_s *state) {
  const client_profile_s *ret = otrng_client_state_get_client_profile(state);
  if (ret)
    return ret;

  // TODO: invoke callback to generate profile if it is NULL, instead of doing
  // it here.
  // TODO: Versions should be configurable
  // TODO: should this ID be random? It should probably be unique for us, so
  // we need to store this in client state (?)
  uint32_t our_instance_tag = otrng_client_state_get_instance_tag(state);
  state->client_profile =
      otrng_client_profile_build(0x101, our_instance_tag, "34", state->keypair);

  return state->client_profile;
}

INTERNAL const otrng_prekey_profile_s *
otrng_client_state_get_or_create_prekey_profile(otrng_client_state_s *state) {
  const otrng_prekey_profile_s *ret =
      otrng_client_state_get_prekey_profile(state);
  if (ret)
    return ret;

  // TODO: invoke callback to generate profile if it is NULL, instead of doing
  // it here.
  // TODO: should this ID be random? It should probably be unique for us, so
  // we need to store this in client state (?)
  uint32_t our_instance_tag = otrng_client_state_get_instance_tag(state);
  state->prekey_profile = otrng_prekey_profile_build(
      0x102, our_instance_tag, state->keypair, state->shared_prekey_pair);

  return state->prekey_profile;
}

INTERNAL const otrng_prekey_profile_s *
otrng_client_state_get_prekey_profile_by_id(uint32_t id,
                                            otrng_client_state_s *state) {
  const otrng_prekey_profile_s *ret = NULL;
  ret = otrng_client_state_get_prekey_profile(state);

  if (ret && ret->id == id)
    return ret;

  return NULL;
}

tstatic list_element_s *get_stored_prekey_node_by_id(uint32_t id,
                                                     list_element_s *l) {
  while (l) {
    const otrng_stored_prekeys_s *s = l->data;
    if (!s)
      continue;

    if (s->id == id)
      return l;

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

  otrng_ec_scalar_copy(s->our_ecdh->priv, ecdh_pair->priv);
  otrng_ec_point_copy(s->our_ecdh->pub, ecdh_pair->pub);
  s->our_dh->priv = otrng_dh_mpi_copy(dh_pair->priv);
  s->our_dh->pub = otrng_dh_mpi_copy(dh_pair->pub);

  state->our_prekeys = otrng_list_add(s, state->our_prekeys);
}

INTERNAL void delete_my_prekey_message_by_id(uint32_t id,
                                             otrng_client_state_s *state) {
  list_element_s *node = get_stored_prekey_node_by_id(id, state->our_prekeys);
  if (!node)
    return;

  state->our_prekeys = otrng_list_remove_element(node, state->our_prekeys);
  otrng_list_free(node, stored_prekeys_free_from_list);
}

INTERNAL const otrng_stored_prekeys_s *
get_my_prekeys_by_id(uint32_t id, const otrng_client_state_s *state) {
  list_element_s *node = get_stored_prekey_node_by_id(id, state->our_prekeys);
  if (!node)
    return NULL;

  return node->data;
}
