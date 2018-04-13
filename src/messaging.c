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

#define OTRNG_MESSAGING_PRIVATE

#include "messaging.h"

API otrng_userstate_s *
otrng_user_state_new(const otrng_client_callbacks_s *cb) {
  otrng_userstate_s *state = malloc(sizeof(otrng_userstate_s));
  if (!state)
    return NULL;

  state->states = NULL;
  state->clients = NULL;
  state->callbacks = cb;

  state->userstate_v3 = otrl_userstate_create();

  return state;
}

tstatic void free_client_state(void *data) { otrng_client_state_free(data); }

tstatic void free_client(void *data) { otrng_client_free(data); }

API void otrng_user_state_free(otrng_userstate_s *state) {
  if (!state)
    return;

  otrng_list_free(state->states, free_client_state);
  state->states = NULL;

  otrng_list_free(state->clients, free_client);
  state->clients = NULL;

  state->callbacks = NULL;

  otrl_userstate_free(state->userstate_v3);
  state->userstate_v3 = NULL;

  free(state);
  state = NULL;
}

tstatic int find_state_by_client_id(const void *current, const void *wanted) {
  const otrng_client_state_s *s = current;
  return s->client_id == wanted;
}

tstatic otrng_client_state_s *get_client_state(otrng_userstate_s *state,
                                               const void *client_id) {
  list_element_s *el =
      otrng_list_get(client_id, state->states, find_state_by_client_id);
  if (el)
    return el->data;

  otrng_client_state_s *s = otrng_client_state_new(client_id);
  if (!s)
    return NULL;

  s->callbacks = state->callbacks;
  s->userstate = state->userstate_v3;

  state->states = otrng_list_add(s, state->states);
  return s;
}

/* tstatic int find_client_by_client_id(const void *current, const void *wanted)
 * { */
/*   const otrng_client_s *s = current; */
/*   return s && s->state && s->state->client_id == wanted; */
/* } */

/* tstatic otrng_messaging_client_t
 * *otrng_messaging_client_new(otrng_userstate_s *state, */
/*                                                    void *client_id) { */
/*   if (!client_id) { */
/*     return NULL; */
/*   } */

/*   list_element_s *e = */
/*       otrng_list_get(client_id, state->clients, find_client_by_client_id); */

/*   if (e) { */
/*     return e->data; */
/*   } else { */
/*     otrng_client_state_s *s = get_client_state(state, client_id); */
/*     if (!s) */
/*       return NULL; */

/*     otrng_client_s *c = otrng_client_new(s); */
/*     if (!c) */
/*       return NULL; */

/*     state->clients = otrng_list_add(c, state->clients); */

/*     return c; */
/*   } */
/* } */

/* otrng_messaging_client_t *otrng_messaging_client_get(otrng_userstate_s
 * *state,
 */
/*                                                    void *client_id) { */
/*   list_element_s *el = */
/*       otrng_list_get(client_id, state->clients, find_client_by_client_id); */
/*   if (el) */
/*     return el->data; */

/*   return otrng_messaging_client_new(state, client_id); */
/* } */

/* int otrng_user_state_private_key_v3_generate_FILEp(otrng_userstate_s *state,
 */
/*                                                   void *client_id, */
/*                                                   FILE *privf) { */
/*   return otrng_client_state_private_key_v3_generate_FILEp( */
/*       get_client_state(state, client_id), privf); */
/* } */

/* int otrng_user_state_private_key_v3_read_FILEp(otrng_userstate_s *state, */
/*                                               FILE *keys) { */
/*   return otrl_privkey_read_FILEp(state->userstate_v3, keys); */
/* } */

API int
otrng_user_state_add_private_key_v4(otrng_userstate_s *state,
                                    const void *clientop,
                                    const uint8_t sym[ED448_PRIVATE_BYTES]) {
  return otrng_client_state_add_private_key_v4(
      get_client_state(state, clientop), sym);
}

/* int otrng_user_state_generate_private_key(otrng_userstate_s *state, */
/*                                          void *client_id) { */
/*   uint8_t sym[ED448_PRIVATE_BYTES]; */
/*   gcry_randomize(sym, ED448_PRIVATE_BYTES, GCRY_VERY_STRONG_RANDOM); */
/*   return otrng_user_state_add_private_key_v4(state, client_id, sym); */
/* } */

API otrng_keypair_s *
otrng_user_state_get_private_key_v4(otrng_userstate_s *state,
                                    const void *client_id) {
  return otrng_client_state_get_private_key_v4(
      get_client_state(state, client_id));
}

/* tstatic void add_private_key_v4_to_FILEp(list_element_s *node, void *context)
 * { */
/*   FILE *privf = context; */
/*   otrng_client_state_s *state = node->data; */
/*   otrng_client_state_private_key_v4_write_FILEp(state, privf); */
/* } */

/* int otrng_user_state_private_key_v4_write_FILEp(const otrng_userstate_s
 * *state, */
/*                                                FILE *privf) { */
/*   if (!privf) */
/*     return -1; */

/*   otrng_list_foreach(state->states, add_private_key_v4_to_FILEp, privf); */
/*   return 0; */
/* } */

API int otrng_user_state_private_key_v4_read_FILEp(
    otrng_userstate_s *state, FILE *privf,
    const void *(*read_client_id_for_key)(FILE *filep)) {
  if (!privf)
    return 1;

  while (!feof(privf)) {
    const void *client_id = read_client_id_for_key(privf);
    if (!client_id)
      continue;

    if (otrng_client_state_private_key_v4_read_FILEp(
            get_client_state(state, client_id), privf))
      continue;
  }

  return 0;
}

/* int otrng_user_state_add_instance_tag(otrng_userstate_s *state, void
 * *client_id, */
/*                                      unsigned int instag) { */
/*   return otrng_client_state_add_instance_tag(get_client_state(state,
 * client_id), */
/*                                             instag); */
/* } */

/* unsigned int otrng_user_state_get_instance_tag(otrng_userstate_s *state, */
/*                                               void *client_id) { */
/*   UNUSED_ARG(state); */
/*   UNUSED_ARG(client_id); */
/*   // TODO */
/*   return 0; */
/* } */

/* int otrng_user_state_instance_tags_read_FILEp(otrng_userstate_s *state, */
/*                                              FILE *instag) { */
/*   // We use v3 userstate also for v4 instance tags, for now. */
/*   return otrl_instag_read_FILEp(state->userstate_v3, instag); */
/* } */
