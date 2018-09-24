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

#ifndef S_SPLINT_S
#include <libotr/privkey.h>
#endif

#define OTRNG_MESSAGING_PRIVATE
#define OTRNG_PERSISTENCE_PRIVATE

#include "alloc.h"
#include "messaging.h"

#include "persistence.h"

API otrng_global_state_s *
otrng_global_state_new(const otrng_client_callbacks_s *cb) {
  otrng_global_state_s *gs = otrng_xmalloc(sizeof(otrng_global_state_s));

  gs->clients = NULL;
  gs->callbacks = cb;
  gs->user_state_v3 = otrl_userstate_create();

  return gs;
}

tstatic void free_client(void *data) { otrng_client_free(data); }

API void otrng_global_state_free(otrng_global_state_s *gs) {
  if (!gs) {
    return;
  }

  otrng_list_free(gs->clients, free_client);
  otrl_userstate_free(gs->user_state_v3);

  free(gs);
}

tstatic int find_client_by_client_id(const void *current, const void *wanted) {
  const otrng_client_s *client = current;
  const otrng_client_id_s *cid = wanted;
  return strcmp(client->client_id.protocol, cid->protocol) == 0 &&
         strcmp(client->client_id.account, cid->account) == 0;
}

tstatic otrng_client_s *get_client(otrng_global_state_s *gs,
                                   const otrng_client_id_s client_id) {
  otrng_client_s *client;
  list_element_s *el =
      otrng_list_get(&client_id, gs->clients, find_client_by_client_id);
  if (el) {
    return el->data;
  }

  client = otrng_client_new(client_id);
  if (!client) {
    return NULL;
  }

  client->global_state = gs;
  gs->clients = otrng_list_add(client, gs->clients);

  return client;
}

otrng_client_s *otrng_client_get(otrng_global_state_s *gs,

                                 const otrng_client_id_s client_id) {
  list_element_s *el =
      otrng_list_get(&client_id, gs->clients, find_client_by_client_id);
  if (el) {
    return el->data;
  }
  return get_client(gs, client_id);
}

API otrng_result otrng_global_state_private_key_v3_generate_FILEp(
    otrng_global_state_s *gs, const otrng_client_id_s client_id, FILE *privf) {
  return otrng_client_private_key_v3_write_FILEp(get_client(gs, client_id),
                                                 privf);
}

API otrng_result otrng_global_state_private_key_v3_read_FILEp(
    otrng_global_state_s *gs, FILE *keys) {
  gcry_error_t res = otrl_privkey_read_FILEp(gs->user_state_v3, keys);
  if (res) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}

tstatic otrng_result otrng_global_state_add_private_key_v4(
    otrng_global_state_s *gs, const otrng_client_id_s clientop,
    const uint8_t sym[ED448_PRIVATE_BYTES]) {
  return otrng_client_add_private_key_v4(get_client(gs, clientop), sym);
}

tstatic otrng_result otrng_global_state_add_forging_key(
    otrng_global_state_s *gs, const otrng_client_id_s clientop,
    otrng_public_key_p *fk) {
  return otrng_client_add_forging_key(get_client(gs, clientop), *fk);
}

API otrng_result otrng_global_state_generate_private_key(
    otrng_global_state_s *gs, const otrng_client_id_s client_id) {
  uint8_t sym[ED448_PRIVATE_BYTES];
  gcry_randomize(sym, ED448_PRIVATE_BYTES, GCRY_VERY_STRONG_RANDOM);
  return otrng_global_state_add_private_key_v4(gs, client_id, sym);
}

API otrng_result otrng_global_state_generate_forging_key(
    otrng_global_state_s *gs, const otrng_client_id_s client_id) {
  /* This function generates the forging key by
     generating a full keypair and then deleting the secret material
     A better way would be to just generate the public material directly */
  uint8_t sym[ED448_PRIVATE_BYTES];
  otrng_keypair_s *k;
  otrng_result r;

  gcry_randomize(sym, ED448_PRIVATE_BYTES, GCRY_VERY_STRONG_RANDOM);
  k = otrng_keypair_new();
  otrng_keypair_generate(k, sym);
  r = otrng_global_state_add_forging_key(gs, client_id, &k->pub);
  // At this point you can add printing of the secret key material
  // if you ever need to use the forging key.
  otrng_keypair_free(k);
  return r;
}

API otrng_result otrng_global_state_generate_client_profile(
    otrng_global_state_s *gs, const otrng_client_id_s client_id) {
  client_profile_s *profile;
  otrng_result err;
  otrng_client_s *client = get_client(gs, client_id);
  if (!client) {
    return OTRNG_ERROR;
  }

  profile = otrng_client_build_default_client_profile(client);
  if (!profile) {
    return OTRNG_ERROR;
  }

  err = otrng_client_add_client_profile(client, profile);
  otrng_client_profile_free(profile);

  return err;
}

API otrng_result otrng_global_state_generate_prekey_profile(
    otrng_global_state_s *gs, const otrng_client_id_s client_id) {
  otrng_client_s *client = get_client(gs, client_id);
  otrng_prekey_profile_s *profile;
  otrng_result err;

  if (!client) {
    return OTRNG_ERROR;
  }

  profile = otrng_client_build_default_prekey_profile(client);
  if (!profile) {
    return OTRNG_ERROR;
  }

  err = otrng_client_add_prekey_profile(client, profile);
  otrng_prekey_profile_free(profile);

  return err;
}

API otrng_result otrng_global_state_generate_shared_prekey(
    otrng_global_state_s *gs, const otrng_client_id_s client_id) {
  uint8_t sym[ED448_PRIVATE_BYTES];
  otrng_client_s *client;
  gcry_randomize(sym, ED448_PRIVATE_BYTES, GCRY_VERY_STRONG_RANDOM);

  client = get_client(gs, client_id);
  if (!client) {
    return OTRNG_ERROR;
  }

  return otrng_client_add_shared_prekey_v4(client, sym);
}

API otrng_keypair_s *
otrng_global_state_get_private_key_v4(otrng_global_state_s *gs,
                                      const otrng_client_id_s client_id) {
  return otrng_client_get_keypair_v4(get_client(gs, client_id));
}

tstatic void add_private_key_v4_to_FILEp(list_element_s *node, void *context) {
  otrng_client_s *client = node->data;
  // TODO: check the return value
  if (!otrng_client_private_key_v4_write_FILEp(client, context)) {
    return;
  }
}

API otrng_result otrng_global_state_private_key_v4_write_FILEp(
    const otrng_global_state_s *gs, FILE *privf) {
  if (!privf) {
    return OTRNG_ERROR;
  }

  otrng_list_foreach(gs->clients, add_private_key_v4_to_FILEp, privf);

  return OTRNG_SUCCESS;
}

tstatic void add_forging_key_to_FILEp(list_element_s *node, void *context) {
  otrng_client_s *client = node->data;
  // TODO: check the return value
  if (!otrng_client_forging_key_write_FILEp(client, context)) {
    return;
  }
}

API otrng_result otrng_global_state_forging_key_write_FILEp(
    const otrng_global_state_s *gs, FILE *f) {
  if (!f) {
    return OTRNG_ERROR;
  }

  otrng_list_foreach(gs->clients, add_forging_key_to_FILEp, f);

  return OTRNG_SUCCESS;
}

tstatic void add_shared_prekey_to_FILEp(list_element_s *node, void *context) {
  otrng_client_s *client = node->data;
  // TODO: check the return value
  if (!otrng_client_shared_prekey_write_FILEp(client, context)) {
    return;
  }
}

API otrng_result otrng_global_state_shared_prekey_write_FILEp(
    const otrng_global_state_s *gs, FILE *shared_prekey_f) {
  if (!shared_prekey_f) {
    return OTRNG_ERROR;
  }

  otrng_list_foreach(gs->clients, add_shared_prekey_to_FILEp, shared_prekey_f);

  return OTRNG_SUCCESS;
}

tstatic void add_client_profile_to_FILEp(list_element_s *node, void *context) {
  otrng_client_client_profile_write_FILEp(node->data, context);
}

API otrng_result otrng_global_state_client_profile_write_FILEp(
    const otrng_global_state_s *gs, FILE *privf) {
  if (!privf) {
    return OTRNG_ERROR;
  }

  otrng_list_foreach(gs->clients, add_client_profile_to_FILEp, privf);
  return OTRNG_SUCCESS;
}

tstatic void add_prekey_profile_to_FILEp(list_element_s *node, void *context) {
  // TODO: check error here
  otrng_client_prekey_profile_write_FILEp(node->data, context);
}

API otrng_result otrng_global_state_prekey_profile_write_FILEp(
    const otrng_global_state_s *gs, FILE *privf) {
  if (!privf) {
    return OTRNG_ERROR;
  }

  otrng_list_foreach(gs->clients, add_prekey_profile_to_FILEp, privf);
  return OTRNG_SUCCESS;
}

tstatic void add_prekey_messages_to_FILEp(list_element_s *node, void *context) {
  if (!otrng_client_prekeys_write_FILEp(node->data, context)) {
    return;
  }
}

API otrng_result otrng_global_state_prekey_messages_write_FILEp(
    const otrng_global_state_s *gs, FILE *privf) {
  if (!privf) {
    return OTRNG_ERROR;
  }

  otrng_list_foreach(gs->clients, add_prekey_messages_to_FILEp, privf);
  return OTRNG_SUCCESS;
}

API otrng_result otrng_global_state_private_key_v4_read_FILEp(
    otrng_global_state_s *gs, FILE *privf,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  if (!privf) {
    return OTRNG_ERROR;
  }

  /* Scan the whole file for a private key for this client */
  while (!feof(privf)) {
    otrng_client_s *client;
    const otrng_client_id_s client_id = read_client_id_for_key(privf);
    if (!client_id.protocol || !client_id.account) {
      continue;
    }

    client = get_client(gs, client_id);
    if (otrng_client_private_key_v4_read_FILEp(client, privf) !=
        OTRNG_SUCCESS) {
      return OTRNG_ERROR; /* We decide to abort, since this means the file is
                             malformed */
    }
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_global_state_forging_key_read_FILEp(
    otrng_global_state_s *gs, FILE *f,
    otrng_client_id_s (*read_client_id_for_key)(FILE *f)) {
  if (!f) {
    return OTRNG_ERROR;
  }

  // Scan the whole file for a private key for this client
  while (!feof(f)) {
    otrng_client_s *client;
    const otrng_client_id_s client_id = read_client_id_for_key(f);
    if (!client_id.protocol || !client_id.account) {
      continue;
    }

    client = get_client(gs, client_id);
    if (otrng_failed(otrng_client_forging_key_read_FILEp(client, f))) {
      return OTRNG_ERROR; /* We decide to abort, since this means the file is
                             malformed */
    }
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_global_state_client_profile_read_FILEp(
    otrng_global_state_s *gs, FILE *profile_filep,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  if (!profile_filep) {
    return OTRNG_ERROR;
  }

  while (!feof(profile_filep)) {
    otrng_client_s *client;
    const otrng_client_id_s client_id = read_client_id_for_key(profile_filep);
    if (!client_id.protocol || !client_id.account) {
      continue;
    }

    client = get_client(gs, client_id);
    if (otrng_client_client_profile_read_FILEp(client, profile_filep) !=
        OTRNG_SUCCESS) {
      return OTRNG_ERROR; /* We decide to abort, since this means the file is
                             malformed */
    }
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_global_state_expired_client_profile_read_FILEp(
    otrng_global_state_s *gs, FILE *exp_profile_filep,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  if (!exp_profile_filep) {
    return OTRNG_ERROR; // TODO: @refactoring maybe this should be success on
                        // every case
  }

  while (!feof(exp_profile_filep)) {
    otrng_client_s *client;
    const otrng_client_id_s client_id =
        read_client_id_for_key(exp_profile_filep);
    if (!client_id.protocol || !client_id.account) {
      continue;
    }

    client = get_client(gs, client_id);
    if (otrng_client_expired_client_profile_read_FILEp(
            client, exp_profile_filep) != OTRNG_SUCCESS) {
      return OTRNG_ERROR; /* We decide to abort, since this means the file is
                             malformed */
    }
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_global_state_shared_prekey_read_FILEp(
    otrng_global_state_s *gs, FILE *shared_prekeyf,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  if (!shared_prekeyf) {
    return OTRNG_ERROR;
  }

  // Scan the whole file for a private key for this client
  while (!feof(shared_prekeyf)) {
    otrng_client_s *client;
    const otrng_client_id_s client_id = read_client_id_for_key(shared_prekeyf);
    if (!client_id.protocol || !client_id.account) {
      continue;
    }

    client = get_client(gs, client_id);
    if (otrng_client_shared_prekey_read_FILEp(client, shared_prekeyf) !=
        OTRNG_SUCCESS) {
      return OTRNG_ERROR; /* We decide to abort, since this means the file is
                             malformed */
    }
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_global_state_prekey_profile_read_FILEp(
    otrng_global_state_s *gs, FILE *profile_filep,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  if (!profile_filep) {
    return OTRNG_ERROR;
  }

  while (!feof(profile_filep)) {
    otrng_client_s *client;
    const otrng_client_id_s client_id = read_client_id_for_key(profile_filep);
    if (!client_id.protocol || !client_id.account) {
      continue;
    }
    client = get_client(gs, client_id);
    if (otrng_client_prekey_profile_read_FILEp(client, profile_filep) !=
        OTRNG_SUCCESS) {
      return OTRNG_ERROR; /* We decide to abort, since this means the file is
                             malformed */
    }
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_global_state_expired_prekey_profile_read_FILEp(
    otrng_global_state_s *gs, FILE *exp_profile_filep,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  if (!exp_profile_filep) {
    return OTRNG_ERROR; // TODO: @refactoring maybe this should be success on
                        // every case
  }

  while (!feof(exp_profile_filep)) {
    otrng_client_s *client;
    const otrng_client_id_s client_id =
        read_client_id_for_key(exp_profile_filep);
    if (!client_id.protocol || !client_id.account) {
      continue;
    }

    client = get_client(gs, client_id);
    if (otrng_client_expired_prekey_profile_read_FILEp(
            client, exp_profile_filep) != OTRNG_SUCCESS) {
      return OTRNG_ERROR; /* We decide to abort, since this means the file is
                             malformed */
    }
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_global_state_prekeys_read_FILEp(
    otrng_global_state_s *gs, FILE *prekey_filep,
    otrng_client_id_s (*read_client_id_for_prekey)(FILE *filep)) {
  if (!prekey_filep) {
    return OTRNG_ERROR;
  }

  while (!feof(prekey_filep)) {
    otrng_client_s *client;
    const otrng_client_id_s client_id = read_client_id_for_prekey(prekey_filep);
    if (!client_id.protocol || !client_id.account) {
      continue;
    }

    client = get_client(gs, client_id);

    if (otrng_client_prekey_messages_read_FILEp(client, prekey_filep) !=
        OTRNG_SUCCESS) {
      return OTRNG_ERROR; /* We decide to abort, since this means the file is
                             malformed */
    }
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_global_state_add_instance_tag(
    otrng_global_state_s *gs, const otrng_client_id_s client_id,
    unsigned int instag) {
  return otrng_client_add_instance_tag(get_client(gs, client_id), instag);
}

API otrng_result otrng_global_state_instag_generate_generate_FILEp(
    otrng_global_state_s *gs, const otrng_client_id_s client_id, FILE *instag) {
  return otrng_client_instance_tag_write_FILEp(get_client(gs, client_id),
                                               instag);
}

API otrng_result otrng_global_state_instance_tags_read_FILEp(
    otrng_global_state_s *gs, FILE *instag) {
  // We use v3 global_state also for v4 instance tags, for now. */
  gcry_error_t res = otrl_instag_read_FILEp(gs->user_state_v3, instag);
  if (res) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}

#ifdef DEBUG_API

#include "debug.h"

static const char **debug_print_ignores = NULL;
static size_t debug_print_ignores_len;
static size_t debug_print_ignores_cap;

API void otrng_add_debug_print_ignore(const char *ign) {
  if (debug_print_ignores == NULL) {
    debug_print_ignores = otrng_xmalloc(7 * sizeof(char *));

    debug_print_ignores_len = 0;
    debug_print_ignores_cap = 7;
  }

  if (debug_print_ignores_len + 1 >= debug_print_ignores_cap) {
    debug_print_ignores_cap += 13;
    debug_print_ignores = otrng_xrealloc(
        debug_print_ignores, debug_print_ignores_cap * sizeof(char *));
  }

  debug_print_ignores[debug_print_ignores_len] = ign;
  debug_print_ignores_len++;
}

API void otrng_clear_debug_print_ignores() { debug_print_ignores_len = 0; }

API otrng_bool otrng_debug_print_should_ignore(const char *ign) {
  int ix;
  for (ix = 0; ix < debug_print_ignores_len; ix++) {
    if (strcmp(ign, debug_print_ignores[ix]) == 0) {
      return otrng_true;
    }
  }
  return otrng_false;
}

API void otrng_client_id_debug_print(FILE *f,
                                     const otrng_client_id_s client_id) {
  /* if (client_id_debug_printer) { */
  /*   client_id_debug_printer(f, client_id); */
  /* } else { */
  /*   otrng_debug_print_pointer(f, client_id); */
  /* } */
}

API void otrng_global_state_debug_print(FILE *f, int indent,
                                        otrng_global_state_s *gs) {
  int ix;
  list_element_s *curr;

  if (otrng_debug_print_should_ignore("global_state")) {
    return;
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "global_state(");
  otrng_debug_print_pointer(f, gs);
  debug_api_print(f, ") {\n");

  if (otrng_debug_print_should_ignore("global_state->clients")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "clients = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "clients = {\n");
    ix = 0;
    curr = gs->clients;
    while (curr) {
      otrng_print_indent(f, indent + 4);
      debug_api_print(f, "[%d] = {\n", ix);
      otrng_client_debug_print(f, indent + 6, curr->data);
      otrng_print_indent(f, indent + 4);
      debug_api_print(f, "} // [%d]\n", ix);
      curr = curr->next;
      ix++;
    }

    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "} // clients\n");
  }

  if (otrng_debug_print_should_ignore("global_state->callbacks")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "callbacks = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "callbacks = {\n");
    otrng_client_callbacks_debug_print(f, indent + 4, gs->callbacks);
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "} // callbacks\n");
  }

  if (otrng_debug_print_should_ignore("global_state->user_state_v3")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "user_state_v3 = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "user_state_v3 = ");
    otrng_debug_print_pointer(f, gs->user_state_v3);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "} // global_state\n");
}

#endif /* DEBUG_API */
