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
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <libotr/privkey.h>
#pragma clang diagnostic pop
#endif

#define OTRNG_MESSAGING_PRIVATE
#define OTRNG_PERSISTENCE_PRIVATE

#include "alloc.h"
#include "debug.h"
#include "messaging.h"
#include "persistence.h"
#include "prekey_manager.h"

API otrng_global_state_s *
otrng_global_state_new(const otrng_client_callbacks_s *cb, otrng_bool die) {
  otrng_global_state_s *gs = otrng_xmalloc_z(sizeof(otrng_global_state_s));
  if (!otrng_client_callbacks_ensure_needed_exist(cb)) {
    otrng_debug_fprintf(stderr,
                        "otrng global state initialization failed - expected "
                        "callbacks missing\n");
    if (die) {
      exit(EXIT_FAILURE);
    }
  }

  gs->callbacks = cb;
  gs->user_state_v3 = otrl_userstate_create();
  if (gs->user_state_v3 == NULL) {
    if (die) {
      exit(EXIT_FAILURE);
    }
  }

  return gs;
}

tstatic void free_client(void *data) { otrng_client_free(data); }

API void otrng_global_state_free(otrng_global_state_s *gs) {
  if (!gs) {
    return;
  }

  otrng_list_free(gs->clients, free_client);
  otrl_userstate_free(gs->user_state_v3);

  otrng_free(gs);
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

API otrng_client_s *otrng_client_get(otrng_global_state_s *gs,

                                     const otrng_client_id_s client_id) {
  list_element_s *el =
      otrng_list_get(&client_id, gs->clients, find_client_by_client_id);
  if (el) {
    return el->data;
  }
  return get_client(gs, client_id);
}

// TODO: unused function.
otrng_result
otrng_global_state_add_instance_tag(otrng_global_state_s *gs,
                                    const otrng_client_id_s client_id,
                                    unsigned int instag) {
  return otrng_client_add_instance_tag(get_client(gs, client_id), instag);
}

API otrng_result otrng_global_state_instag_generate_into(
    otrng_global_state_s *gs, const otrng_client_id_s client_id, FILE *instag) {
  return otrng_client_instance_tag_write_to(get_client(gs, client_id), instag);
}

tstatic otrng_result otrng_global_state_add_private_key_v4(
    otrng_global_state_s *gs, const otrng_client_id_s clientop,
    const uint8_t sym[ED448_PRIVATE_BYTES]) {
  return otrng_client_add_private_key_v4(get_client(gs, clientop), sym);
}

otrng_keypair_s *
otrng_global_state_get_private_key_v4(otrng_global_state_s *gs,
                                      const otrng_client_id_s client_id) {
  return otrng_client_get_keypair_v4(get_client(gs, client_id));
}

API otrng_result otrng_global_state_generate_private_key(
    otrng_global_state_s *gs, const otrng_client_id_s client_id) {
  otrng_result res;
  uint8_t *sym = otrng_secure_alloc(ED448_PRIVATE_BYTES);

  gcry_randomize(sym, ED448_PRIVATE_BYTES, GCRY_VERY_STRONG_RANDOM);
  res = otrng_global_state_add_private_key_v4(gs, client_id, sym);

  otrng_secure_free(sym);

  return res;
}

API otrng_result otrng_global_state_generate_private_key_v3(
    otrng_global_state_s *gs, const otrng_client_id_s client_id) {
  return otrng_v3_create_private_key(get_client(gs, client_id));
}

tstatic otrng_result otrng_global_state_add_forging_key(
    otrng_global_state_s *gs, const otrng_client_id_s clientop,
    otrng_public_key *fk) {
  return otrng_client_add_forging_key(get_client(gs, clientop), *fk);
}

API otrng_result otrng_global_state_generate_forging_key(
    otrng_global_state_s *gs, const otrng_client_id_s client_id) {
  /* This function generates the forging key by
     generating a full keypair and then deleting the secret material
     A better way would be to just generate the public material directly */
  uint8_t *sym = otrng_secure_alloc(ED448_PRIVATE_BYTES);
  otrng_keypair_s *key_pair;
  otrng_result res;

  gcry_randomize(sym, ED448_PRIVATE_BYTES, GCRY_VERY_STRONG_RANDOM);
  key_pair = otrng_keypair_new();

  if (!otrng_keypair_generate(key_pair, sym)) {
    otrng_secure_free(sym);
    otrng_keypair_free(key_pair);
    return OTRNG_ERROR;
  }

  res = otrng_global_state_add_forging_key(gs, client_id, &key_pair->pub);

  // At this point you can add printing of the secret key material
  // if you ever need to use the forging key.
  otrng_secure_free(sym);
  otrng_keypair_free(key_pair);

  return res;
}

API otrng_result otrng_global_state_generate_client_profile(
    otrng_global_state_s *gs, const otrng_client_id_s client_id) {
  otrng_client_profile_s *profile;
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
  otrng_prekey_profile_s *profile;
  otrng_result err;
  otrng_client_s *client = get_client(gs, client_id);
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

static void add_private_key_v4_to(list_element_s *node, void *context) {
  if (!otrng_client_private_key_v4_write_to(node->data, context)) {
    return;
  }
}

tstatic otrng_result global_state_write_to(const otrng_global_state_s *gs,
                                           FILE *f,
                                           void (*fn)(list_element_s *,
                                                      void *)) {
  if (!f) {
    return OTRNG_ERROR;
  }

  otrng_list_foreach(gs->clients, fn, f);

  return OTRNG_SUCCESS;
}

API otrng_result otrng_global_state_private_key_v4_write_to(
    const otrng_global_state_s *gs, FILE *privf) {
  return global_state_write_to(gs, privf, add_private_key_v4_to);
}

tstatic void add_forging_key_to(list_element_s *node, void *context) {
  if (!otrng_client_forging_key_write_to(node->data, context)) {
    return;
  }
}

API otrng_result otrng_global_state_forging_key_write_to(
    const otrng_global_state_s *gs, FILE *f) {
  return global_state_write_to(gs, f, add_forging_key_to);
}

tstatic void add_client_profile_to(list_element_s *node, void *context) {
  if (!otrng_client_client_profile_write_to(node->data, context)) {
    return;
  }
}

API otrng_result otrng_global_state_client_profile_write_to(
    const otrng_global_state_s *gs, FILE *f) {
  return global_state_write_to(gs, f, add_client_profile_to);
}

tstatic void add_expired_client_profile_to(list_element_s *node,
                                           void *context) {
  if (!otrng_client_expired_client_profile_write_to(node->data, context)) {
    return;
  }
}

API otrng_result otrng_global_state_expired_client_profile_write_to(
    const otrng_global_state_s *gs, FILE *f) {
  return global_state_write_to(gs, f, add_expired_client_profile_to);
}

tstatic void add_expired_prekey_profile_to(list_element_s *node,
                                           void *context) {
  if (!otrng_client_expired_prekey_profile_write_to(node->data, context)) {
    return;
  }
}

API otrng_result otrng_global_state_expired_prekey_profile_write_to(
    const otrng_global_state_s *gs, FILE *f) {
  return global_state_write_to(gs, f, add_expired_prekey_profile_to);
}

tstatic void add_prekey_profile_to(list_element_s *node, void *context) {
  if (!otrng_client_prekey_profile_write_to(node->data, context)) {
    return;
  }
}

API otrng_result otrng_global_state_prekey_profile_write_to(
    const otrng_global_state_s *gs, FILE *f) {
  return global_state_write_to(gs, f, add_prekey_profile_to);
}

tstatic void add_prekey_messages_to(list_element_s *node, void *context) {
  if (!otrng_client_prekeys_write_to(node->data, context)) {
    return;
  }
}

API otrng_result otrng_global_state_prekey_messages_write_to(
    const otrng_global_state_s *gs, FILE *f) {
  return global_state_write_to(gs, f, add_prekey_messages_to);
}

API otrng_result otrng_global_state_instance_tags_read_from(
    otrng_global_state_s *gs, FILE *instag) {
  /* We use v3 global_state also for v4 instance tags, for now. */
  gcry_error_t res = otrl_instag_read_FILEp(gs->user_state_v3, instag);
  if (res) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}

API otrng_result otrng_global_state_private_key_v3_read_from(
    otrng_global_state_s *gs, FILE *keys,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  gcry_error_t res = otrl_privkey_read_FILEp(gs->user_state_v3, keys);
  (void)read_client_id_for_key;
  if (res) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}

static void sexp_write(FILE *fp, gcry_sexp_t sexp) {
  size_t buflen;
  char *buf;

  buflen = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = otrng_xmalloc_z(buflen);
  gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, buf, buflen);
  fprintf(fp, "%s", buf);
  otrng_free(buf);
}

static gcry_error_t account_write(FILE *fp, const char *accountname,
                                  const char *protocol, gcry_sexp_t privkey) {
  gcry_error_t err;
  gcry_sexp_t names, protos;

  fprintf(fp, " (account\n");

  err = gcry_sexp_build(&names, NULL, "(name %s)", accountname);
  if (!err) {
    sexp_write(fp, names);
    gcry_sexp_release(names);
  }
  if (!err) {
    err = gcry_sexp_build(&protos, NULL, "(protocol %s)", protocol);
  }
  if (!err) {
    sexp_write(fp, protos);
    gcry_sexp_release(protos);
  }
  if (!err) {
    sexp_write(fp, privkey);
  }

  fprintf(fp, " )\n");

  return err;
}

API otrng_result otrng_global_state_private_key_v3_write_to(
    const otrng_global_state_s *gs, FILE *fp) {
  gcry_error_t ret;
  OtrlUserState us = gs->user_state_v3;
  OtrlPrivKey *p;

  fprintf(fp, "(privkeys\n");
  for (p = us->privkey_root; p; p = p->next) {
    ret = account_write(fp, p->accountname, p->protocol, p->privkey);
    if (ret) {
      return OTRNG_ERROR;
    }
  }
  fprintf(fp, ")\n");

  return OTRNG_SUCCESS;
}

tstatic otrng_result
global_state_read_from(otrng_global_state_s *gs, FILE *f,
                       otrng_client_id_s (*read_client_id_for_key)(FILE *),
                       otrng_result (*on_each_line)(otrng_client_s *, FILE *)) {
  otrng_client_s *last_client = NULL;
  const char *last_protocol = NULL;
  const char *last_account = NULL;

  if (!f) {
    return OTRNG_ERROR;
  }

  while (!feof(f)) {
    otrng_client_s *client;
    const otrng_client_id_s client_id = read_client_id_for_key(f);
    if (!client_id.protocol || !client_id.account) {
      continue;
    }

    if (last_protocol == client_id.protocol &&
        last_account == client_id.account) {
      client = last_client;
    } else {
      client = get_client(gs, client_id);
      last_protocol = client_id.protocol;
      last_account = client_id.account;
      last_client = client;
    }

    if (otrng_failed(on_each_line(client, f))) {
      return OTRNG_ERROR;
    }
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_global_state_private_key_v4_read_from(
    otrng_global_state_s *gs, FILE *f,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  return global_state_read_from(gs, f, read_client_id_for_key,
                                otrng_client_private_key_v4_read_from);
}

API otrng_result otrng_global_state_forging_key_read_from(
    otrng_global_state_s *gs, FILE *f,
    otrng_client_id_s (*read_client_id_for_key)(FILE *f)) {
  return global_state_read_from(gs, f, read_client_id_for_key,
                                otrng_client_forging_key_read_from);
}

API otrng_result otrng_global_state_client_profile_read_from(
    otrng_global_state_s *gs, FILE *f,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  return global_state_read_from(gs, f, read_client_id_for_key,
                                otrng_client_client_profile_read_from);
}

API otrng_result otrng_global_state_expired_client_profile_read_from(
    otrng_global_state_s *gs, FILE *f,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  return global_state_read_from(gs, f, read_client_id_for_key,
                                otrng_client_expired_client_profile_read_from);
}

API otrng_result otrng_global_state_prekey_profile_read_from(
    otrng_global_state_s *gs, FILE *f,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  return global_state_read_from(gs, f, read_client_id_for_key,
                                otrng_client_prekey_profile_read_from);
}

API otrng_result otrng_global_state_expired_prekey_profile_read_from(
    otrng_global_state_s *gs, FILE *f,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  return global_state_read_from(gs, f, read_client_id_for_key,
                                otrng_client_expired_prekey_profile_read_from);
}

tstatic void prekey_global_state_message_free_from_list(void *prekeys) {
  otrng_prekey_message_free(prekeys);
}

tstatic void free_prekeys_from(list_element_s *node, void *ignored) {
  otrng_client_s *client = node->data;
  (void)ignored;
  otrng_list_free(client->our_prekeys,
                  prekey_global_state_message_free_from_list);
  client->our_prekeys = NULL;
}

API otrng_result otrng_global_state_prekeys_read_from(
    otrng_global_state_s *gs, FILE *f,
    otrng_client_id_s (*read_client_id_for_line)(FILE *)) {
  otrng_list_foreach(gs->clients, free_prekeys_from, NULL);
  return global_state_read_from(gs, f, read_client_id_for_line,
                                otrng_client_prekey_messages_read_from);
}

API otrng_result otrng_global_state_fingerprints_v3_read_from(
    otrng_global_state_s *gs, FILE *f,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep)) {
  (void)read_client_id_for_key;
  otrl_privkey_read_fingerprints_FILEp(gs->user_state_v3, f, NULL, NULL);
  otrng_global_state_fingerprints_v3_loaded(gs);
  return OTRNG_SUCCESS;
}

tstatic void remove_fingerprints_from(list_element_s *node, void *ignored) {
  otrng_client_s *client = node->data;
  (void)ignored;
  if (client->fingerprints != NULL) {
    otrng_known_fingerprints_free(client->fingerprints);
    client->fingerprints = NULL;
  }
}

API void otrng_global_state_clean_all(otrng_global_state_s *gs) {
  otrng_list_foreach(gs->clients, remove_fingerprints_from, NULL);
}

tstatic void free_fingerprints_from(list_element_s *node, void *ignored) {
  otrng_client_s *client = node->data;
  (void)ignored;
  otrng_known_fingerprints_free(client->fingerprints);
  client->fingerprints = NULL;
}

API otrng_result otrng_global_state_fingerprints_v4_read_from(
    otrng_global_state_s *gs, FILE *f, otrng_client_id_s (*ignored)(FILE *)) {
  (void)ignored;

  otrng_list_foreach(gs->clients, free_fingerprints_from, NULL);

  if (!f) {
    return OTRNG_ERROR;
  }

  while (!feof(f)) {
    (void)otrng_client_fingerprint_v4_read_from(gs, f, get_client);
  }

  return OTRNG_SUCCESS;
}

static void add_fingerprints_v4_to(list_element_s *node, void *fp) {
  if (!otrng_client_fingerprints_v4_write_to(node->data, fp)) {
    return;
  }
}

API otrng_result otrng_global_state_fingerprints_v4_write_to(
    const otrng_global_state_s *gs, FILE *fp) {
  return global_state_write_to(gs, fp, add_fingerprints_v4_to);
}

API otrng_result otrng_global_state_fingerprints_v3_write_to(
    const otrng_global_state_s *gs, FILE *fp) {
  gcry_error_t err =
      otrl_privkey_write_fingerprints_FILEp(gs->user_state_v3, fp);

  if (err) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

typedef struct all_fingerprints_ctx {
  void (*fn)(const otrng_client_s *, otrng_known_fingerprint_s *, void *);
  void *context;
} all_fingerprints_ctx;

static void do_all_fingerprints(list_element_s *node, void *ctx) {
  all_fingerprints_ctx *fctx = ctx;
  otrng_fingerprints_do_all(node->data, fctx->fn, fctx->context);
}

API void otrng_global_state_do_all_fingerprints(
    const otrng_global_state_s *gs,
    void (*fn)(const otrng_client_s *, otrng_known_fingerprint_s *, void *),
    void *context) {
  all_fingerprints_ctx fctx = {
      .fn = fn,
      .context = context,
  };
  otrng_list_foreach(gs->clients, do_all_fingerprints, &fctx);
}

/* This function will actually not return ALL fingerprints.
   Instead, it will return all fingerprints where we can find a corresponding
   otrng_client_s instance Also, if you want keep the fingerprint from the
   callback, you need to create a copy of it!
*/
API void otrng_global_state_do_all_fingerprints_v3(
    const otrng_global_state_s *gs,
    void (*fn)(const otrng_client_s *, otrng_known_fingerprint_v3_s *, void *),
    void *context) {
  otrng_client_id_s cid;
  ConnContext *cc;
  Fingerprint *fprint;
  list_element_s *el;
  otrng_known_fingerprint_v3_s fp;

  for (cc = gs->user_state_v3->context_root; cc; cc = cc->next) {
    /* Fingerprints are only stored in the master contexts */
    if (cc->their_instance != OTRL_INSTAG_MASTER)
      continue;

    /* Don't bother with the first (fingerprintless) entry. */
    for (fprint = cc->fingerprint_root.next; fprint; fprint = fprint->next) {
      cid.protocol = cc->protocol;
      cid.account = cc->accountname;
      el = otrng_list_get(&cid, gs->clients, find_client_by_client_id);
      if (el) {
        fp.username = cc->username;
        fp.fp = fprint;
        fn(el->data, &fp, context);
      }
    }
  }
}

tstatic void poll_for_client(list_element_s *node, void *context) {
  otrng_client_s *client = node->data;
  (void)context;
  otrng_client_expire_sessions(client);
  (void)otrng_client_expire_fragments(client);
  otrng_prekey_check_account_request(client);
}

API void otrng_poll(otrng_global_state_s *gs) {
  otrng_list_foreach(gs->clients, poll_for_client, NULL);
  otrl_message_poll(gs->user_state_v3, NULL, NULL);
}

INTERNAL void
otrng_global_state_fingerprints_v3_loaded(otrng_global_state_s *gs) {
  gs->fingerprints_v3_loaded = otrng_true;
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
