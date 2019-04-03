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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "base64.h"
#include "client.h"
#include "deserialize.h"
#include "prekey_client_dake.h"
#include "prekey_client_shared.h"
#include "prekey_fragment.h"
#include "prekey_manager.h"
#include "prekey_proofs.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"

/*
  In this module the rule is that we verify the presence and non-nullity of
  needed things inside the API functions, in the beginning. None of the
  static helper functions will verify these invariants, so they should
  be checked first.

  In general, the API functions should specify their invariants using splint
  annotations, and also test them dynamically using 'assert'.
*/

#define PREKEY_HASH_DOMAIN "OTR-Prekey-Server"

#define USAGE_SK 0x01
#define USAGE_INITIATOR_CLIENT_PROFILE 0x02
#define USAGE_INITIATOR_PREKEY_COMPOSITE_IDENTITY 0x03
#define USAGE_INITIATOR_PREKEY_COMPOSITE_PHI 0x04
#define USAGE_RECEIVER_CLIENT_PROFILE 0x05
#define USAGE_RECEIVER_PREKEY_COMPOSITE_IDENTITY 0x06
#define USAGE_RECEIVER_PREKEY_COMPOSITE_PHI 0x07
#define USAGE_PREMAC_KEY 0x08
#define USAGE_PRE_MAC 0x09
#define USAGE_SUCCESS_MAC 0x0C
#define USAGE_FAILURE_MAC 0x0D
#define USAGE_PREKEY_MESSAGE 0x0E
#define USAGE_CLIENT_PROFILE 0x0F
#define USAGE_PREKEY_PROFILE 0x10
#define USAGE_AUTH 0x11
#define USAGE_PROOF_CONTEXT 0x12
#define USAGE_PROOF_MESSAGE_ECDH 0x13
#define USAGE_PROOF_MESSAGE_DH 0x14
#define USAGE_PROOF_SHARED_ECDH 0x15
#define USAGE_MAC_PROOFS 0x16

/*
  This function calls the prekey server shake 256 and will kill the program
  if a failure happens. The reason for this is that the only thing that can go
  wrong is actually that the update functions are called after the hash has
  finished. This should not be possible in how we use them, and is a sign of a
  catastrophic programming error. Thus, it should be safe to exit completely on
  this failure.
 */
static void do_hash_x(uint8_t *dst, size_t dst_len, uint8_t usage,
                      const uint8_t *values, size_t values_len) {
  if (otrng_failed(shake_256_prekey_server_kdf(dst, dst_len, usage, values,
                                               values_len))) {
    fprintf(stderr, "fatal: hash failure, this shouldn't happen - usage %d.\n",
            usage);
    exit(EXIT_FAILURE);
  }
}

static void hash_update_x(goldilocks_shake256_ctx_p hash, const uint8_t *buf,
                          const size_t len) {
  if (hash_update(hash, buf, len) == GOLDILOCKS_FAILURE) {
    fprintf(stderr, "fatal: hash failure, this shouldn't happen\n");
    exit(EXIT_FAILURE);
  }
}

static void hash_update_single_x(goldilocks_shake256_ctx_p hash,
                                 const uint8_t val) {
  hash_update_x(hash, &val, 1);
}

static void kdf_init_with_usage_x(goldilocks_shake256_ctx_p hash,
                                  uint8_t usage) {
  if (!hash_init_with_usage_and_domain_separation(hash, usage,
                                                  PREKEY_HASH_DOMAIN)) {
    fprintf(stderr,
            "fatal: hash failure, this shouldn't happen, init with usage: %d\n",
            usage);
    exit(EXIT_FAILURE);
  }
}

/*
  The returned value is NOT owned by the caller.
 */
static const char *get_domain_for_account(otrng_client_s *client, void *ctx) {
  assert(client->prekey_manager != NULL);
  return client->prekey_manager->callbacks->domain_for_account(client, ctx);
}

/*
  This function will try to look up the prekey server for a specific domain.
  It returns NULL if no such server exists in the list. It will NOT call any
  callbacks or anything to supply this information. Instead, it's assumed that a
  function such as otrng_prekey_provide_server_identity_for have been called
  before entering this function.
 */
static /*@null@*/ otrng_prekey_server_s *
get_prekey_server_for(/*@notnull@*/ otrng_prekey_manager_s *manager,
                      const char *domain) {
  otrng_prekey_server_s *server = NULL;
  list_element_s *current = manager->server_identities;

  for (; current; current = current->next) {
    server = current->data;
    if (strcmp(domain, server->domain) == 0) {
      return server;
    }
  }

  return NULL;
}

static /*@null@*/ otrng_prekey_request_s *
create_prekey_request(otrng_prekey_server_s *server, void *ctx) {
  uint8_t *sym = otrng_secure_alloc(ED448_PRIVATE_BYTES);
  otrng_prekey_request_s *result =
      otrng_xmalloc_z(sizeof(otrng_prekey_request_s));

  random_bytes(sym, ED448_PRIVATE_BYTES);

  result->server = server;
  result->ctx = ctx;

  result->ephemeral_ecdh = otrng_secure_alloc(sizeof(ecdh_keypair_s));
  if (!otrng_ecdh_keypair_generate(result->ephemeral_ecdh, sym)) {
    otrng_secure_free(sym);
    return NULL;
  }

  otrng_secure_free(sym);

  return result;
}

static otrng_result
create_dake1(/*@notnull@*/ otrng_client_s *client,
             /*@notnull@*/ otrng_prekey_request_s *request,
             /*@notnull@*/ otrng_prekey_dake1_message_s *dake1) {
  dake1->client_instance_tag = otrng_client_get_instance_tag(client);
  dake1->client_profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));

  if (!otrng_client_profile_copy(dake1->client_profile,
                                 client->client_profile)) {
    return OTRNG_ERROR;
  }

  otrng_ec_point_copy(dake1->I, request->ephemeral_ecdh->pub);
  return OTRNG_SUCCESS;
}

static void clean_ephemeral_ecdh(otrng_prekey_request_s *request) {
  if (request->ephemeral_ecdh != NULL) {
    otrng_ecdh_keypair_destroy(request->ephemeral_ecdh);
    otrng_secure_free(request->ephemeral_ecdh);
    request->ephemeral_ecdh = NULL;
  }
}

static void prekey_request_free(/*@notnull@*/ otrng_prekey_request_s *request) {
  if (!request) {
    return;
  }

  clean_ephemeral_ecdh(request);
  otrng_free(request);
}

static char *prekey_message_encode(const uint8_t *buffer, size_t buff_len) {
  char *ret = otrng_xmalloc_z(OTRNG_BASE64_ENCODE_LEN(buff_len) + 2);
  size_t l;

  l = otrl_base64_encode(ret, buffer, buff_len);
  ret[l] = '.';
  ret[l + 1] = '\0';

  return ret;
}

static otrng_result prekey_message_decode(const char *msg, uint8_t **buffer,
                                          size_t *buff_len) {
  size_t len = strlen(msg);

  if (!msg || !len || '.' != msg[len - 1]) {
    return OTRNG_ERROR;
  }

  /* (((base64len+3) / 4) * 3) */
  *buffer = otrng_xmalloc_z(((len - 1 + 3) / 4) * 3);
  *buff_len = otrl_base64_decode(*buffer, msg, len - 1);

  return OTRNG_SUCCESS;
}

/*
   The returned value will be owned by the caller
*/
static char *
serialize_dake1(/*@notnull@*/ otrng_prekey_dake1_message_s *dake1) {
  uint8_t *ser = NULL;
  size_t ser_len = 0;
  char *result;

  if (otrng_failed(
          otrng_prekey_dake1_message_serialize(&ser, &ser_len, dake1))) {
    return NULL;
  }

  result = prekey_message_encode(ser, ser_len);
  otrng_free(ser);
  return result;
}

static otrng_result prekey_manager_register_account_request(
    /*@notnull@*/ otrng_prekey_manager_s *manager,
    /*@notnull@*/ otrng_prekey_request_s *request) {
  if (manager->request_for_account != NULL) {
    return OTRNG_ERROR;
  }

  manager->request_for_account = request;
  return OTRNG_SUCCESS;
}

static otrng_result start_dake1(
    /*@notnull@*/ char **new_msg,
    /*@notnull@*/ otrng_client_s *client,
    /*@null@*/ void *ctx,
    /*@notnull@*/ otrng_prekey_next_message after_dake) {
  const char *domain;
  otrng_prekey_server_s *server;
  otrng_prekey_request_s *request;
  otrng_prekey_dake1_message_s dake1;

  /* We verify the static assertions dynamically as well */
  assert(client);
  assert(client->prekey_manager);
  assert(new_msg);

  domain = get_domain_for_account(client, ctx);
  server = get_prekey_server_for(client->prekey_manager, domain);
  if (!server) {
    return OTRNG_ERROR;
  }

  request = create_prekey_request(server, ctx);
  if (!request) {
    return OTRNG_ERROR;
  }

  if (otrng_failed(create_dake1(client, request, &dake1))) {
    prekey_request_free(request);
    return OTRNG_ERROR;
  }

  *new_msg = serialize_dake1(&dake1);
  if (!*new_msg) {
    prekey_request_free(request);
    otrng_prekey_dake1_message_destroy(&dake1);
    return OTRNG_ERROR;
  }
  otrng_prekey_dake1_message_destroy(&dake1);

  if (otrng_failed(prekey_manager_register_account_request(
          client->prekey_manager, request))) {
    prekey_request_free(request);
    otrng_free(*new_msg);
    return OTRNG_ERROR;
  }

  request->after_dake = after_dake;

  return OTRNG_SUCCESS;
}

#define OTRNG_DAKE3_MSG_LEN 67

static void dake3_message_append_storage_information_request(
    otrng_prekey_dake3_message_s *dake_3, uint8_t mac_key[MAC_KEY_BYTES]) {
  uint8_t msg_type = OTRNG_PREKEY_STORAGE_INFO_REQ_MSG;
  size_t w = 0;
  goldilocks_shake256_ctx_p hd;

  dake_3->msg = otrng_xmalloc_z(2 + 1 + MAC_KEY_BYTES);
  dake_3->msg_len = OTRNG_DAKE3_MSG_LEN;

  w += otrng_serialize_uint16(dake_3->msg, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(dake_3->msg + w, msg_type);

  /* MAC: KDF(usage_storage_info_MAC, prekey_mac_k || msg type, 64) */
  kdf_init_with_usage_x(hd, USAGE_RECEIVER_CLIENT_PROFILE);
  hash_update_x(hd, mac_key, MAC_KEY_BYTES);
  hash_update_x(hd, &msg_type, 1);
  hash_final(hd, dake_3->msg + w, HASH_BYTES);
  hash_destroy(hd);
}

static otrng_result storage_request_after_dake(
    /*@notnull@*/ otrng_client_s *client,
    /*@notnull@*/ otrng_prekey_request_s *request,
    /*@notnull@*/ otrng_prekey_dake3_message_s *dake_3) {
  (void)client;

  dake3_message_append_storage_information_request(dake_3, request->mac_key);

  return OTRNG_SUCCESS;
}

API otrng_result otrng_prekey_request_storage_information(
    /*@notnull@*/ char **new_msg,
    /*@notnull@*/ otrng_client_s *client,
    /*@null@*/ void *ctx) {
  return start_dake1(new_msg, client, ctx, storage_request_after_dake);
}

API otrng_bool
otrng_prekey_ensure_manager(/*@notnull@*/ struct otrng_client_s *client,
                            /*@notnull@*/ const char *identity) {
  if (client->prekey_manager != NULL) {
    return otrng_false;
  }

  client->prekey_manager = otrng_xmalloc_z(sizeof(otrng_prekey_manager_s));

  client->prekey_manager->our_identity = otrng_xstrdup(identity);
  client->prekey_manager->client = client;
  client->prekey_manager->publication_policy =
      otrng_xmalloc_z(sizeof(otrng_prekey_publication_policy_s));
  client->prekey_manager->callbacks =
      otrng_xmalloc_z(sizeof(otrng_prekey_callbacks_s));

  return otrng_true;
}

/*
   This assumes the server + domain does NOT exists in the list yet. It won't
   check for presence. This function does NOT take ownership of the domain,
   identity or pub elements
*/
API void otrng_prekey_provide_server_identity_for(
    /*@notnull@*/ otrng_client_s *client,
    /*@notnull@*/ const char *domain,
    /*@notnull@*/ const char *identity,
    /*@notnull@*/ const otrng_fingerprint fpr) {
  otrng_prekey_server_s *server =
      otrng_xmalloc_z(sizeof(otrng_prekey_server_s));

  assert(client->prekey_manager != NULL);

  server->domain = otrng_xstrdup(domain);
  server->identity = otrng_xstrdup(identity);
  memcpy(server->fpr, fpr, FPRINT_LEN_BYTES);

  client->prekey_manager->server_identities =
      otrng_list_add(server, client->prekey_manager->server_identities);
}

static void notify_error(otrng_client_s *client, int error, void *ctx) {
  const otrng_prekey_manager_s *manager = client->prekey_manager;
  assert(manager != NULL);
  manager->callbacks->notify_error(client, error, ctx);
}

static uint8_t *
get_expected_composite_phi(const otrng_prekey_manager_s *manager,
                           const otrng_prekey_request_s *request, size_t *len) {
  uint8_t *dst = NULL;
  size_t size, w = 0;

  size =
      4 + strlen(request->server->identity) + 4 + strlen(manager->our_identity);
  dst = otrng_xmalloc(size);

  w += otrng_serialize_data(dst + w, (const uint8_t *)manager->our_identity,
                            strlen(manager->our_identity));
  w += otrng_serialize_data(dst + w, (const uint8_t *)request->server->identity,
                            strlen(request->server->identity));

  if (len) {
    *len = size;
  }

  return dst;
}

/* Assumes buf contains enough size for the client profile hash. Returns size
 * written */
static size_t kdf_client_profile_into(uint8_t *buf,
                                      const otrng_client_profile_s *cp,
                                      const uint8_t usage) {
  uint8_t *ser = NULL;
  size_t ser_len = 0;

  /* We ignore the result, since this can't actually fail */
  (void)otrng_client_profile_serialize(&ser, &ser_len, cp);
  do_hash_x(buf, HASH_BYTES, usage, ser, ser_len);
  otrng_free(ser);

  return HASH_BYTES;
}

static size_t
kdf_composite_identity_into(uint8_t *buf,
                            const otrng_prekey_dake2_message_s *msg,
                            const uint8_t usage) {
  do_hash_x(buf, HASH_BYTES, usage, msg->composite_identity,
            msg->composite_identity_len);
  return HASH_BYTES;
}

static size_t kdf_composite_phi_into(uint8_t *buf,
                                     const otrng_prekey_manager_s *manager,
                                     const otrng_prekey_request_s *request,
                                     const uint8_t usage) {
  size_t composite_phi_len = 0;
  uint8_t *composite_phi =
      get_expected_composite_phi(manager, request, &composite_phi_len);

  do_hash_x(buf, HASH_BYTES, usage, composite_phi, composite_phi_len);
  otrng_free(composite_phi);
  return HASH_BYTES;
}

#define T_LEN 1 + 3 * HASH_BYTES + 2 * ED448_POINT_BYTES

static otrng_bool validate_dake2(otrng_client_s *client,
                                 otrng_prekey_request_s *request,
                                 const otrng_prekey_dake2_message_s *msg) {
  /*
     The spec says:
     "Ensure the identity element of the Prekey Server Composite Identity is
     correct." We make this check implicitly by verifying the ring signature
     (which contains this value as part of its "composite identity".
  */

  /*
    t = 0x00 || KDF(usage_Initiator_Client_Profile, Alices_Client_Profile, 64)
      || KDF(usage_initiator_prekey_composite_identity,
             Prekey_Server_Composite_Identity, 64) || I || S ||
         KDF(usage_initiator_prekey_composite_PHI, phi, 64)
  */

  uint8_t *t = otrng_xmalloc_z(T_LEN);
  size_t w = 0;
  otrng_bool ret;
  t[w++] = 0x00;

  w += kdf_client_profile_into(t + w, client->client_profile,
                               USAGE_INITIATOR_CLIENT_PROFILE);
  w += kdf_composite_identity_into(t + w, msg,
                                   USAGE_INITIATOR_PREKEY_COMPOSITE_IDENTITY);
  w += otrng_serialize_ec_point(t + w, request->ephemeral_ecdh->pub);
  w += otrng_serialize_ec_point(t + w, msg->S);
  w += kdf_composite_phi_into(t + w, client->prekey_manager, request,
                              USAGE_INITIATOR_PREKEY_COMPOSITE_PHI);

  ret = otrng_rsig_verify_with_usage_and_domain(
      USAGE_AUTH, PREKEY_HASH_DOMAIN, msg->sigma, client->keypair->pub,
      msg->server_pub_key, request->ephemeral_ecdh->pub, t, T_LEN);
  otrng_free(t);

  return ret;
}

static otrng_result create_mac_keys(otrng_prekey_request_s *request,
                                    const otrng_prekey_dake2_message_s *msg) {
  uint8_t *ecdh_shared = NULL, *shared_secret = NULL;

  ecdh_shared = otrng_secure_alloc(ED448_POINT_BYTES);

  /* ECDH(i, S) */
  if (otrng_failed(otrng_ecdh_shared_secret(ecdh_shared, ED448_POINT_BYTES,
                                            request->ephemeral_ecdh->priv,
                                            msg->S))) {
    clean_ephemeral_ecdh(request);
    otrng_secure_free(ecdh_shared);
    return OTRNG_ERROR;
  }
  clean_ephemeral_ecdh(request);

  shared_secret = otrng_secure_alloc(HASH_BYTES);

  /* SK = KDF(0x01, ECDH(i, S), 64) */
  do_hash_x(shared_secret, HASH_BYTES, USAGE_SK, ecdh_shared,
            ED448_POINT_BYTES);
  otrng_secure_free(ecdh_shared);

  /* prekey_mac_k = KDF(0x08, SK, 64) */
  do_hash_x(request->mac_key, MAC_KEY_BYTES, USAGE_PREMAC_KEY, shared_secret,
            HASH_BYTES);

  /* mac for proofs = KDF(0x12, SK, 64) */
  do_hash_x(request->mac_proof_key, HASH_BYTES, USAGE_PROOF_CONTEXT,
            shared_secret, HASH_BYTES);

  otrng_secure_free(shared_secret);

  return OTRNG_SUCCESS;
}

static otrng_result
create_rsig_auth_for_dake3(otrng_client_s *client,
                           otrng_prekey_request_s *request,
                           const otrng_prekey_dake2_message_s *msg,
                           otrng_prekey_dake3_message_s *dake_3) {
  uint8_t *t = otrng_xmalloc_z(T_LEN);
  size_t w = 0;
  otrng_result ret;

  t[w++] = 0x01;
  w += kdf_client_profile_into(t + w, client->client_profile,
                               USAGE_RECEIVER_CLIENT_PROFILE);
  w += kdf_composite_identity_into(t + w, msg,
                                   USAGE_RECEIVER_PREKEY_COMPOSITE_IDENTITY);
  w += otrng_serialize_ec_point(t + w, request->ephemeral_ecdh->pub);
  w += otrng_serialize_ec_point(t + w, msg->S);
  w += kdf_composite_phi_into(t + w, client->prekey_manager, request,
                              USAGE_RECEIVER_PREKEY_COMPOSITE_PHI);

  assert(w == T_LEN);

  ret = otrng_rsig_authenticate_with_usage_and_domain(
      USAGE_AUTH, PREKEY_HASH_DOMAIN, dake_3->sigma, client->keypair->priv,
      client->keypair->pub, client->keypair->pub, msg->server_pub_key, msg->S,
      t, T_LEN);
  otrng_free(t);
  return ret;
}

static char *send_dake3(otrng_client_s *client, otrng_prekey_request_s *request,
                        const otrng_prekey_dake2_message_s *msg) {
  /*
    t = 0x01 || KDF(usage_receiver_client_profile, Alices_Client_Profile, 64) ||
        KDF(usage_receiver_prekey_composite_identity,
            Prekey_Server_Composite_Identity, 64) || I || S ||
        KDF(usage_receiver_prekey_composite_PHI, phi, 64)
  */
  uint8_t *ser = NULL;
  size_t ser_len = 0;
  otrng_prekey_dake3_message_s dake_3;
  char *ret = NULL;

  dake_3.sigma = NULL;
  otrng_prekey_dake3_message_init(&dake_3);
  dake_3.client_instance_tag = otrng_client_get_instance_tag(client);

  if (otrng_failed(create_rsig_auth_for_dake3(client, request, msg, &dake_3))) {
    return NULL;
  }

  if (otrng_failed(create_mac_keys(request, msg))) {
    return NULL;
  }

  if (otrng_failed(request->after_dake(client, request, &dake_3))) {
    return NULL;
  }

  otrng_prekey_dake3_message_serialize(&ser, &ser_len, &dake_3);
  otrng_prekey_dake3_message_destroy(&dake_3);

  ret = prekey_message_encode(ser, ser_len);
  otrng_free(ser);

  return ret;
}

static char *process_received_dake2(otrng_client_s *client,
                                    otrng_prekey_request_s *request,
                                    const otrng_prekey_dake2_message_s *msg) {
  if (msg->client_instance_tag != otrng_client_get_instance_tag(client)) {
    return NULL;
  }

  if (!validate_dake2(client, request, msg)) {
    notify_error(client, OTRNG_PREKEY_CLIENT_INVALID_DAKE2, request->ctx);
    return NULL;
  }

  return send_dake3(client, request, msg);
}

static void clean_request_for_account(otrng_client_s *client) {
  if (client->prekey_manager->request_for_account != NULL) {
    prekey_request_free(client->prekey_manager->request_for_account);
    client->prekey_manager->request_for_account = NULL;
  }
}

static char *receive_dake2(otrng_client_s *client,
                           otrng_prekey_request_s *request,
                           const uint8_t *decoded, size_t decoded_len) {
  otrng_prekey_dake2_message_s msg;
  char *ret = NULL;

  otrng_prekey_dake2_message_init(&msg);
  if (!otrng_prekey_dake2_message_deserialize(&msg, decoded, decoded_len)) {
    notify_error(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG, request->ctx);
    return NULL;
  }

  ret = process_received_dake2(client, request, &msg);
  otrng_prekey_dake2_message_destroy(&msg);

  return ret;
}

static char *receive_success_or_failure(
    otrng_client_s *client, otrng_prekey_request_s *request,
    const uint8_t *decoded, size_t decoded_len, const size_t len,
    const uint8_t usage, const uint8_t error_code,
    void (*callback)(struct otrng_client_s *client, void *ctx)) {
  uint32_t instance_tag = 0;
  size_t read = 0;
  uint8_t *mac_tag;
  goldilocks_shake256_ctx_p hash;

  /* Since we check the length here, we don't need to check the later
   * deserializations */
  if (decoded_len < len) {
    notify_error(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG, request->ctx);
    return NULL;
  }

  (void)otrng_deserialize_uint32(&instance_tag, decoded + 3, decoded_len - 3,
                                 &read);

  if (instance_tag != otrng_client_get_instance_tag(client)) {
    return NULL;
  }

  kdf_init_with_usage_x(hash, usage);
  hash_update_x(hash, request->mac_key, MAC_KEY_BYTES);
  hash_update_x(hash, decoded + 2, 5);

  mac_tag = otrng_xmalloc_z(HASH_BYTES * sizeof(uint8_t));
  hash_final(hash, mac_tag, HASH_BYTES);
  hash_destroy(hash);

  if (sodium_memcmp(mac_tag, decoded + 7, HASH_BYTES) != 0) {
    notify_error(client, error_code, request->ctx);
  } else {
    callback(client, request->ctx);
  }

  otrng_free(mac_tag);
  return NULL;
}

static char *receive_success(otrng_client_s *client,
                             otrng_prekey_request_s *request,
                             const uint8_t *decoded, size_t decoded_len) {
  assert(client->prekey_manager != NULL);
  return receive_success_or_failure(
      client, request, decoded, decoded_len, OTRNG_PREKEY_SUCCESS_MSG_LEN,
      USAGE_SUCCESS_MAC, OTRNG_PREKEY_CLIENT_INVALID_SUCCESS,
      client->prekey_manager->callbacks->success_received);
}

static char *receive_failure(otrng_client_s *client,
                             otrng_prekey_request_s *request,
                             const uint8_t *decoded, size_t decoded_len) {
  assert(client->prekey_manager != NULL);
  return receive_success_or_failure(
      client, request, decoded, decoded_len, OTRNG_PREKEY_FAILURE_MSG_LEN,
      USAGE_FAILURE_MAC, OTRNG_PREKEY_CLIENT_INVALID_FAILURE,
      client->prekey_manager->callbacks->failure_received);
}

static char *process_received_storage_status(
    otrng_client_s *client, const otrng_prekey_request_s *request,
    const otrng_prekey_storage_status_message_s *msg) {
  assert(client->prekey_manager != NULL);

  if (msg->client_instance_tag != otrng_client_get_instance_tag(client)) {
    return NULL;
  }

  if (!otrng_prekey_storage_status_message_valid(msg, request->mac_key)) {
    notify_error(client, OTRNG_PREKEY_CLIENT_INVALID_STORAGE_STATUS,
                 request->ctx);
    return NULL;
  }

  if (msg->stored_prekeys < client->prekey_manager->publication_policy
                                ->minimum_stored_prekey_message) {
    client->prekey_msgs_num_to_publish =
        client->prekey_manager->publication_policy
            ->max_published_prekey_message -
        msg->stored_prekeys;
    client->prekey_manager->callbacks->low_prekey_messages_in_storage(
        client, request->ctx);
  }

  client->prekey_manager->callbacks->storage_status_received(client, msg,
                                                             request->ctx);
  return NULL;
}

static char *receive_storage_status(otrng_client_s *client,
                                    otrng_prekey_request_s *request,
                                    const uint8_t *decoded,
                                    size_t decoded_len) {
  otrng_prekey_storage_status_message_s msg;
  char *ret;

  if (!otrng_prekey_storage_status_message_deserialize(&msg, decoded,
                                                       decoded_len)) {
    notify_error(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG, request->ctx);
    return NULL;
  }

  ret = process_received_storage_status(client, request, &msg);
  otrng_prekey_storage_status_message_destroy(&msg);
  return ret;
}

static char *receive_no_prekey_in_storage(otrng_client_s *client,
                                          const uint8_t *decoded,
                                          const size_t decoded_len) {
  uint32_t instance_tag = 0;
  size_t read = 0;
  uint8_t *identity_ser = NULL;
  size_t identity_len = 0;
  char *identity = NULL;

  assert(client->prekey_manager != NULL);

  if (!otrng_deserialize_uint32(&instance_tag, decoded + 3, decoded_len - 3,
                                &read)) {
    notify_error(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG, NULL);
    return NULL;
  }

  if (instance_tag != otrng_client_get_instance_tag(client)) {
    return NULL;
  }

  if (!otrng_deserialize_data(&identity_ser, &identity_len, decoded + 7,
                              decoded_len - 7, &read)) {
    return NULL;
  }

  identity = otrng_xmalloc_z((identity_len + 1) * sizeof(uint8_t));
  memcpy(identity, identity_ser, identity_len);
  otrng_free(identity_ser);

  client->prekey_manager->callbacks->no_prekey_in_storage_received(client,
                                                                   identity);
  otrng_free(identity);

  return NULL;
}

static otrng_result process_received_prekey_ensemble_retrieval(
    otrng_client_s *client, otrng_prekey_ensemble_retrieval_message_s *msg) {
  int i;

  assert(client->prekey_manager != NULL);

  if (msg->instance_tag != otrng_client_get_instance_tag(client)) {
    return OTRNG_ERROR;
  }

  for (i = 0; i < msg->num_ensembles; i++) {
    if (!otrng_prekey_ensemble_validate(msg->ensembles[i])) {
      otrng_prekey_ensemble_destroy(msg->ensembles[i]);
      msg->ensembles[i] = NULL;
      msg->num_ensembles = msg->num_ensembles - 1;
    }
  }

  if (msg->num_ensembles == 0) {
    return OTRNG_ERROR;
  }

  client->prekey_manager->callbacks->prekey_ensembles_received(
      client, msg->ensembles, msg->num_ensembles, msg->identity);
  return OTRNG_SUCCESS;
}

static char *receive_prekey_ensemble_retrieval(otrng_client_s *client,
                                               const uint8_t *decoded,
                                               const size_t decoded_len) {
  otrng_prekey_ensemble_retrieval_message_s msg;

  if (!otrng_prekey_ensemble_retrieval_message_deserialize(&msg, decoded,
                                                           decoded_len)) {
    notify_error(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG, NULL);
    otrng_prekey_ensemble_retrieval_message_destroy(&msg);
    return NULL;
  }

  if (!process_received_prekey_ensemble_retrieval(client, &msg)) {
    notify_error(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG, NULL);
    otrng_prekey_ensemble_retrieval_message_destroy(&msg);
    return NULL;
  }

  otrng_prekey_ensemble_retrieval_message_destroy(&msg);
  return NULL;
}

static otrng_prekey_request_s *
check_current_dake_request(const otrng_client_s *client, const char *from) {
  otrng_prekey_request_s *rfa;

  assert(client->prekey_manager != NULL);

  rfa = client->prekey_manager->request_for_account;

  if (rfa == NULL) {
    return NULL;
  }

  if (strcmp(rfa->server->identity, from) == 0) {
    return rfa;
  }

  return NULL;
}

static char *receive_decoded_message(otrng_client_s *client,
                                     const uint8_t *decoded,
                                     const size_t decoded_len,
                                     /*@notnull@*/ const char *from) {
  uint8_t msg_type = 0;
  otrng_prekey_request_s *request = NULL;
  char *res;

  if (!otrng_prekey_parse_header(&msg_type, decoded, decoded_len, NULL)) {
    notify_error(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG, NULL);
    return NULL;
  }

  request = check_current_dake_request(client, from);

  switch (msg_type) {
  case OTRNG_PREKEY_DAKE2_MSG:
    if (!request) {
      notify_error(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG, NULL);
      return NULL;
    }
    res = receive_dake2(client, request, decoded, decoded_len);
    if (res == NULL) {
      clean_request_for_account(client);
    }
    return res;
  case OTRNG_PREKEY_SUCCESS_MSG:
    if (!request) {
      notify_error(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG, NULL);
      return NULL;
    }
    res = receive_success(client, request, decoded, decoded_len);
    clean_request_for_account(client);
    return res;
  case OTRNG_PREKEY_FAILURE_MSG:
    if (!request) {
      notify_error(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG, NULL);
      return NULL;
    }
    res = receive_failure(client, request, decoded, decoded_len);
    clean_request_for_account(client);
    return res;
  case OTRNG_PREKEY_STORAGE_STATUS_MSG:
    if (!request) {
      notify_error(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG, NULL);
      return NULL;
    }
    res = receive_storage_status(client, request, decoded, decoded_len);
    clean_request_for_account(client);
    return res;
  case OTRNG_PREKEY_NO_PREKEY_IN_STORAGE_MSG:
    return receive_no_prekey_in_storage(client, decoded, decoded_len);
  case OTRNG_PREKEY_ENSEMBLE_RETRIEVAL_MSG:
    return receive_prekey_ensemble_retrieval(client, decoded, decoded_len);
  default:
    notify_error(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG, request->ctx);
  }

  return NULL;
}

tstatic otrng_prekey_server_s *
find_server_for_identity(/*@notnull@*/ otrng_prekey_manager_s *manager,
                         const char *identity) {
  otrng_prekey_server_s *server = NULL;
  list_element_s *current = manager->server_identities;

  for (; current; current = current->next) {
    server = current->data;
    if (strcmp(identity, server->identity) == 0) {
      return server;
    }
  }

  return NULL;
}

/*
  If no prekey manager exists, or this message is from a sender
  that doesn't map to an active prekey conversation, this function
  returns false - that means someone else needs to handle the message.
*/
API otrng_bool otrng_prekey_receive(/*@notnull@*/ char **to_send,
                                    /*@notnull@*/ otrng_client_s *client,
                                    /*@notnull@*/ const char *from,
                                    /*@notnull@*/ const char *msg) {
  char *defrag = NULL;
  uint8_t *ser = NULL;
  size_t ser_len = 0;

  assert(to_send);
  assert(client);
  assert(from);
  assert(msg);

  if (client->prekey_manager == NULL) {
    return otrng_false;
  }

  /* If the message is not from one of our known prekey servers, it can't
     be a prekey message */
  if (find_server_for_identity(client->prekey_manager, from) == NULL) {
    return otrng_false;
  }

  if (otrng_failed(otrng_fragment_message_receive(
          &defrag, &client->prekey_manager->pending_fragments, msg,
          otrng_client_get_instance_tag(client)))) {
    return otrng_false;
  }

  /* If it fails to decode it was not a prekey server message. */
  if (!prekey_message_decode(defrag, &ser, &ser_len)) {
    otrng_free(defrag);
    return otrng_false;
  }
  otrng_free(defrag);

  *to_send = receive_decoded_message(client, ser, ser_len, from);
  otrng_free(ser);

  return otrng_true;
}

API void otrng_prekey_retrieve_prekeys(/*@notnull@*/ char **new_msg,
                                       /*@notnull@*/ otrng_client_s *client,
                                       /*@notnull@*/ const char *identity_for,
                                       /*@notnull@*/ const char *versions) {
  otrng_prekey_ensemble_query_retrieval_message_s msg;
  uint8_t *ser = NULL;
  size_t ser_len = 0;

  assert(new_msg);
  assert(client);
  assert(identity_for);
  assert(versions);
  assert(client->prekey_manager);

  msg.identity = otrng_xstrdup(identity_for);
  msg.versions = otrng_xstrdup(versions);
  msg.instance_tag = otrng_client_get_instance_tag(client);

  otrng_prekey_ensemble_query_retrieval_message_serialize(&ser, &ser_len, &msg);
  otrng_prekey_ensemble_query_retrieval_message_destroy(&msg);

  *new_msg = prekey_message_encode(ser, ser_len);
  otrng_free(ser);
}

API otrng_bool otrng_prekey_has_server_identity_for(
    /*@notnull@*/ const otrng_client_s *client,
    /*@notnull@*/ const char *domain) {
  assert(client);
  assert(domain);
  assert(client->prekey_manager);

  if (get_prekey_server_for(client->prekey_manager, domain) == NULL) {
    return otrng_false;
  }

  return otrng_true;
}

API /*@null@*/ otrng_prekey_server_s *otrng_prekey_get_server_identity_for(
    /*@notnull@*/ const struct otrng_client_s *client,
    /*@notnull@*/ const char *domain) {
  assert(client);
  assert(domain);
  assert(client->prekey_manager);

  return get_prekey_server_for(client->prekey_manager, domain);
}

static void serialize_cp_and_pp(otrng_prekey_publication_message_s *pub_msg,
                                uint8_t **cp_ser, size_t *cp_len,
                                uint8_t **pp_ser, size_t *pp_len) {
  if (pub_msg->client_profile) {
    (void)otrng_client_profile_serialize(cp_ser, cp_len,
                                         pub_msg->client_profile);
  }

  if (pub_msg->prekey_profile) {
    (void)otrng_prekey_profile_serialize(pp_ser, pp_len,
                                         pub_msg->prekey_profile);
  }
}

static size_t
calculate_proof_buf_len(const otrng_prekey_publication_message_s *pub_msg) {
  size_t result = 0;

  if (pub_msg->prekey_profile) {
    result += PROOF_C_SIZE + ED448_SCALAR_BYTES;
  }

  if (pub_msg->num_prekey_messages > 0) {
    result += PROOF_C_SIZE + ED448_SCALAR_BYTES;
    result += PROOF_C_SIZE + DH_MPI_MAX_BYTES;
  }

  return result;
}

static size_t
calculate_total_message_size(const otrng_prekey_publication_message_s *pub_msg,
                             size_t cp_len, size_t pp_len) {
  return 2 + 1 + 1 + (4 + pub_msg->num_prekey_messages * PRE_KEY_MAX_BYTES) +
         1 + cp_len + 1 + pp_len + calculate_proof_buf_len(pub_msg) +
         MAC_KEY_BYTES;
}

static size_t
serialize_prekey_messages_into(uint8_t *msg, size_t size, size_t num,
                               prekey_message_s **prekey_messages) {
  int i;
  size_t w = 0;

  for (i = 0; i < (int)num; i++) {
    size_t w_out = 0;
    /* It's safe to ignore the return value - it can never fail for us */
    (void)otrng_prekey_message_serialize(msg + w, size - w, &w_out,
                                         prekey_messages[i]);
    w += w_out;
  }

  return w;
}

static otrng_result
generate_proofs_for_prekey_messages(ecdh_proof_s *prekey_message_proof_ecdh,
                                    dh_proof_s *prekey_message_proof_dh,
                                    otrng_prekey_publication_message_s *pub_msg,
                                    uint8_t mac[HASH_BYTES]) {
  ec_scalar *values_priv_ecdh;
  ec_point *values_pub_ecdh;
  dh_mpi *values_priv_dh;
  dh_mpi *values_pub_dh;
  int i;
  otrng_result res;

  if (pub_msg->num_prekey_messages == 0) {
    return OTRNG_SUCCESS;
  }

  values_priv_ecdh =
      otrng_secure_alloc_array(pub_msg->num_prekey_messages, sizeof(ec_scalar));
  values_pub_ecdh =
      otrng_xmalloc_z(pub_msg->num_prekey_messages * sizeof(ec_point));

  values_priv_dh =
      otrng_secure_alloc_array(pub_msg->num_prekey_messages, sizeof(dh_mpi));
  values_pub_dh =
      otrng_xmalloc_z(pub_msg->num_prekey_messages * sizeof(dh_mpi));

  for (i = 0; i < pub_msg->num_prekey_messages; i++) {
    *values_pub_ecdh[i] = *pub_msg->prekey_messages[i]->y->pub;
    *values_priv_ecdh[i] = *pub_msg->prekey_messages[i]->y->priv;
    values_pub_dh[i] = pub_msg->prekey_messages[i]->b->pub;
    values_priv_dh[i] = pub_msg->prekey_messages[i]->b->priv;
  }

  res = otrng_ecdh_proof_generate(
      prekey_message_proof_ecdh, (const ec_scalar *)values_priv_ecdh,
      (const ec_point *)values_pub_ecdh, pub_msg->num_prekey_messages, mac,
      USAGE_PROOF_MESSAGE_ECDH);
  if (!otrng_failed(res)) {
    res = otrng_dh_proof_generate(prekey_message_proof_dh, values_priv_dh,
                                  values_pub_dh, pub_msg->num_prekey_messages,
                                  mac, USAGE_PROOF_MESSAGE_DH, NULL);
  }

  otrng_secure_free(values_priv_ecdh);
  otrng_free(values_pub_ecdh);
  otrng_secure_free(values_priv_dh);
  otrng_free(values_pub_dh);

  return res;
}

static otrng_result
generate_proof_for_prekey_profile(ecdh_proof_s *prekey_profile_proof,
                                  otrng_prekey_publication_message_s *pub_msg,
                                  uint8_t mac[HASH_BYTES]) {
  ec_scalar *values_priv_ecdh;
  ec_point *values_pub_ecdh;
  otrng_result res;

  if (pub_msg->prekey_profile == NULL) {
    return OTRNG_SUCCESS;
  }

  values_priv_ecdh = otrng_secure_alloc_array(1, sizeof(ec_scalar));
  values_pub_ecdh = otrng_xmalloc_z(1 * sizeof(ec_point));

  *values_pub_ecdh[0] = *pub_msg->prekey_profile->keys->pub;
  *values_priv_ecdh[0] = *pub_msg->prekey_profile->keys->priv;

  res = otrng_ecdh_proof_generate(
      prekey_profile_proof, (const ec_scalar *)values_priv_ecdh,
      (const ec_point *)values_pub_ecdh, 1, mac, USAGE_PROOF_SHARED_ECDH);

  otrng_secure_free(values_priv_ecdh);
  otrng_free(values_pub_ecdh);

  return res;
}

static otrng_result generate_proof_data_for_message(
    otrng_prekey_publication_message_s *pub_msg, uint8_t mac[HASH_BYTES],
    uint8_t **proofs, size_t *proof_index, uint8_t **prekey_proofs_kdf) {
  ecdh_proof_s prekey_message_proof_ecdh;
  dh_proof_s prekey_message_proof_dh;
  ecdh_proof_s prekey_profile_proof;

  *proof_index = 0;

  if (otrng_failed(generate_proofs_for_prekey_messages(
          &prekey_message_proof_ecdh, &prekey_message_proof_dh, pub_msg,
          mac))) {
    return OTRNG_ERROR;
  }

  if (otrng_failed(generate_proof_for_prekey_profile(&prekey_profile_proof,
                                                     pub_msg, mac))) {
    return OTRNG_ERROR;
  }

  *proofs = otrng_xmalloc_z(calculate_proof_buf_len(pub_msg) * sizeof(uint8_t));

  if (pub_msg->num_prekey_messages > 0) {
    *proof_index += otrng_ecdh_proof_serialize(*proofs + *proof_index,
                                               &prekey_message_proof_ecdh);
    *proof_index += otrng_dh_proof_serialize(*proofs + *proof_index,
                                             &prekey_message_proof_dh);
  }

  if (pub_msg->prekey_profile != NULL) {
    *proof_index += otrng_ecdh_proof_serialize(*proofs + *proof_index,
                                               &prekey_profile_proof);
  }

  *prekey_proofs_kdf = otrng_xmalloc_z(HASH_BYTES * sizeof(uint8_t));
  do_hash_x(*prekey_proofs_kdf, HASH_BYTES, USAGE_MAC_PROOFS, *proofs,
            *proof_index);

  return OTRNG_SUCCESS;
}

static void hash_client_profile_for_publication_message(
    goldilocks_shake256_ctx_p hd, otrng_prekey_publication_message_s *pub_msg,
    uint8_t *cp_ser, size_t cp_len) {
  if (pub_msg->client_profile) {
    uint8_t client_profile_kdf[HASH_BYTES];
    memset(client_profile_kdf, 0, HASH_BYTES);

    do_hash_x(client_profile_kdf, HASH_BYTES, USAGE_CLIENT_PROFILE, cp_ser,
              cp_len);
    hash_update_single_x(hd, 1);
    hash_update_x(hd, client_profile_kdf, HASH_BYTES);
  } else {
    hash_update_single_x(hd, 0);
  }
}

static void hash_prekey_profile_for_publication_message(
    goldilocks_shake256_ctx_p hd, otrng_prekey_publication_message_s *pub_msg,
    uint8_t *pp_ser, size_t pp_len) {
  if (pub_msg->prekey_profile) {
    uint8_t prekey_profile_kdf[HASH_BYTES];
    memset(prekey_profile_kdf, 0, HASH_BYTES);

    do_hash_x(prekey_profile_kdf, HASH_BYTES, USAGE_PREKEY_PROFILE, pp_ser,
              pp_len);
    hash_update_single_x(hd, 1);
    hash_update_x(hd, prekey_profile_kdf, HASH_BYTES);
  } else {
    hash_update_single_x(hd, 0);
  }
}

static otrng_result dake3_message_append_prekey_publication_message(
    otrng_prekey_publication_message_s *pub_msg,
    otrng_prekey_dake3_message_s *dake_3, uint8_t mac_key[MAC_KEY_BYTES],
    uint8_t mac[HASH_BYTES]) {
  size_t w = 0;
  uint8_t *cp_ser = NULL, *pp_ser = NULL, *proofs = NULL;
  size_t cp_len = 0, pp_len = 0, msg_size = 0, proof_index = 0;
  uint8_t *prekey_proofs_kdf = NULL, *prekey_messages_kdf = NULL;
  goldilocks_shake256_ctx_p hd;

  const uint8_t *prekey_messages_beginning;

  (void)mac_key;

  if (otrng_failed(generate_proof_data_for_message(
          pub_msg, mac, &proofs, &proof_index, &prekey_proofs_kdf))) {
    return OTRNG_ERROR;
  }

  serialize_cp_and_pp(pub_msg, &cp_ser, &cp_len, &pp_ser, &pp_len);

  msg_size = calculate_total_message_size(pub_msg, cp_len, pp_len);
  dake_3->msg = otrng_xmalloc_z(msg_size);

  w += otrng_serialize_uint16(dake_3->msg, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(dake_3->msg + w, OTRNG_PREKEY_PUBLICATION_MSG);
  w += otrng_serialize_uint8(dake_3->msg + w, pub_msg->num_prekey_messages);

  prekey_messages_beginning = dake_3->msg + w;
  w += serialize_prekey_messages_into(dake_3->msg + w, msg_size - w,
                                      pub_msg->num_prekey_messages,
                                      pub_msg->prekey_messages);

  prekey_messages_kdf = otrng_xmalloc_z(HASH_BYTES * sizeof(uint8_t));
  do_hash_x(prekey_messages_kdf, HASH_BYTES, USAGE_PREKEY_MESSAGE,
            prekey_messages_beginning,
            dake_3->msg + w - prekey_messages_beginning);

  w += otrng_serialize_uint8(dake_3->msg + w, pub_msg->client_profile ? 1 : 0);
  w += otrng_serialize_bytes_array(dake_3->msg + w, cp_ser, cp_len);

  w += otrng_serialize_uint8(dake_3->msg + w, pub_msg->prekey_profile ? 1 : 0);
  w += otrng_serialize_bytes_array(dake_3->msg + w, pp_ser, pp_len);
  w += otrng_serialize_bytes_array(dake_3->msg + w, proofs, proof_index);

  otrng_free(proofs);

  /* MAC: KDF(usage_preMAC, prekey_mac_k || message type
            || N || KDF(usage_prekey_message, Prekey Messages, 64)
            || K || KDF(usage_client_profile, Client Profile, 64)
            || J || KDF(usage_prekey_profile, Prekey Profile, 64)
            || KDF(usage_mac_proofs, Proofs, 64),
        64) */

  kdf_init_with_usage_x(hd, USAGE_PRE_MAC);
  hash_update_x(hd, mac_key, MAC_KEY_BYTES);
  hash_update_single_x(hd, OTRNG_PREKEY_PUBLICATION_MSG);
  hash_update_single_x(hd, pub_msg->num_prekey_messages);
  hash_update_x(hd, prekey_messages_kdf, HASH_BYTES);

  hash_client_profile_for_publication_message(hd, pub_msg, cp_ser, cp_len);
  otrng_free(cp_ser);

  hash_prekey_profile_for_publication_message(hd, pub_msg, pp_ser, pp_len);
  otrng_free(pp_ser);

  hash_update_x(hd, prekey_proofs_kdf, HASH_BYTES);

  hash_final(hd, dake_3->msg + w, HASH_BYTES);
  hash_destroy(hd);

  dake_3->msg_len = w + HASH_BYTES;

  return OTRNG_SUCCESS;
}

static otrng_result publication_after_dake(
    /*@notnull@*/ otrng_client_s *client,
    /*@notnull@*/ otrng_prekey_request_s *request,
    /*@notnull@*/ otrng_prekey_dake3_message_s *dake_3) {
  otrng_prekey_publication_message_s *pub_msg =
      otrng_prekey_publication_message_new();
  const otrng_prekey_manager_s *manager = client->prekey_manager;
  otrng_result res;

  assert(manager != NULL);

  if (!manager->callbacks->build_prekey_publication_message(client, pub_msg,
                                                            request->ctx)) {
    return OTRNG_ERROR;
  }

  res = dake3_message_append_prekey_publication_message(
      pub_msg, dake_3, request->mac_key, request->mac_proof_key);
  otrng_prekey_publication_message_destroy(pub_msg);
  return res;
}

API otrng_result otrng_prekey_publish(/*@notnull@*/ char **new_msg,
                                      /*@notnull@*/ otrng_client_s *client,
                                      /*@null@*/ void *ctx) {
  return start_dake1(new_msg, client, ctx, publication_after_dake);
}

API void otrng_prekey_add_prekey_messages_for_publication(
    /*@notnull@*/ otrng_client_s *client,
    /*@notnull@*/ otrng_prekey_publication_message_s *msg) {
  const size_t max = otrng_list_len(client->our_prekeys);
  size_t real = 0;
  prekey_message_s **msg_list = otrng_xmalloc(max * sizeof(prekey_message_s *));
  list_element_s *current = client->our_prekeys;

  assert(client);
  assert(msg);

  for (; current; current = current->next) {
    prekey_message_s *pm = current->data;
    if (pm->should_publish && !pm->is_publishing) {
      msg_list[real] = otrng_prekey_message_create_copy(pm);
      pm->is_publishing = otrng_true;
      real++;
    }
  }

  assert(real <= max);

  if (real != 0) {
    // Since we are shrinking the array, there is no way this can fail, so no
    // need to check the result
    msg->prekey_messages = realloc(msg_list, real * sizeof(prekey_message_s *));
  }
  msg->num_prekey_messages = real;
}

API void otrng_prekey_set_client_profile_publication(otrng_client_s *client) {
  assert(client->prekey_manager != NULL);
  client->prekey_manager->publication_policy->publish_client_profile =
      otrng_true;
}

API void otrng_prekey_set_prekey_profile_publication(otrng_client_s *client) {
  assert(client->prekey_manager != NULL);
  client->prekey_manager->publication_policy->publish_prekey_profile =
      otrng_true;
}

static void otrng_prekey_server_free(otrng_prekey_server_s *server) {
  if (server == NULL) {
    return;
  }

  otrng_free(server->domain);
  otrng_free(server->identity);

  otrng_free(server);
}

static void free_fragment_context(void *p) { otrng_fragment_context_free(p); }
static void free_server_identity(void *p) { otrng_prekey_server_free(p); }

INTERNAL void otrng_prekey_manager_free(otrng_prekey_manager_s *manager) {
  if (manager == NULL) {
    return;
  }

  otrng_free(manager->our_identity);
  otrng_free(manager->publication_policy);
  otrng_free(manager->callbacks);

  otrng_list_free(manager->pending_fragments, free_fragment_context);
  otrng_list_free(manager->server_identities, free_server_identity);
  if (manager->request_for_account != NULL) {
    prekey_request_free(manager->request_for_account);
  }

  otrng_free(manager);
}
