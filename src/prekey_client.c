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

#include "prekey_client.h"

#include "alloc.h"
#include "base64.h"
#include "client.h"
#include "dake.h"
#include "deserialize.h"
#include "fingerprint.h"
#include "prekey_proofs.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"

#ifndef S_SPLINT_S
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <libotr/mem.h>
#pragma clang diagnostic pop
#endif

#define OTRNG_PREKEY_CLIENT_MALFORMED_MESSAGE 1
#define OTRNG_PREKEY_CLIENT_INVALID_DAKE2 2
#define OTRNG_PREKEY_CLIENT_INVALID_STORAGE_STATUS 3
#define OTRNG_PREKEY_CLIENT_INVALID_SUCCESS 4
#define OTRNG_PREKEY_CLIENT_INVALID_FAILURE 5

static void notify_error_callback(otrng_client_s *client, int error) {
  const otrng_prekey_client_s *prekey_client = client->prekey_client;
  prekey_client->callbacks->notify_error(client, error,
                                         prekey_client->callbacks->ctx);
}

static void prekey_storage_status_received_callback(
    otrng_client_s *client,
    const otrng_prekey_storage_status_message_s *message) {
  const otrng_prekey_client_s *prekey_client = client->prekey_client;
  prekey_client->callbacks->storage_status_received(
      client, message, prekey_client->callbacks->ctx);
}

static void success_received_callback(otrng_client_s *client) {
  const otrng_prekey_client_s *prekey_client = client->prekey_client;
  prekey_client->callbacks->success_received(client,
                                             prekey_client->callbacks->ctx);
}

static void failure_received_callback(otrng_client_s *client) {
  const otrng_prekey_client_s *prekey_client = client->prekey_client;
  prekey_client->callbacks->failure_received(client,
                                             prekey_client->callbacks->ctx);
}

static void no_prekey_in_storage_received_callback(otrng_client_s *client) {
  const otrng_prekey_client_s *prekey_client = client->prekey_client;
  prekey_client->callbacks->no_prekey_in_storage_received(
      client, prekey_client->callbacks->ctx);
}

static void low_prekey_messages_in_storage_callback(otrng_client_s *client) {
  const otrng_prekey_client_s *prekey_client = client->prekey_client;
  prekey_client->callbacks->low_prekey_messages_in_storage(
      client, prekey_client->server_identity, prekey_client->callbacks->ctx);
}

static void
prekey_ensembles_received_callback(otrng_client_s *client,
                                   prekey_ensemble_s *const *const ensembles,
                                   uint8_t num_ensembles) {
  const otrng_prekey_client_s *prekey_client = client->prekey_client;
  prekey_client->callbacks->prekey_ensembles_received(
      client, ensembles, num_ensembles, prekey_client->callbacks->ctx);
}

static int build_prekey_publication_message_callback(
    otrng_prekey_publication_message_s *pub_message, otrng_client_s *client) {
  const otrng_prekey_client_s *prekey_client = client->prekey_client;
  return prekey_client->callbacks->build_prekey_publication_message(
      client, pub_message, prekey_client->publication_policy,
      prekey_client->callbacks->ctx);
}

API otrng_prekey_client_s *otrng_prekey_client_new() {
  otrng_prekey_client_s *client =
      otrng_secure_alloc(sizeof(otrng_prekey_client_s));

  client->publication_policy =
      otrng_xmalloc_z(sizeof(otrng_prekey_publication_policy_s));

  client->ephemeral_ecdh = otrng_secure_alloc(sizeof(ecdh_keypair_s));

  return client;
}

API void otrng_prekey_client_init(otrng_prekey_client_s *client,
                                  const char *server, const char *our_identity,
                                  uint32_t instance_tag,
                                  const otrng_keypair_s *keypair,
                                  const otrng_client_profile_s *client_profile,
                                  const otrng_prekey_profile_s *prekey_profile,
                                  unsigned int max_published_prekey_message,
                                  unsigned int minimum_stored_prekey_message) {
  if (!client) {
    return;
  }

  if (!server) {
    return;
  }

  if (!our_identity) {
    return;
  }

  if (!instance_tag) {
    return;
  }

  if (!client_profile) {
    return;
  }

  client->instance_tag = instance_tag;
  client->client_profile = client_profile;

  // TODO: Can be null if you dont want to publish it
  client->server_identity = otrng_xstrdup(server);
  client->our_identity = otrng_xstrdup(our_identity);
  client->prekey_profile = prekey_profile;
  client->keypair = keypair;

  otrng_ecdh_keypair_destroy(client->ephemeral_ecdh);
  free(client->ephemeral_ecdh);
  client->ephemeral_ecdh = otrng_secure_alloc(sizeof(ecdh_keypair_s));
  client->publication_policy->max_published_prekey_message =
      max_published_prekey_message;
  client->publication_policy->minimum_stored_prekey_message =
      minimum_stored_prekey_message;
}

API void otrng_prekey_client_free(otrng_prekey_client_s *client) {
  if (!client) {
    return;
  }

  otrng_ecdh_keypair_destroy(client->ephemeral_ecdh);
  free(client->ephemeral_ecdh);
  free(client->server_identity);
  free(client->our_identity);
  free(client->publication_policy);

  otrng_secure_wipe(client, sizeof(otrng_prekey_client_s));

  free(client);
}

static otrng_result prekey_decode(const char *message, uint8_t **buffer,
                                  size_t *buffer_len) {
  size_t len = strlen(message);

  if (!len || '.' != message[len - 1]) {
    return OTRNG_ERROR;
  }

  /* (((base64len+3) / 4) * 3) */
  *buffer = otrng_xmalloc_z(((len - 1 + 3) / 4) * 3);

  *buffer_len = otrl_base64_decode(*buffer, message, len - 1);

  return OTRNG_SUCCESS;
}

static char *prekey_encode(const uint8_t *buffer, size_t buffer_len) {
  char *ret = otrng_xmalloc_z(OTRNG_BASE64_ENCODE_LEN(buffer_len) + 2);
  size_t l;

  l = otrl_base64_encode(ret, buffer, buffer_len);
  ret[l] = '.';
  ret[l + 1] = 0;

  return ret;
}

static char *start_dake_and_then_send(otrng_prekey_client_s *client,
                                      otrng_prekey_next_message_t next) {
  uint8_t *sym = otrng_secure_alloc(ED448_PRIVATE_BYTES);
  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
  otrng_result success;
  char *ret;
  otrng_prekey_dake1_message_s message;

  message.client_instance_tag = client->instance_tag;
  message.client_profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));
  otrng_client_profile_copy(message.client_profile, client->client_profile);

  random_bytes(sym, ED448_PRIVATE_BYTES);
  otrng_ecdh_keypair_generate(client->ephemeral_ecdh, sym);
  otrng_secure_wipe(sym, ED448_PRIVATE_BYTES);
  free(sym);
  otrng_ec_point_copy(message.I, client->ephemeral_ecdh->pub);

  success = otrng_prekey_dake1_message_serialize(&serialized, &serialized_len,
                                                 &message);
  otrng_prekey_dake1_message_destroy(&message);

  if (!success) {
    return NULL;
  }

  ret = prekey_encode(serialized, serialized_len);
  free(serialized);

  client->after_dake = next;

  return ret;
}

API char *
otrng_prekey_client_request_storage_information(otrng_prekey_client_s *client) {
  return start_dake_and_then_send(client,
                                  OTRNG_PREKEY_STORAGE_INFORMATION_REQUEST);
}

API char *otrng_prekey_client_publish(otrng_prekey_client_s *client) {
  return start_dake_and_then_send(client, OTRNG_PREKEY_PREKEY_PUBLICATION);
}

// What if we want to publish ONLY the profiles?
// API char *
// otrng_prekey_client_publish_profiles(otrng_prekey_client_s *client) {
//}

API char *otrng_prekey_client_retrieve_prekeys(const char *identity,
                                               const char *versions,
                                               otrng_prekey_client_s *client) {
  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
  otrng_result success;
  char *ret;

  otrng_prekey_ensemble_query_retrieval_message_s message[1];

  message->identity = otrng_xstrdup(identity);
  message->versions = versions ? otrng_xstrdup(versions) : NULL;
  message->instance_tag = client->instance_tag;

  success = otrng_prekey_ensemble_query_retrieval_message_serialize(
      &serialized, &serialized_len, message);

  otrng_prekey_ensemble_query_retrieval_message_destroy(message);

  if (!success) {
    return NULL;
  }

  ret = prekey_encode(serialized, serialized_len);
  free(serialized);
  return ret;
}

API void otrng_prekey_client_set_client_profile_publication(
    otrng_prekey_client_s *client) {
  client->publication_policy->publish_client_profile = otrng_true;
}

API void otrng_prekey_client_set_prekey_profile_publication(
    otrng_prekey_client_s *client) {
  client->publication_policy->publish_prekey_profile = otrng_true;
}

INTERNAL otrng_result otrng_prekey_ensemble_query_retrieval_message_serialize(
    uint8_t **destination, size_t *len,
    const otrng_prekey_ensemble_query_retrieval_message_s *message) {
  size_t w = 0;

  if (!len || !destination) {
    return OTRNG_ERROR;
  }

  *len = 2 + 1 + 4 + (4 + strlen(message->identity)) +
         (4 + otrng_strlen_ns(message->versions));
  *destination = otrng_xmalloc(*len);

  w += otrng_serialize_uint16(*destination, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(*destination + w,
                             OTRNG_PREKEY_ENSEMBLE_QUERY_RETRIEVAL_MESSAGE);
  w += otrng_serialize_uint32(*destination + w, message->instance_tag);
  w += otrng_serialize_data(*destination + w, (uint8_t *)message->identity,
                            strlen(message->identity));
  otrng_serialize_data(*destination + w, (uint8_t *)message->versions,
                       otrng_strlen_ns(message->versions));

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_prekey_ensemble_query_retrieval_message_destroy(
    otrng_prekey_ensemble_query_retrieval_message_s *message) {
  if (!message) {
    return;
  }

  free(message->identity);
  message->identity = NULL;

  free(message->versions);
  message->versions = NULL;
}

static uint8_t *otrng_prekey_client_get_expected_composite_phi(
    size_t *len, const otrng_prekey_client_s *client) {
  uint8_t *destination = NULL;
  size_t size, w = 0;

  if (!client->server_identity || !client->our_identity) {
    return NULL;
  }

  size = 4 + strlen(client->server_identity) + 4 + strlen(client->our_identity);
  destination = otrng_xmalloc(size);

  w += otrng_serialize_data(destination + w,
                            (const uint8_t *)client->our_identity,
                            strlen(client->our_identity));
  otrng_serialize_data(destination + w,
                       (const uint8_t *)client->server_identity,
                       strlen(client->server_identity));

  if (len) {
    *len = size;
  }

  return destination;
}

static uint8_t usage_auth = 0x11;
static const char *prekey_hash_domain = "OTR-Prekey-Server";

INTERNAL void kdf_init_with_usage(goldilocks_shake256_ctx_p hash,
                                  uint8_t usage) {
  hash_init_with_usage_and_domain_separation(hash, usage, prekey_hash_domain);
}

static otrng_bool
otrng_prekey_dake2_message_valid(const otrng_prekey_dake2_message_s *message,
                                 const otrng_prekey_client_s *client) {
  // The spec says:
  // "Ensure the identity element of the Prekey Server Composite Identity is
  // correct." We make this check implicitly by verifying the ring signature
  // (which contains this value as part of its "composite identity".

  // TODO: Check if the fingerprint from the key received in this message is
  // what we expect. Through a callback maybe, since the user may need to take
  // action.

  size_t composite_phi_len = 0;
  uint8_t *composite_phi = otrng_prekey_client_get_expected_composite_phi(
      &composite_phi_len, client);
  uint8_t *our_profile = NULL;
  size_t our_profile_len = 0;
  size_t tlen, w;
  uint8_t *t;
  uint8_t usage_initator_client_profile = 0x02;
  uint8_t usage_initiator_prekey_composite_identity = 0x03;
  uint8_t usage_initiator_prekey_composite_phi = 0x04;
  otrng_bool ret;

  if (!composite_phi) {
    return otrng_false;
  }

  if (!otrng_client_profile_serialize(&our_profile, &our_profile_len,
                                      client->client_profile)) {
    free(composite_phi);
    return otrng_false;
  }

  tlen = 1 + 3 * HASH_BYTES + 2 * ED448_POINT_BYTES;
  t = otrng_xmalloc_z(tlen);

  *t = 0x0;
  w = 1;

  shake_256_prekey_server_kdf(t + w, HASH_BYTES, usage_initator_client_profile,
                              our_profile, our_profile_len);
  free(our_profile);

  w += HASH_BYTES;

  /* Both composite identity AND composite phi have the server's bare JID */
  shake_256_prekey_server_kdf(
      t + w, HASH_BYTES, usage_initiator_prekey_composite_identity,
      message->composite_identity, message->composite_identity_len);

  w += HASH_BYTES;

  w += otrng_serialize_ec_point(t + w, client->ephemeral_ecdh->pub);
  w += otrng_serialize_ec_point(t + w, message->S);

  shake_256_prekey_server_kdf(t + w, HASH_BYTES,
                              usage_initiator_prekey_composite_phi,
                              composite_phi, composite_phi_len);
  free(composite_phi);

  ret = otrng_rsig_verify_with_usage_and_domain(
      usage_auth, prekey_hash_domain, message->sigma, client->keypair->pub,
      message->server_pub_key, client->ephemeral_ecdh->pub, t, tlen);
  free(t);

  return ret;
}

INTERNAL otrng_result
otrng_prekey_dake3_message_append_storage_information_request(
    otrng_prekey_dake3_message_s *message, uint8_t mac_key[MAC_KEY_BYTES]) {
  uint8_t message_type = OTRNG_PREKEY_STORAGE_INFO_REQ_MESSAGE;
  size_t w = 0;
  uint8_t usage_receiver_client_profile = 0x0A;
  goldilocks_shake256_ctx_p hmac;

  message->message = otrng_xmalloc_z(2 + 1 + MAC_KEY_BYTES);

  message->message_len = 67; // TODO: extract this

  w += otrng_serialize_uint16(message->message, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(message->message + w, message_type);

  /* MAC: KDF(usage_storage_info_MAC, prekey_mac_k || message type, 64) */

  kdf_init_with_usage(hmac, usage_receiver_client_profile);
  hash_update(hmac, mac_key, MAC_KEY_BYTES);
  hash_update(hmac, &message_type, 1);
  hash_final(hmac, message->message + w, HASH_BYTES);
  hash_destroy(hmac);

  return OTRNG_SUCCESS;
}

// TODO: make sure that the message buffer is large enough
INTERNAL otrng_result
otrng_prekey_dake3_message_append_prekey_publication_message(
    otrng_prekey_publication_message_s *pub_message,
    otrng_prekey_dake3_message_s *message, uint8_t mac_key[MAC_KEY_BYTES],
    uint8_t m[64]) {
  uint8_t *client_profile = NULL;
  size_t client_profile_len = 0;
  uint8_t *prekey_profile = NULL;
  uint8_t *proofs = NULL;
  size_t proof_buf_len = 0;
  size_t prekey_profile_len = 0;
  size_t size;
  uint8_t message_type = OTRNG_PREKEY_PUBLICATION_MESSAGE;
  size_t w = 0;
  const uint8_t *prekey_messages_beginning;
  uint8_t usage_prekey_message = 0x0E;
  uint8_t prekey_messages_kdf[HASH_BYTES];
  uint8_t prekey_proofs_kdf[HASH_BYTES];

  uint8_t usage_pre_MAC = 0x09;
  uint8_t usage_proof_message_ecdh = 0x13;
  uint8_t usage_proof_message_dh = 0x14;
  uint8_t usage_proof_shared_ecdh = 0x15;
  uint8_t usage_mac_proofs = 0x16;
  uint8_t one = 1, zero = 0;

  ec_scalar *values_priv_ecdh;
  ec_point *values_pub_ecdh;
  dh_mpi *values_priv_dh;
  dh_mpi *values_pub_dh;
  size_t proof_index = 0;

  ecdh_proof_s prekey_message_proof_ecdh;
  dh_proof_s prekey_message_proof_dh;
  ecdh_proof_s prekey_profile_proof;

  goldilocks_shake256_ctx_p hd;

  int i;

  memset(prekey_messages_kdf, 0, HASH_BYTES);
  memset(prekey_proofs_kdf, 0, HASH_BYTES);

  if (pub_message->client_profile) {
    if (!otrng_client_profile_serialize(&client_profile, &client_profile_len,
                                        pub_message->client_profile)) {
      return OTRNG_ERROR;
    }
  }

  if (pub_message->prekey_profile) {
    if (!otrng_prekey_profile_serialize(&prekey_profile, &prekey_profile_len,
                                        pub_message->prekey_profile)) {
      free(client_profile);
      return OTRNG_ERROR;
    }
  }

  if (pub_message->num_prekey_messages > 0) {
    proof_buf_len += PROOF_C_SIZE + ED448_SCALAR_BYTES;
    proof_buf_len += PROOF_C_SIZE + DH_MPI_MAX_BYTES;
  }
  if (pub_message->prekey_profile != NULL) {
    proof_buf_len += PROOF_C_SIZE + ED448_SCALAR_BYTES;
  }

  size = 2 + 1 + 1 +
         (4 + pub_message->num_prekey_messages * PRE_KEY_MAX_BYTES) + 1 +
         client_profile_len + 1 + prekey_profile_len + proof_buf_len +
         MAC_KEY_BYTES;
  message->message = otrng_xmalloc_z(size);

  w += otrng_serialize_uint16(message->message, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(message->message + w, message_type);

  w += otrng_serialize_uint8(message->message + w,
                             pub_message->num_prekey_messages);

  prekey_messages_beginning = message->message + w;
  for (i = 0; i < pub_message->num_prekey_messages; i++) {
    size_t w2 = 0;
    if (!otrng_dake_prekey_message_serialize(message->message + w, size - w,
                                             &w2,
                                             pub_message->prekey_messages[i])) {
      free(client_profile);
      free(prekey_profile);
      return OTRNG_ERROR;
    }
    w += w2;
  }

  if (pub_message->num_prekey_messages > 0) {
    values_priv_ecdh = otrng_secure_alloc(pub_message->num_prekey_messages *
                                          sizeof(ec_scalar));
    values_pub_ecdh =
        otrng_xmalloc_z(pub_message->num_prekey_messages * sizeof(ec_point));

    values_priv_dh =
        otrng_secure_alloc(pub_message->num_prekey_messages * sizeof(dh_mpi));
    values_pub_dh =
        otrng_xmalloc_z(pub_message->num_prekey_messages * sizeof(dh_mpi));

    for (i = 0; i < pub_message->num_prekey_messages; i++) {
      *values_pub_ecdh[i] = *pub_message->prekey_messages[i]->Y;
      *values_priv_ecdh[i] = *pub_message->ecdh_keys[i];
      values_pub_dh[i] = pub_message->prekey_messages[i]->B;
      values_priv_dh[i] = pub_message->dh_keys[i];
    }

    if (!otrng_ecdh_proof_generate(
            &prekey_message_proof_ecdh, (const ec_scalar *)values_priv_ecdh,
            (const ec_point *)values_pub_ecdh, pub_message->num_prekey_messages,
            m, usage_proof_message_ecdh)) {
      free(client_profile);
      free(prekey_profile);
      otrng_secure_wipe(values_priv_ecdh,
                        pub_message->num_prekey_messages * sizeof(ec_scalar));
      free(values_priv_ecdh);
      free(values_pub_ecdh);
      otrng_secure_wipe(values_priv_dh,
                        pub_message->num_prekey_messages * sizeof(dh_mpi));
      free(values_priv_dh);
      free(values_pub_dh);
      return OTRNG_ERROR;
    }

    if (!otrng_dh_proof_generate(&prekey_message_proof_dh, values_priv_dh,
                                 values_pub_dh,
                                 pub_message->num_prekey_messages, m,
                                 usage_proof_message_dh, NULL)) {
      free(client_profile);
      free(prekey_profile);
      otrng_secure_wipe(values_priv_ecdh,
                        pub_message->num_prekey_messages * sizeof(ec_scalar));
      free(values_priv_ecdh);
      free(values_pub_ecdh);
      otrng_secure_wipe(values_priv_dh,
                        pub_message->num_prekey_messages * sizeof(dh_mpi));
      free(values_priv_dh);
      free(values_pub_dh);
      return OTRNG_ERROR;
    }

    otrng_secure_wipe(values_priv_ecdh,
                      pub_message->num_prekey_messages * sizeof(ec_scalar));
    free(values_priv_ecdh);
    free(values_pub_ecdh);
    otrng_secure_wipe(values_priv_dh,
                      pub_message->num_prekey_messages * sizeof(dh_mpi));
    free(values_priv_dh);
    free(values_pub_dh);
  }

  if (pub_message->prekey_profile != NULL) {
    proof_buf_len += PROOF_C_SIZE + ED448_SCALAR_BYTES;
    values_priv_ecdh = otrng_secure_alloc(1 * sizeof(ec_scalar));
    values_pub_ecdh = otrng_xmalloc_z(1 * sizeof(ec_point));

    *values_pub_ecdh[0] = *pub_message->prekey_profile->shared_prekey;
    *values_priv_ecdh[0] = *pub_message->prekey_profile_key;

    if (!otrng_ecdh_proof_generate(
            &prekey_profile_proof, (const ec_scalar *)values_priv_ecdh,
            (const ec_point *)values_pub_ecdh, 1, m, usage_proof_shared_ecdh)) {
      free(client_profile);
      free(prekey_profile);
      otrng_secure_wipe(values_priv_ecdh, 1 * sizeof(ec_scalar));
      free(values_priv_ecdh);
      free(values_pub_ecdh);
      return OTRNG_ERROR;
    }

    otrng_secure_wipe(values_priv_ecdh, 1 * sizeof(ec_scalar));
    free(values_priv_ecdh);
    free(values_pub_ecdh);
  }

  proofs = otrng_xmalloc_z(proof_buf_len * sizeof(uint8_t));

  if (pub_message->num_prekey_messages > 0) {
    proof_index += otrng_ecdh_proof_serialize(proofs + proof_index,
                                              &prekey_message_proof_ecdh);
    proof_index += otrng_dh_proof_serialize(proofs + proof_index,
                                            &prekey_message_proof_dh);
  }

  if (pub_message->prekey_profile != NULL) {
    proof_index +=
        otrng_ecdh_proof_serialize(proofs + proof_index, &prekey_profile_proof);
  }

  shake_256_prekey_server_kdf(prekey_proofs_kdf, HASH_BYTES, usage_mac_proofs,
                              proofs, proof_index);

  shake_256_prekey_server_kdf(prekey_messages_kdf, HASH_BYTES,
                              usage_prekey_message, prekey_messages_beginning,
                              message->message + w - prekey_messages_beginning);

  w += otrng_serialize_uint8(message->message + w,
                             pub_message->client_profile ? 1 : 0);
  w += otrng_serialize_bytes_array(message->message + w, client_profile,
                                   client_profile_len);

  w += otrng_serialize_uint8(message->message + w,
                             pub_message->prekey_profile ? 1 : 0);
  w += otrng_serialize_bytes_array(message->message + w, prekey_profile,
                                   prekey_profile_len);

  w += otrng_serialize_bytes_array(message->message + w, proofs, proof_index);

  free(proofs);

  /* MAC: KDF(usage_preMAC, prekey_mac_k || message type
            || N || KDF(usage_prekey_message, Prekey Messages, 64)
            || K || KDF(usage_client_profile, Client Profile, 64)
            || J || KDF(usage_prekey_profile, Prekey Profile, 64)
            || KDF(usage_mac_proofs, Proofs, 64),
        64) */

  kdf_init_with_usage(hd, usage_pre_MAC);
  hash_update(hd, mac_key, MAC_KEY_BYTES);

  hash_update(hd, &message_type, 1);
  hash_update(hd, &pub_message->num_prekey_messages, 1);
  hash_update(hd, prekey_messages_kdf, HASH_BYTES);

  if (pub_message->client_profile) {
    uint8_t usage_client_profile = 0x0F;
    uint8_t client_profile_kdf[HASH_BYTES];

    memset(client_profile_kdf, 0, HASH_BYTES);

    shake_256_prekey_server_kdf(client_profile_kdf, HASH_BYTES,
                                usage_client_profile, client_profile,
                                client_profile_len);

    hash_update(hd, &one, 1);
    hash_update(hd, client_profile_kdf, HASH_BYTES);
  } else {
    hash_update(hd, &zero, 1);
  }
  free(client_profile);

  if (pub_message->prekey_profile) {
    uint8_t prekey_profile_kdf[HASH_BYTES];
    uint8_t usage_prekey_profile = 0x10;

    memset(prekey_profile_kdf, 0, HASH_BYTES);

    shake_256_prekey_server_kdf(prekey_profile_kdf, HASH_BYTES,
                                usage_prekey_profile, prekey_profile,
                                prekey_profile_len);

    hash_update(hd, &one, 1);
    hash_update(hd, prekey_profile_kdf, HASH_BYTES);
  } else {
    hash_update(hd, &zero, 1);
  }
  free(prekey_profile);

  hash_update(hd, prekey_proofs_kdf, HASH_BYTES);

  hash_final(hd, message->message + w, HASH_BYTES);
  hash_destroy(hd);

  message->message_len = w + HASH_BYTES;

  return OTRNG_SUCCESS;
}

tstatic char *send_dake3(const otrng_prekey_dake2_message_s *message2,
                         otrng_client_s *client) {
  otrng_prekey_dake3_message_s message;
  size_t composite_phi_len = 0;
  uint8_t *composite_phi;
  uint8_t *our_profile = NULL;
  size_t our_profile_len = 0;
  size_t tlen;
  uint8_t *t;
  size_t w = 1;
  uint8_t usage_receiver_client_profile = 0x05;
  uint8_t usage_receiver_prekey_composite_identity = 0x06;
  uint8_t usage_receiver_prekey_composite_phi = 0x07;
  uint8_t *shared_secret = otrng_secure_alloc(HASH_BYTES);
  uint8_t *ecdh_shared = otrng_secure_alloc(ED448_POINT_BYTES);
  uint8_t usage_SK = 0x01;
  uint8_t usage_preMAC_key = 0x08;
  uint8_t usage_proof_context = 0x12;
  otrng_result success;
  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
  char *ret;
  uint8_t m[64];
  otrng_prekey_client_s *prekey_client = client->prekey_client;

  otrng_prekey_dake3_message_init(&message);
  message.client_instance_tag = prekey_client->instance_tag;

  composite_phi = otrng_prekey_client_get_expected_composite_phi(
      &composite_phi_len, prekey_client);
  if (!composite_phi) {
    free(shared_secret);
    free(ecdh_shared);
    return NULL;
  }

  if (!otrng_client_profile_serialize(&our_profile, &our_profile_len,
                                      prekey_client->client_profile)) {
    free(shared_secret);
    free(ecdh_shared);
    return NULL;
  }

  tlen = 1 + 3 * HASH_BYTES + 2 * ED448_POINT_BYTES;
  t = otrng_xmalloc_z(tlen);

  *t = 0x1;

  shake_256_prekey_server_kdf(t + w, HASH_BYTES, usage_receiver_client_profile,
                              our_profile, our_profile_len);
  free(our_profile);

  w += HASH_BYTES;

  /* Both composite identity AND composite phi have the server's bare JID */
  shake_256_prekey_server_kdf(
      t + w, HASH_BYTES, usage_receiver_prekey_composite_identity,
      message2->composite_identity, message2->composite_identity_len);

  w += HASH_BYTES;

  w += otrng_serialize_ec_point(t + w, prekey_client->ephemeral_ecdh->pub);
  w += otrng_serialize_ec_point(t + w, message2->S);

  shake_256_prekey_server_kdf(t + w, HASH_BYTES,
                              usage_receiver_prekey_composite_phi,
                              composite_phi, composite_phi_len);
  free(composite_phi);

  /* H_a, sk_ha, {H_a, H_s, S}, t */
  otrng_rsig_authenticate_with_usage_and_domain(
      usage_auth, prekey_hash_domain, message.sigma,
      prekey_client->keypair->priv, prekey_client->keypair->pub,
      prekey_client->keypair->pub, message2->server_pub_key, message2->S, t,
      tlen);
  free(t);

  /* ECDH(i, S) */
  // TODO: check is the ephemeral is erased
  if (otrng_failed(otrng_ecdh_shared_secret(ecdh_shared, ED448_POINT_BYTES,
                                            prekey_client->ephemeral_ecdh->priv,
                                            message2->S))) {
    free(shared_secret);
    free(ecdh_shared);
    return NULL;
  }

  /* SK = KDF(0x01, ECDH(i, S), 64) */
  shake_256_prekey_server_kdf(shared_secret, HASH_BYTES, usage_SK,
                              ecdh_shared, ED448_POINT_BYTES);

  /* prekey_mac_k = KDF(0x08, SK, 64) */
  shake_256_prekey_server_kdf(prekey_client->mac_key, MAC_KEY_BYTES,
                              usage_preMAC_key, shared_secret,
                              HASH_BYTES);

  /* Attach MESSAGE in the message */
  if (prekey_client->after_dake == OTRNG_PREKEY_STORAGE_INFORMATION_REQUEST) {
    if (!otrng_prekey_dake3_message_append_storage_information_request(
            &message, prekey_client->mac_key)) {
      otrng_secure_wipe(shared_secret, HASH_BYTES);
      free(shared_secret);
      otrng_secure_wipe(ecdh_shared, ED448_POINT_BYTES);
      free(ecdh_shared);
      return NULL;
    }
  } else if (prekey_client->after_dake == OTRNG_PREKEY_PREKEY_PUBLICATION) {
    otrng_prekey_publication_message_s *pub_message =
        otrng_prekey_publication_message_new();
    if (!build_prekey_publication_message_callback(pub_message, client)) {
      otrng_secure_wipe(shared_secret, HASH_BYTES);
      free(shared_secret);
      otrng_secure_wipe(ecdh_shared, ED448_POINT_BYTES);
      free(ecdh_shared);
      return NULL;
    }

    /* m for proofs = KDF(0x12, SK, 64) */
    shake_256_prekey_server_kdf(m, 64, usage_proof_context, shared_secret,
                                HASH_BYTES);

    success = otrng_prekey_dake3_message_append_prekey_publication_message(
        pub_message, &message, prekey_client->mac_key, m);
    otrng_prekey_publication_message_destroy(pub_message);

    if (!success) {
      otrng_secure_wipe(shared_secret, HASH_BYTES);
      free(shared_secret);
      otrng_secure_wipe(ecdh_shared, ED448_POINT_BYTES);
      free(ecdh_shared);
      return NULL;
    }
  } else {
    otrng_secure_wipe(shared_secret, HASH_BYTES);
    free(shared_secret);
    otrng_secure_wipe(ecdh_shared, ED448_POINT_BYTES);
    free(ecdh_shared);
    return NULL;
  }

  prekey_client->after_dake = 0;

  success = otrng_prekey_dake3_message_serialize(&serialized, &serialized_len,
                                                 &message);
  otrng_prekey_dake3_message_destroy(&message);

  if (!success) {
    otrng_secure_wipe(shared_secret, HASH_BYTES);
    free(shared_secret);
    otrng_secure_wipe(ecdh_shared, ED448_POINT_BYTES);
    free(ecdh_shared);
    return NULL;
  }

  ret = prekey_encode(serialized, serialized_len);
  free(serialized);
  otrng_secure_wipe(shared_secret, HASH_BYTES);
  free(shared_secret);
  otrng_secure_wipe(ecdh_shared, ED448_POINT_BYTES);
  free(ecdh_shared);

  return ret;
}

static char *process_received_dake2(const otrng_prekey_dake2_message_s *message,
                                    otrng_client_s *client) {

  if (message->client_instance_tag != client->prekey_client->instance_tag) {
    return NULL;
  }

  if (!otrng_prekey_dake2_message_valid(message, client->prekey_client)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_INVALID_DAKE2);
    return NULL;
  }

  return send_dake3(message, client);
}

static char *receive_dake2(const uint8_t *decoded, size_t decoded_len,
                           otrng_client_s *client) {
  otrng_prekey_dake2_message_s message;
  char *ret = NULL;

  otrng_prekey_dake2_message_init(&message);
  if (!otrng_prekey_dake2_message_deserialize(&message, decoded, decoded_len)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MESSAGE);
    return NULL;
  }

  ret = process_received_dake2(&message, client);
  otrng_prekey_dake2_message_destroy(&message);

  return ret;
}

static otrng_bool otrng_prekey_storage_status_message_valid(
    const otrng_prekey_storage_status_message_s *message,
    const uint8_t mac_key[MAC_KEY_BYTES]) {

  size_t bufl = 1 + 4 + 4;
  uint8_t *buf = otrng_xmalloc_z(bufl);
  uint8_t mac_tag[HASH_BYTES];
  uint8_t usage_status_MAC = 0x0B;
  goldilocks_shake256_ctx_p hmac;

  *buf = OTRNG_PREKEY_STORAGE_STATUS_MESSAGE; /* message type */
  otrng_serialize_uint32(buf + 1, message->client_instance_tag);
  otrng_serialize_uint32(buf + 5, message->stored_prekeys);

  /* KDF(usage_status_MAC, prekey_mac_k || message type || receiver instance
   tag
   || Stored Prekey Messages Number, 64) */

  kdf_init_with_usage(hmac, usage_status_MAC);
  hash_update(hmac, mac_key, MAC_KEY_BYTES);
  hash_update(hmac, buf, bufl);
  hash_final(hmac, mac_tag, HASH_BYTES);
  hash_destroy(hmac);

  free(buf);

  if (otrl_mem_differ(mac_tag, message->mac, HASH_BYTES) != 0) {
    otrng_secure_wipe(mac_tag, HASH_BYTES);
    return otrng_false;
  }

  return otrng_true;
}

static char *process_received_storage_status(
    const otrng_prekey_storage_status_message_s *message,
    otrng_client_s *client) {
  if (message->client_instance_tag != client->prekey_client->instance_tag) {
    return NULL;
  }

  if (!otrng_prekey_storage_status_message_valid(
          message, client->prekey_client->mac_key)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_INVALID_STORAGE_STATUS);
    return NULL;
  }

  prekey_storage_status_received_callback(client, message);
  return NULL;
}

static char *receive_storage_status(const uint8_t *decoded, size_t decoded_len,
                                    otrng_client_s *client) {
  otrng_prekey_storage_status_message_s message[1];
  char *ret;

  if (!otrng_prekey_storage_status_message_deserialize(message, decoded,
                                                       decoded_len)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MESSAGE);
    return NULL;
  }

  ret = process_received_storage_status(message, client);

  if (message->stored_prekeys < client->prekey_client->publication_policy
                                    ->minimum_stored_prekey_message) {
    client->prekey_messages_num_to_publish =
        client->prekey_client->publication_policy
            ->max_published_prekey_message -
        message->stored_prekeys;
    low_prekey_messages_in_storage_callback(client);
  }

  otrng_prekey_storage_status_message_destroy(message);
  return ret;
}

static char *receive_success(const uint8_t *decoded, size_t decoded_len,
                             otrng_client_s *client) {
  uint32_t instance_tag = 0;
  size_t read = 0;
  uint8_t mac_tag[HASH_BYTES];
  uint8_t usage_success_MAC = 0x0C;
  goldilocks_shake256_ctx_p hash;

  memset(mac_tag, 0, HASH_BYTES);

  if (decoded_len < OTRNG_PREKEY_SUCCESS_MESSAGE_LEN) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MESSAGE);
    return NULL;
  }

  if (!otrng_deserialize_uint32(&instance_tag, decoded + 3, decoded_len - 3,
                                &read)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MESSAGE);
    return NULL;
  }

  if (instance_tag != client->prekey_client->instance_tag) {
    return NULL;
  }

  kdf_init_with_usage(hash, usage_success_MAC);
  hash_update(hash, client->prekey_client->mac_key, MAC_KEY_BYTES);
  hash_update(hash, decoded + 2, 5);
  hash_final(hash, mac_tag, HASH_BYTES);
  hash_destroy(hash);

  if (otrl_mem_differ(mac_tag, decoded + 7, HASH_BYTES) != 0) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_INVALID_SUCCESS);
  } else {
    success_received_callback(client);
  }

  otrng_secure_wipe(mac_tag, HASH_BYTES);
  return NULL;
}

static char *receive_failure(const uint8_t *decoded, size_t decoded_len,
                             otrng_client_s *client) {
  uint32_t instance_tag = 0;
  size_t read = 0;
  uint8_t mac_tag[HASH_BYTES];
  uint8_t usage_failure_MAC = 0x0D;

  goldilocks_shake256_ctx_p hash;

  memset(mac_tag, 0, HASH_BYTES);

  if (decoded_len < 71) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MESSAGE);
    return NULL;
  }

  if (!otrng_deserialize_uint32(&instance_tag, decoded + 3, decoded_len - 3,
                                &read)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MESSAGE);
    return NULL;
  }

  if (instance_tag != client->prekey_client->instance_tag) {
    return NULL;
  }

  kdf_init_with_usage(hash, usage_failure_MAC);
  hash_update(hash, client->prekey_client->mac_key, MAC_KEY_BYTES);
  hash_update(hash, decoded + 2, 5);
  hash_final(hash, mac_tag, HASH_BYTES);
  hash_destroy(hash);

  if (otrl_mem_differ(mac_tag, decoded + 7, HASH_BYTES) != 0) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_INVALID_SUCCESS);
  } else {
    failure_received_callback(client);
  }

  otrng_secure_wipe(mac_tag, HASH_BYTES);
  return NULL;
}

static char *receive_no_prekey_in_storage(const uint8_t *decoded,
                                          size_t decoded_len,
                                          otrng_client_s *client) {
  uint32_t instance_tag = 0;
  size_t read = 0;

  if (!otrng_deserialize_uint32(&instance_tag, decoded + 3, decoded_len - 3,
                                &read)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MESSAGE);
    return NULL;
  }

  if (instance_tag != client->prekey_client->instance_tag) {
    return NULL;
  }

  no_prekey_in_storage_received_callback(client);
  return NULL;
}

static void process_received_prekey_ensemble_retrieval(
    otrng_prekey_ensemble_retrieval_message_s *message,
    otrng_client_s *client) {
  int i;

  if (message->instance_tag != client->prekey_client->instance_tag) {
    return;
  }

  for (i = 0; i < message->num_ensembles; i++) {
    if (!otrng_prekey_ensemble_validate(message->ensembles[i])) {
      otrng_prekey_ensemble_destroy(message->ensembles[i]);
      message->ensembles[i] = NULL;
    }
  }

  prekey_ensembles_received_callback(client, message->ensembles,
                                     message->num_ensembles);
}

static char *receive_prekey_ensemble_retrieval(const uint8_t *decoded,
                                               size_t decoded_len,
                                               otrng_client_s *client) {
  otrng_prekey_ensemble_retrieval_message_s message[1];

  if (!otrng_prekey_ensemble_retrieval_message_deserialize(message, decoded,
                                                           decoded_len)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MESSAGE);
    otrng_prekey_ensemble_retrieval_message_destroy(message);
    return NULL;
  }

  process_received_prekey_ensemble_retrieval(message, client);
  otrng_prekey_ensemble_retrieval_message_destroy(message);
  return NULL;
}

API otrng_result otrng_parse_header(uint8_t *message_type, const uint8_t *buf,
                                    size_t buflen, size_t *read) {
  size_t r = 0; /* read */
  size_t w = 0; /* walked */

  uint16_t protocol_version = 0;

  if (!otrng_deserialize_uint16(&protocol_version, buf, buflen, &r)) {
    return OTRNG_ERROR;
  }

  w += r;

  if (protocol_version != OTRNG_PROTOCOL_VERSION_4) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint8(message_type, buf + w, buflen - w, &r)) {
    return OTRNG_ERROR;
  }

  w += r;

  if (read) {
    *read = w;
  }

  return OTRNG_SUCCESS;
}

static char *receive_decoded(const uint8_t *decoded, size_t decoded_len,
                             otrng_client_s *client) {
  uint8_t message_type = 0;
  char *ret = NULL;

  if (!otrng_parse_header(&message_type, decoded, decoded_len, NULL)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MESSAGE);
    return NULL;
  }

  if (message_type == OTRNG_PREKEY_DAKE2_MESSAGE) {
    ret = receive_dake2(decoded, decoded_len, client);
  } else if (message_type == OTRNG_PREKEY_SUCCESS_MESSAGE) {
    ret = receive_success(decoded, decoded_len, client);
  } else if (message_type == OTRNG_PREKEY_FAILURE_MESSAGE) {
    ret = receive_failure(decoded, decoded_len, client);
  } else if (message_type == OTRNG_PREKEY_NO_PREKEY_IN_STORAGE_MESSAGE) {
    ret = receive_no_prekey_in_storage(decoded, decoded_len, client);
  } else if (message_type == OTRNG_PREKEY_ENSEMBLE_RETRIEVAL_MESSAGE) {
    ret = receive_prekey_ensemble_retrieval(decoded, decoded_len, client);
  } else if (message_type == OTRNG_PREKEY_STORAGE_STATUS_MESSAGE) {
    ret = receive_storage_status(decoded, decoded_len, client);
  } else {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MESSAGE);
  }

  return ret;
}

/* TODO: this function should probably return otrng_bool instead */
API otrng_result otrng_prekey_client_receive(char **tosend, const char *server,
                                             const char *message,
                                             otrng_client_s *client) {
  uint8_t *serialized = NULL;
  size_t serialized_len = 0;

  assert(client);
  assert(client->prekey_client);

  /* It should only process prekey server messages from the expected server.
     This avoids processing any plaintext message from a party as a
     malformed prekey server message. */
  if (strcmp(client->prekey_client->server_identity, server) != 0) {
    return OTRNG_ERROR;
  }

  // TODO: process fragmented messages

  /* If it fails to decode it was not a prekey server message. */
  if (!prekey_decode(message, &serialized, &serialized_len)) {
    return OTRNG_ERROR;
  }

  /* In any other case, it returns SUCCESS because we processed the message.
     Even if there was an error processing it. We should consider informing the
     error while processing using callbacks.
  */
  *tosend = receive_decoded(serialized, serialized_len, client);
  free(serialized);

  return OTRNG_SUCCESS;
}

INTERNAL
otrng_result otrng_prekey_dake1_message_serialize(
    uint8_t **serialized, size_t *serialized_len,
    const otrng_prekey_dake1_message_s *message) {

  uint8_t *client_profile_buff = NULL;
  size_t client_profile_buff_len = 0;
  size_t ret_len;
  uint8_t *ret;
  size_t w = 0;

  if (!otrng_client_profile_serialize(&client_profile_buff,
                                      &client_profile_buff_len,
                                      message->client_profile)) {
    return OTRNG_ERROR;
  }

  ret_len = 2 + 1 + 4 + client_profile_buff_len + ED448_POINT_BYTES;
  ret = otrng_xmalloc_z(ret_len);

  w += otrng_serialize_uint16(ret + w, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(ret + w, OTRNG_PREKEY_DAKE1_MESSAGE);
  w += otrng_serialize_uint32(ret + w, message->client_instance_tag);
  w += otrng_serialize_bytes_array(ret + w, client_profile_buff,
                                   client_profile_buff_len);
  w += otrng_serialize_ec_point(ret + w, message->I);
  free(client_profile_buff);

  *serialized = ret;
  if (serialized_len) {
    *serialized_len = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL
void otrng_prekey_dake1_message_destroy(otrng_prekey_dake1_message_s *message) {
  if (!message) {
    return;
  }

  otrng_client_profile_destroy(message->client_profile);
  free(message->client_profile);
  message->client_profile = NULL;
  otrng_ec_point_destroy(message->I);
}

INTERNAL otrng_result otrng_prekey_dake2_message_deserialize(
    otrng_prekey_dake2_message_s *destination, const uint8_t *serialized,
    size_t serialized_len) {

  size_t w = 0;
  size_t read = 0;
  uint8_t message_type = 0;
  const uint8_t *composite_identity_start;

  if (!otrng_parse_header(&message_type, serialized, serialized_len, &w)) {
    return OTRNG_ERROR;
  }

  if (message_type != OTRNG_PREKEY_DAKE2_MESSAGE) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&destination->client_instance_tag,
                                serialized + w, serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  composite_identity_start = serialized + w;
  if (!otrng_deserialize_data(&destination->server_identity,
                              &destination->server_identity_len, serialized + w,
                              serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_public_key(destination->server_pub_key, serialized + w,
                                    serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  /* Store the composite identity, so we can use it to generate `t` */
  destination->composite_identity_len =
      serialized + w - composite_identity_start;
  destination->composite_identity =
      otrng_xmalloc(destination->composite_identity_len);
  memcpy(destination->composite_identity, composite_identity_start,
         destination->composite_identity_len);

  if (!otrng_deserialize_ec_point(destination->S, serialized + w,
                                  serialized_len - w)) {
    return OTRNG_ERROR;
  }

  w += ED448_POINT_BYTES;

  if (!otrng_deserialize_ring_sig(destination->sigma, serialized + w,
                                  serialized_len - w, NULL)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_prekey_dake2_message_s *otrng_prekey_dake2_message_new() {
  otrng_prekey_dake2_message_s *r =
      otrng_xmalloc_z(sizeof(otrng_prekey_dake2_message_s));
  otrng_prekey_dake2_message_init(r);
  return r;
}

INTERNAL void otrng_prekey_dake2_message_init(otrng_prekey_dake2_message_s *a) {
  memset(a, 0, sizeof(otrng_prekey_dake2_message_s));
  a->sigma = otrng_xmalloc_z(sizeof(ring_sig_s));
}

INTERNAL
void otrng_prekey_dake2_message_destroy(otrng_prekey_dake2_message_s *message) {
  if (!message) {
    return;
  }

  if (message->composite_identity) {
    free(message->composite_identity);
    message->composite_identity = NULL;
  }

  if (message->server_identity) {
    free(message->server_identity);
    message->server_identity = NULL;
  }

  otrng_ec_point_destroy(message->S);
  otrng_ring_sig_destroy(message->sigma);
  free(message->sigma);
  message->sigma = NULL;
}

INTERNAL otrng_result otrng_prekey_dake3_message_serialize(
    uint8_t **serialized, size_t *serialized_len,
    const otrng_prekey_dake3_message_s *message) {
  size_t ret_len = 2 + 1 + 4 + RING_SIG_BYTES + (4 + message->message_len) +
                   ED448_POINT_BYTES;
  uint8_t *ret = otrng_xmalloc_z(ret_len);
  size_t w = 0;

  w += otrng_serialize_uint16(ret + w, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(ret + w, OTRNG_PREKEY_DAKE3_MESSAGE);
  w += otrng_serialize_uint32(ret + w, message->client_instance_tag);
  w += otrng_serialize_ring_sig(ret + w, message->sigma);
  w += otrng_serialize_data(ret + w, message->message, message->message_len);

  *serialized = ret;
  if (serialized_len) {
    *serialized_len = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_prekey_dake3_message_s *otrng_prekey_dake3_message_new() {
  otrng_prekey_dake3_message_s *r =
      otrng_xmalloc_z(sizeof(otrng_prekey_dake3_message_s));
  otrng_prekey_dake3_message_init(r);
  return r;
}

INTERNAL void otrng_prekey_dake3_message_init(otrng_prekey_dake3_message_s *a) {
  memset(a, 0, sizeof(otrng_prekey_dake3_message_s));
  a->sigma = otrng_xmalloc_z(sizeof(ring_sig_s));
}

INTERNAL
void otrng_prekey_dake3_message_destroy(otrng_prekey_dake3_message_s *message) {
  if (!message) {
    return;
  }

  free(message->message);
  message->message = NULL;

  otrng_ring_sig_destroy(message->sigma);
  free(message->sigma);
  message->sigma = NULL;
}

INTERNAL otrng_result otrng_prekey_storage_status_message_deserialize(
    otrng_prekey_storage_status_message_s *destination,
    const uint8_t *serialized, size_t serialized_len) {
  size_t w = 0;
  size_t read = 0;

  uint8_t message_type = 0;

  if (!otrng_parse_header(&message_type, serialized, serialized_len, &w)) {
    return OTRNG_ERROR;
  }

  if (message_type != OTRNG_PREKEY_STORAGE_STATUS_MESSAGE) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&destination->client_instance_tag,
                                serialized + w, serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_uint32(&destination->stored_prekeys, serialized + w,
                                serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_bytes_array(destination->mac, DATA_MESSAGE_MAC_BYTES,
                                     serialized + w, serialized_len - w)) {
    return OTRNG_ERROR;
  }

  w += DATA_MESSAGE_MAC_BYTES;

  return OTRNG_SUCCESS;
}

INTERNAL
void otrng_prekey_storage_status_message_destroy(
    otrng_prekey_storage_status_message_s *message) {
  if (!message) {
    return;
  }

  message->client_instance_tag = 0;
  message->stored_prekeys = 0;
  otrng_secure_wipe(message->mac, DATA_MESSAGE_MAC_BYTES);
}

INTERNAL otrng_prekey_publication_message_s *
otrng_prekey_publication_message_new() {
  otrng_prekey_publication_message_s *message =
      malloc(sizeof(otrng_prekey_publication_message_s));
  if (!message) {
    return NULL;
  }

  message->client_profile = NULL;
  message->prekey_profile = NULL;
  message->prekey_messages = NULL;

  return message;
}

INTERNAL
void otrng_prekey_publication_message_destroy(
    otrng_prekey_publication_message_s *message) {
  int i;

  if (!message) {
    return;
  }

  if (message->prekey_messages) {
    for (i = 0; i < message->num_prekey_messages; i++) {
      otrng_dake_prekey_message_free(message->prekey_messages[i]);
    }

    free(message->prekey_messages);
    message->prekey_messages = NULL;
  }

  otrng_client_profile_free(message->client_profile);
  message->client_profile = NULL;

  otrng_prekey_profile_free(message->prekey_profile);
  message->prekey_profile = NULL;
}

INTERNAL otrng_result otrng_prekey_ensemble_retrieval_message_deserialize(
    otrng_prekey_ensemble_retrieval_message_s *destination,
    const uint8_t *serialized, size_t serialized_len) {
  size_t w = 0;
  size_t read = 0;
  uint8_t l;

  uint8_t message_type = 0;

  int i;

  if (!otrng_parse_header(&message_type, serialized, serialized_len, &w)) {
    return OTRNG_ERROR;
  }

  if (message_type != OTRNG_PREKEY_ENSEMBLE_RETRIEVAL_MESSAGE) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&destination->instance_tag, serialized + w,
                                serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_uint8(&l, serialized + w, serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  destination->ensembles = otrng_xmalloc_z(sizeof(prekey_ensemble_s *) * l);

  destination->num_ensembles = l;

  for (i = 0; i < l; i++) {
    destination->ensembles[i] = otrng_prekey_ensemble_new();

    if (!otrng_prekey_ensemble_deserialize(destination->ensembles[i],
                                           serialized + w, serialized_len - w,
                                           &read)) {
      return OTRNG_ERROR;
    }

    w += read;
  }

  return OTRNG_SUCCESS;
}

INTERNAL
void otrng_prekey_ensemble_retrieval_message_destroy(
    otrng_prekey_ensemble_retrieval_message_s *message) {
  int i;

  if (!message) {
    return;
  }

  if (message->ensembles) {
    for (i = 0; i < message->num_ensembles; i++) {
      otrng_prekey_ensemble_free(message->ensembles[i]);
    }
    free(message->ensembles);
  }

  message->ensembles = NULL;
}
