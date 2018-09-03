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

#include "prekey_client.h"

#include "base64.h"
#include "dake.h"
#include "deserialize.h"
#include "fingerprint.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"

#include <libotr/mem.h>

#define OTRNG_PREKEY_CLIENT_MALFORMED_MSG 1
#define OTRNG_PREKEY_CLIENT_INVALID_DAKE2 2
#define OTRNG_PREKEY_CLIENT_INVALID_STORAGE_STATUS 3
#define OTRNG_PREKEY_CLIENT_INVALID_SUCCESS 4
#define OTRNG_PREKEY_CLIENT_INVALID_FAILURE 5

static void notify_error_callback(otrng_prekey_client_s *client, int error) {
  client->callbacks->notify_error(error, client->callbacks->ctx);
}

static void prekey_storage_status_received_callback(
    otrng_prekey_client_s *client,
    const otrng_prekey_storage_status_message_s *msg) {
  client->callbacks->storage_status_received(msg, client->callbacks->ctx);
}

static void success_received_callback(otrng_prekey_client_s *client) {
  client->callbacks->success_received(client->callbacks->ctx);
}

static void failure_received_callback(otrng_prekey_client_s *client) {
  client->callbacks->failure_received(client->callbacks->ctx);
}

static void
no_prekey_in_storage_received_callback(otrng_prekey_client_s *client) {
  client->callbacks->no_prekey_in_storage_received(client->callbacks->ctx);
}

static void
low_prekey_messages_in_storage_callback(otrng_prekey_client_s *client) {
  client->callbacks->low_prekey_messages_in_storage(client->server_identity,
                                                    client->callbacks->ctx);
}

static void
prekey_ensembles_received_callback(otrng_prekey_client_s *client,
                                   prekey_ensemble_s *const *const ensembles,
                                   uint8_t num_ensembles) {
  client->callbacks->prekey_ensembles_received(ensembles, num_ensembles,
                                               client->callbacks->ctx);
}

static int build_prekey_publication_message_callback(
    otrng_prekey_publication_message_s *pub_msg,
    const otrng_prekey_client_s *client) {
  return client->callbacks->build_prekey_publication_message(
      pub_msg, client->max_published_prekey_msg, client->callbacks->ctx);
}

API otrng_prekey_client_s *
otrng_prekey_client_new(const char *server, const char *our_identity,
                        uint32_t instance_tag, const otrng_keypair_s *keypair,
                        const client_profile_s *client_profile,
                        const otrng_prekey_profile_s *prekey_profile,
                        unsigned int max_published_prekey_msg,
                        unsigned int minimum_stored_prekey_msg) {
  if (!server) {
    return NULL;
  }

  if (!our_identity) {
    return NULL;
  }

  if (!instance_tag) {
    return NULL;
  }

  if (!client_profile) {
    return NULL;
  }

  otrng_prekey_client_s *ret = malloc(sizeof(otrng_prekey_client_s));
  if (!ret) {
    return NULL;
  }

  ret->instance_tag = instance_tag;
  ret->client_profile = client_profile;
  // TODO: Can be null if you dont want to publish it
  ret->prekey_profile = prekey_profile;
  ret->keypair = keypair;
  ret->server_identity = otrng_strdup(server);
  ret->our_identity = otrng_strdup(our_identity);
  otrng_ecdh_keypair_destroy(ret->ephemeral_ecdh);
  ret->max_published_prekey_msg = max_published_prekey_msg;
  ret->minimum_stored_prekey_msg = minimum_stored_prekey_msg;

  return ret;
}

API void otrng_prekey_client_free(otrng_prekey_client_s *client) {
  if (!client) {
    return;
  }

  otrng_ecdh_keypair_destroy(client->ephemeral_ecdh);
  client->client_profile = NULL;

  free(client->server_identity);
  client->server_identity = NULL;

  free(client->our_identity);
  client->our_identity = NULL;

  free(client);
}

static otrng_result prekey_decode(const char *message, uint8_t **buffer,
                                  size_t *buffer_len) {
  size_t len = strlen(message);

  if (!len || '.' != message[len - 1]) {
    return OTRNG_ERROR;
  }

  /* (((base64len+3) / 4) * 3) */
  *buffer = malloc(((len - 1 + 3) / 4) * 3);
  if (!*buffer) {
    return OTRNG_ERROR;
  }

  *buffer_len = otrl_base64_decode(*buffer, message, len - 1);

  return OTRNG_SUCCESS;
}

static char *prekey_encode(const uint8_t *buffer, size_t buffer_len) {
  char *ret = malloc(OTRNG_BASE64_ENCODE_LEN(buffer_len) + 2);
  if (!ret) {
    return NULL;
  }

  size_t l = otrl_base64_encode(ret, buffer, buffer_len);
  ret[l] = '.';
  ret[l + 1] = 0;

  return ret;
}

static char *start_dake_and_then_send(otrng_prekey_client_s *client,
                                      otrng_prekey_next_message_t next) {
  otrng_prekey_dake1_message_s msg[1];
  msg->client_instance_tag = client->instance_tag;
  otrng_client_profile_copy(msg->client_profile, client->client_profile);

  uint8_t sym[ED448_PRIVATE_BYTES] = {0};
  random_bytes(sym, ED448_PRIVATE_BYTES);
  otrng_ecdh_keypair_generate(client->ephemeral_ecdh, sym);
  goldilocks_bzero(sym, ED448_PRIVATE_BYTES);
  otrng_ec_point_copy(msg->I, client->ephemeral_ecdh->pub);

  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
  otrng_result success =
      otrng_prekey_dake1_message_asprint(&serialized, &serialized_len, msg);
  otrng_prekey_dake1_message_destroy(msg);

  if (!success) {
    return NULL;
  }

  char *ret = prekey_encode(serialized, serialized_len);
  free(serialized);

  client->after_dake = next;

  return ret;
}

API char *
otrng_prekey_client_request_storage_information(otrng_prekey_client_s *client) {
  return start_dake_and_then_send(client,
                                  OTRNG_PREKEY_STORAGE_INFORMATION_REQUEST);
}

// TODO: this can publish up to 255 prekeys. How will this be handled? via
// callback? Via parameter?
API char *otrng_prekey_client_publish_prekeys(otrng_prekey_client_s *client) {
  return start_dake_and_then_send(client, OTRNG_PREKEY_PREKEY_PUBLICATION);
}

// What if we want to publish ONLY the profiles?
// API char *
// otrng_prekey_client_publish_profiles(otrng_prekey_client_s *client) {
//}

API char *otrng_prekey_client_retrieve_prekeys(const char *identity,
                                               const char *versions,
                                               otrng_prekey_client_s *client) {
  otrng_prekey_ensemble_query_retrieval_message_s msg[1];

  msg->identity = otrng_strdup(identity);
  msg->versions = otrng_strdup(versions);
  msg->instance_tag = client->instance_tag;

  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
  otrng_result success = otrng_prekey_ensemble_query_retrieval_message_asprint(
      &serialized, &serialized_len, msg);

  otrng_prekey_ensemble_query_retrieval_message_destroy(msg);

  if (!success) {
    return NULL;
  }

  char *ret = prekey_encode(serialized, serialized_len);
  free(serialized);
  return ret;
}

INTERNAL otrng_result otrng_prekey_ensemble_query_retrieval_message_asprint(
    uint8_t **dst, size_t *len,
    const otrng_prekey_ensemble_query_retrieval_message_s *msg) {
  if (!len || !dst) {
    return OTRNG_ERROR;
  }

  *len = 2 + 1 + 4 + (4 + strlen(msg->identity)) + (4 + strlen(msg->versions));
  *dst = malloc(*len);
  if (!*dst) {
    return OTRNG_ERROR;
  }

  size_t w = 0;
  w += otrng_serialize_uint16(*dst, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(*dst + w,
                             OTRNG_PREKEY_ENSEMBLE_QUERY_RETRIEVAL_MSG);
  w += otrng_serialize_uint32(*dst + w, msg->instance_tag);
  w += otrng_serialize_data(*dst + w, (uint8_t *)msg->identity,
                            strlen(msg->identity));
  w += otrng_serialize_data(*dst + w, (uint8_t *)msg->versions,
                            strlen(msg->versions));

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_prekey_ensemble_query_retrieval_message_destroy(
    otrng_prekey_ensemble_query_retrieval_message_s *msg) {
  if (!msg) {
    return;
  }

  free(msg->identity);
  msg->identity = NULL;

  free(msg->versions);
  msg->versions = NULL;
}

static uint8_t *otrng_prekey_client_get_expected_composite_phi(
    size_t *len, const otrng_prekey_client_s *client) {
  uint8_t *dst = NULL;
  if (!client->server_identity || !client->our_identity) {
    return NULL;
  }

  size_t s =
      4 + strlen(client->server_identity) + 4 + strlen(client->our_identity);
  dst = malloc(s);
  if (!dst) {
    return NULL;
  }

  size_t w = 0;
  w += otrng_serialize_data(dst + w, (const uint8_t *)client->our_identity,
                            strlen(client->our_identity));
  w += otrng_serialize_data(dst + w, (const uint8_t *)client->server_identity,
                            strlen(client->server_identity));

  if (len) {
    *len = s;
  }

  return dst;
}

static uint8_t usage_auth = 0x11;
static const char *prekey_hash_domain = "OTR-Prekey-Server";

INTERNAL void kdf_init_with_usage(goldilocks_shake256_ctx_p hash,
                                  uint8_t usage) {
  hash_init_with_usage_and_domain_separation(hash, usage, prekey_hash_domain);
}

static otrng_bool
otrng_prekey_dake2_message_valid(const otrng_prekey_dake2_message_s *msg,
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
  if (!composite_phi) {
    return otrng_false;
  }

  uint8_t *our_profile = NULL;
  size_t our_profile_len = 0;
  if (!otrng_client_profile_asprintf(&our_profile, &our_profile_len,
                                     client->client_profile)) {
    free(composite_phi);
    return otrng_false;
  }

  size_t tlen = 1 + 3 * HASH_BYTES + 2 * ED448_POINT_BYTES;
  uint8_t *t = malloc(tlen);
  if (!t) {
    free(composite_phi);
    free(our_profile);
    return otrng_false;
  }

  *t = 0x0;
  size_t w = 1;

  uint8_t usage_initator_client_profile = 0x02;
  uint8_t usage_initiator_prekey_composite_identity = 0x03;
  uint8_t usage_initiator_prekey_composite_phi = 0x04;

  shake_256_prekey_server_kdf(t + w, HASH_BYTES, usage_initator_client_profile,
                              our_profile, our_profile_len);
  free(our_profile);

  w += HASH_BYTES;

  /* Both composite identity AND composite phi have the server's bare JID */
  shake_256_prekey_server_kdf(
      t + w, HASH_BYTES, usage_initiator_prekey_composite_identity,
      msg->composite_identity, msg->composite_identity_len);

  w += HASH_BYTES;

  w += otrng_serialize_ec_point(t + w, client->ephemeral_ecdh->pub);
  w += otrng_serialize_ec_point(t + w, msg->S);

  shake_256_prekey_server_kdf(t + w, HASH_BYTES,
                              usage_initiator_prekey_composite_phi,
                              composite_phi, composite_phi_len);
  free(composite_phi);

  otrng_bool ret = otrng_rsig_verify_with_usage_and_domain(
      usage_auth, prekey_hash_domain, msg->sigma, client->keypair->pub,
      msg->server_pub_key, client->ephemeral_ecdh->pub, t, tlen);
  free(t);

  return ret;
}

INTERNAL otrng_result
otrng_prekey_dake3_message_append_storage_information_request(
    otrng_prekey_dake3_message_s *msg, uint8_t mac_key[MAC_KEY_BYTES]) {
  msg->message = malloc(2 + 1 + MAC_KEY_BYTES);
  if (!msg->message) {
    return OTRNG_ERROR;
  }
  msg->message_len = 67; // TODO: extract this

  uint8_t msg_type = OTRNG_PREKEY_STORAGE_INFO_REQ_MSG;
  size_t w = 0;
  w += otrng_serialize_uint16(msg->message, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(msg->message + w, msg_type);

  /* MAC: KDF(usage_storage_info_MAC, prekey_mac_k || message type, 64) */
  uint8_t usage_receiver_client_profile = 0x0A;

  goldilocks_shake256_ctx_p hmac;
  kdf_init_with_usage(hmac, usage_receiver_client_profile);
  hash_update(hmac, mac_key, MAC_KEY_BYTES);
  hash_update(hmac, &msg_type, 1);
  hash_final(hmac, msg->message + w, HASH_BYTES);
  hash_destroy(hmac);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_prekey_dake3_message_append_prekey_publication_message(
    otrng_prekey_publication_message_s *pub_msg,
    otrng_prekey_dake3_message_s *msg, uint8_t mac_key[MAC_KEY_BYTES]) {
  uint8_t *client_profile = NULL;
  size_t client_profile_len = 0;
  if (!otrng_client_profile_asprintf(&client_profile, &client_profile_len,
                                     pub_msg->client_profile)) {
    return OTRNG_ERROR;
  }

  uint8_t *prekey_profile = NULL;
  size_t prekey_profile_len = 0;
  if (!otrng_prekey_profile_asprint(&prekey_profile, &prekey_profile_len,
                                    pub_msg->prekey_profile)) {
    free(client_profile);
    return OTRNG_ERROR;
  }

  size_t s = 2 + 1 + 1 +
             (4 + pub_msg->num_prekey_messages * PRE_KEY_MAX_BYTES) + 1 +
             client_profile_len + 1 + prekey_profile_len + MAC_KEY_BYTES;
  msg->message = malloc(s);
  if (!msg->message) {
    free(client_profile);
    free(prekey_profile);
    return OTRNG_ERROR;
  }

  uint8_t msg_type = OTRNG_PREKEY_PUBLICATION_MSG;
  size_t w = 0;
  w += otrng_serialize_uint16(msg->message, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(msg->message + w, msg_type);

  w += otrng_serialize_uint8(msg->message + w, pub_msg->num_prekey_messages);

  const uint8_t *prekey_messages_beginning = msg->message + w;
  for (int i = 0; i < pub_msg->num_prekey_messages; i++) {
    size_t w2 = 0;
    if (!otrng_dake_prekey_message_serialize(msg->message + w, s - w, &w2,
                                             pub_msg->prekey_messages[i])) {
      free(client_profile);
      free(prekey_profile);
      return OTRNG_ERROR;
    }
    w += w2;
  }

  uint8_t usage_prekey_message = 0x0E;
  uint8_t prekey_messages_kdf[HASH_BYTES] = {0};

  shake_256_prekey_server_kdf(prekey_messages_kdf, HASH_BYTES,
                              usage_prekey_message, prekey_messages_beginning,
                              msg->message + w - prekey_messages_beginning);

  w += otrng_serialize_uint8(msg->message + w, pub_msg->client_profile ? 1 : 0);
  w += otrng_serialize_bytes_array(msg->message + w, client_profile,
                                   client_profile_len);

  free(client_profile);

  w += otrng_serialize_uint8(msg->message + w, pub_msg->prekey_profile ? 1 : 0);
  w += otrng_serialize_bytes_array(msg->message + w, prekey_profile,
                                   prekey_profile_len);

  free(prekey_profile);

  /* MAC: KDF(usage_preMAC, prekey_mac_k || message type
            || N || KDF(usage_prekey_message, Prekey Messages, 64)
            || K || KDF(usage_client_profile, Client Profile, 64)
            || J || KDF(usage_prekey_profile, Prekey Profile, 64),
        64) */

  uint8_t usage_pre_MAC = 0x09;
  uint8_t one = 1, zero = 0;

  goldilocks_shake256_ctx_p hd;
  kdf_init_with_usage(hd, usage_pre_MAC);
  hash_update(hd, mac_key, MAC_KEY_BYTES);
  hash_update(hd, &msg_type, 1);
  hash_update(hd, &pub_msg->num_prekey_messages, 1);
  hash_update(hd, prekey_messages_kdf, HASH_BYTES);

  if (pub_msg->client_profile) {
    uint8_t usage_client_profile = 0x0F;
    uint8_t client_profile_kdf[HASH_BYTES] = {0};

    shake_256_prekey_server_kdf(client_profile_kdf, HASH_BYTES,
                                usage_client_profile, client_profile,
                                client_profile_len);

    hash_update(hd, &one, 1);
    hash_update(hd, client_profile_kdf, HASH_BYTES);
  } else {
    hash_update(hd, &zero, 1);
  }

  if (pub_msg->prekey_profile) {
    uint8_t prekey_profile_kdf[HASH_BYTES] = {0};
    uint8_t usage_prekey_profile = 0x10;

    shake_256_prekey_server_kdf(prekey_profile_kdf, HASH_BYTES,
                                usage_prekey_profile, prekey_profile,
                                prekey_profile_len);

    hash_update(hd, &one, 1);
    hash_update(hd, prekey_profile_kdf, HASH_BYTES);
  } else {
    hash_update(hd, &zero, 1);
  }
  hash_final(hd, msg->message + w, HASH_BYTES);
  hash_destroy(hd);

  msg->message_len = w + HASH_BYTES;

  return OTRNG_SUCCESS;
}

tstatic char *send_dake3(const otrng_prekey_dake2_message_s *msg2,
                         otrng_prekey_client_s *client) {
  otrng_prekey_dake3_message_s msg[1];

  msg->client_instance_tag = client->instance_tag;

  size_t composite_phi_len = 0;
  uint8_t *composite_phi = otrng_prekey_client_get_expected_composite_phi(
      &composite_phi_len, client);
  if (!composite_phi) {
    return NULL;
  }

  uint8_t *our_profile = NULL;
  size_t our_profile_len = 0;
  if (!otrng_client_profile_asprintf(&our_profile, &our_profile_len,
                                     client->client_profile)) {
    return NULL;
  }

  size_t tlen = 1 + 3 * HASH_BYTES + 2 * ED448_POINT_BYTES;
  uint8_t *t = malloc(tlen);
  if (!t) {
    free(composite_phi);
    free(our_profile);
    return NULL;
  }

  *t = 0x1;
  size_t w = 1;

  uint8_t usage_receiver_client_profile = 0x05;
  uint8_t usage_receiver_prekey_composite_identity = 0x06;
  uint8_t usage_receiver_prekey_composite_phi = 0x07;

  shake_256_prekey_server_kdf(t + w, HASH_BYTES, usage_receiver_client_profile,
                              our_profile, our_profile_len);
  free(our_profile);

  w += HASH_BYTES;

  /* Both composite identity AND composite phi have the server's bare JID */
  shake_256_prekey_server_kdf(
      t + w, HASH_BYTES, usage_receiver_prekey_composite_identity,
      msg2->composite_identity, msg2->composite_identity_len);

  w += HASH_BYTES;

  w += otrng_serialize_ec_point(t + w, client->ephemeral_ecdh->pub);
  w += otrng_serialize_ec_point(t + w, msg2->S);

  shake_256_prekey_server_kdf(t + w, HASH_BYTES,
                              usage_receiver_prekey_composite_phi,
                              composite_phi, composite_phi_len);
  free(composite_phi);

  /* H_a, sk_ha, {H_a, H_s, S}, t */
  otrng_rsig_authenticate_with_usage_and_domain(
      usage_auth, prekey_hash_domain, msg->sigma, client->keypair->priv,
      client->keypair->pub, client->keypair->pub, msg2->server_pub_key, msg2->S,
      t, tlen);
  free(t);

  /* ECDH(i, S) */
  // TODO: check is the ephemeral is erased
  uint8_t shared_secret[HASH_BYTES] = {0};
  uint8_t ecdh_shared[ED448_POINT_BYTES] = {0};
  otrng_ecdh_shared_secret(ecdh_shared, sizeof(ecdh_shared),
                           client->ephemeral_ecdh->priv, msg2->S);

  uint8_t usage_SK = 0x01;
  uint8_t usage_preMAC_key = 0x08;

  /* SK = KDF(0x01, ECDH(i, S), 64) */
  shake_256_prekey_server_kdf(shared_secret, HASH_BYTES, usage_SK, ecdh_shared,
                              ED448_POINT_BYTES);

  /* prekey_mac_k = KDF(0x08, SK, 64) */
  shake_256_prekey_server_kdf(client->mac_key, MAC_KEY_BYTES, usage_preMAC_key,
                              shared_secret, HASH_BYTES);

  /* Attach MESSAGE in the message */
  if (client->after_dake == OTRNG_PREKEY_STORAGE_INFORMATION_REQUEST) {
    if (!otrng_prekey_dake3_message_append_storage_information_request(
            msg, client->mac_key)) {
      return NULL;
    }
  } else if (client->after_dake == OTRNG_PREKEY_PREKEY_PUBLICATION) {
    otrng_prekey_publication_message_s pub_msg[1];
    if (!build_prekey_publication_message_callback(pub_msg, client)) {
      return NULL;
    }

    otrng_result success =
        otrng_prekey_dake3_message_append_prekey_publication_message(
            pub_msg, msg, client->mac_key);
    otrng_prekey_publication_message_destroy(pub_msg);

    if (!success) {
      return NULL;
    }
  } else {
    return NULL;
  }

  client->after_dake = 0;

  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
  otrng_result success =
      otrng_prekey_dake3_message_asprint(&serialized, &serialized_len, msg);
  otrng_prekey_dake3_message_destroy(msg);

  if (!success) {
    return NULL;
  }

  char *ret = prekey_encode(serialized, serialized_len);
  free(serialized);

  return ret;
}

static char *process_received_dake2(const otrng_prekey_dake2_message_s *msg,
                                    otrng_prekey_client_s *client) {

  if (msg->client_instance_tag != client->instance_tag) {
    return NULL;
  }

  if (!otrng_prekey_dake2_message_valid(msg, client)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_INVALID_DAKE2);
    return NULL;
  }

  return send_dake3(msg, client);
}

static char *receive_dake2(const uint8_t *decoded, size_t decoded_len,
                           otrng_prekey_client_s *client) {
  otrng_prekey_dake2_message_s msg[1];

  if (!otrng_prekey_dake2_message_deserialize(msg, decoded, decoded_len)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG);
    otrng_prekey_dake2_message_destroy(msg);
    return NULL;
  }

  char *ret = process_received_dake2(msg, client);
  otrng_prekey_dake2_message_destroy(msg);

  return ret;
}

static otrng_bool otrng_prekey_storage_status_message_valid(
    const otrng_prekey_storage_status_message_s *msg,
    const uint8_t mac_key[MAC_KEY_BYTES]) {

  size_t bufl = 1 + 4 + 4;
  uint8_t *buf = malloc(bufl);
  if (!buf) {
    return otrng_false;
  }

  *buf = OTRNG_PREKEY_STORAGE_STATUS_MSG; /* message type */
  otrng_serialize_uint32(buf + 1, msg->client_instance_tag);
  otrng_serialize_uint32(buf + 5, msg->stored_prekeys);

  /* KDF(usage_status_MAC, prekey_mac_k || message type || receiver instance
   tag
   || Stored Prekey Messages Number, 64) */
  uint8_t mac_tag[HASH_BYTES];
  uint8_t usage_status_MAC = 0x0B;

  goldilocks_shake256_ctx_p hmac;
  kdf_init_with_usage(hmac, usage_status_MAC);
  hash_update(hmac, mac_key, MAC_KEY_BYTES);
  hash_update(hmac, buf, bufl);
  hash_final(hmac, mac_tag, HASH_BYTES);
  hash_destroy(hmac);

  free(buf);

  if (otrl_mem_differ(mac_tag, msg->mac, sizeof(mac_tag)) != 0) {
    sodium_memzero(mac_tag, sizeof(mac_tag));
    return otrng_false;
  }

  return otrng_true;
}

static char *process_received_storage_status(
    const otrng_prekey_storage_status_message_s *msg,
    otrng_prekey_client_s *client) {
  if (msg->client_instance_tag != client->instance_tag) {
    return NULL;
  }

  if (!otrng_prekey_storage_status_message_valid(msg, client->mac_key)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_INVALID_STORAGE_STATUS);
    return NULL;
  }

  prekey_storage_status_received_callback(client, msg);
  return NULL;
}

static char *receive_storage_status(const uint8_t *decoded, size_t decoded_len,
                                    otrng_prekey_client_s *client) {
  otrng_prekey_storage_status_message_s msg[1];

  if (!otrng_prekey_storage_status_message_deserialize(msg, decoded,
                                                       decoded_len)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG);
    return NULL;
  }

  char *ret = process_received_storage_status(msg, client);

  if (msg->stored_prekeys < client->minimum_stored_prekey_msg) {
    low_prekey_messages_in_storage_callback(client);
  }

  otrng_prekey_storage_status_message_destroy(msg);
  return ret;
}

static char *receive_success(const uint8_t *decoded, size_t decoded_len,
                             otrng_prekey_client_s *client) {
  if (decoded_len < OTRNG_PREKEY_SUCCESS_MSG_LEN) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG);
    return NULL;
  }

  uint32_t instance_tag = 0;
  size_t read = 0;
  if (!otrng_deserialize_uint32(&instance_tag, decoded + 3, decoded_len - 3,
                                &read)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG);
    return NULL;
  }

  if (instance_tag != client->instance_tag) {
    return NULL;
  }

  uint8_t mac_tag[HASH_BYTES] = {0};
  uint8_t usage_success_MAC = 0x0C;

  goldilocks_shake256_ctx_p hash;
  kdf_init_with_usage(hash, usage_success_MAC);
  hash_update(hash, client->mac_key, MAC_KEY_BYTES);
  hash_update(hash, decoded + 2, 5);
  hash_final(hash, mac_tag, HASH_BYTES);
  hash_destroy(hash);

  if (otrl_mem_differ(mac_tag, decoded + 7, HASH_BYTES) != 0) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_INVALID_SUCCESS);
  } else {
    success_received_callback(client);
  }

  sodium_memzero(mac_tag, sizeof(mac_tag));
  return NULL;
}

static char *receive_failure(const uint8_t *decoded, size_t decoded_len,
                             otrng_prekey_client_s *client) {
  if (decoded_len < 71) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG);
    return NULL;
  }

  uint32_t instance_tag = 0;
  size_t read = 0;
  if (!otrng_deserialize_uint32(&instance_tag, decoded + 3, decoded_len - 3,
                                &read)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG);
    return NULL;
  }

  if (instance_tag != client->instance_tag) {
    return NULL;
  }

  uint8_t mac_tag[HASH_BYTES] = {0};
  uint8_t usage_failure_MAC = 0x0D;

  goldilocks_shake256_ctx_p hash;
  kdf_init_with_usage(hash, usage_failure_MAC);
  hash_update(hash, client->mac_key, MAC_KEY_BYTES);
  hash_update(hash, decoded + 2, 5);
  hash_final(hash, mac_tag, HASH_BYTES);
  hash_destroy(hash);

  if (otrl_mem_differ(mac_tag, decoded + 7, HASH_BYTES) != 0) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_INVALID_SUCCESS);
  } else {
    failure_received_callback(client);
  }

  sodium_memzero(mac_tag, sizeof(mac_tag));
  return NULL;
}

static char *receive_no_prekey_in_storage(const uint8_t *decoded,
                                          size_t decoded_len,
                                          otrng_prekey_client_s *client) {
  uint32_t instance_tag = 0;
  size_t read = 0;
  if (!otrng_deserialize_uint32(&instance_tag, decoded + 3, decoded_len - 3,
                                &read)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG);
    return NULL;
  }

  if (instance_tag != client->instance_tag) {
    return NULL;
  }

  no_prekey_in_storage_received_callback(client);
  return NULL;
}

static void process_received_prekey_ensemble_retrieval(
    otrng_prekey_ensemble_retrieval_message_s *msg,
    otrng_prekey_client_s *client) {

  if (msg->instance_tag != client->instance_tag) {
    return;
  }

  // TODO: Validate the received ensembles and filter out any invalid ensemble

  prekey_ensembles_received_callback(client, msg->ensembles,
                                     msg->num_ensembles);
}

static char *receive_prekey_ensemble_retrieval(const uint8_t *decoded,
                                               size_t decoded_len,
                                               otrng_prekey_client_s *client) {
  otrng_prekey_ensemble_retrieval_message_s msg[1];

  if (!otrng_prekey_ensemble_retrieval_message_deserialize(msg, decoded,
                                                           decoded_len)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG);
    otrng_prekey_ensemble_retrieval_message_destroy(msg);
    return NULL;
  }

  process_received_prekey_ensemble_retrieval(msg, client);
  otrng_prekey_ensemble_retrieval_message_destroy(msg);
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
                             otrng_prekey_client_s *client) {
  uint8_t message_type = 0;
  if (!otrng_parse_header(&message_type, decoded, decoded_len, NULL)) {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG);
    return NULL;
  }

  char *ret = NULL;

  if (message_type == OTRNG_PREKEY_DAKE2_MSG) {
    ret = receive_dake2(decoded, decoded_len, client);
  } else if (message_type == OTRNG_PREKEY_SUCCESS_MSG) {
    ret = receive_success(decoded, decoded_len, client);
  } else if (message_type == OTRNG_PREKEY_FAILURE_MSG) {
    ret = receive_failure(decoded, decoded_len, client);
  } else if (message_type == OTRNG_PREKEY_NO_PREKEY_IN_STORAGE_MSG) {
    ret = receive_no_prekey_in_storage(decoded, decoded_len, client);
  } else if (message_type == OTRNG_PREKEY_ENSEMBLE_RETRIEVAL_MSG) {
    ret = receive_prekey_ensemble_retrieval(decoded, decoded_len, client);
  } else if (message_type == OTRNG_PREKEY_STORAGE_STATUS_MSG) {
    ret = receive_storage_status(decoded, decoded_len, client);
  } else {
    notify_error_callback(client, OTRNG_PREKEY_CLIENT_MALFORMED_MSG);
  }

  return ret;
}

API otrng_result otrng_prekey_client_receive(char **tosend, const char *server,
                                             const char *message,
                                             otrng_prekey_client_s *client) {
  /* It should only process prekey server messages from the expected server.
     This avoids processing any plaintext message from a party as a
     malformed prekey server message. */
  if (strcmp(client->server_identity, server) != 0) {
    return OTRNG_ERROR;
  }

  // TODO: process fragmented messages

  /* If it fails to decode it was not a prekey server message. */
  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
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
otrng_result
otrng_prekey_dake1_message_asprint(uint8_t **serialized, size_t *serialized_len,
                                   const otrng_prekey_dake1_message_s *msg) {

  uint8_t *client_profile_buff = NULL;
  size_t client_profile_buff_len = 0;
  if (!otrng_client_profile_asprintf(&client_profile_buff,
                                     &client_profile_buff_len,
                                     msg->client_profile)) {
    return OTRNG_ERROR;
  }

  size_t ret_len = 2 + 1 + 4 + client_profile_buff_len + ED448_POINT_BYTES;
  uint8_t *ret = malloc(ret_len);
  if (!ret) {
    free(client_profile_buff);
    return OTRNG_ERROR;
  }

  size_t w = 0;
  w += otrng_serialize_uint16(ret + w, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(ret + w, OTRNG_PREKEY_DAKE1_MSG);
  w += otrng_serialize_uint32(ret + w, msg->client_instance_tag);
  w += otrng_serialize_bytes_array(ret + w, client_profile_buff,
                                   client_profile_buff_len);
  w += otrng_serialize_ec_point(ret + w, msg->I);
  free(client_profile_buff);

  *serialized = ret;
  if (serialized_len) {
    *serialized_len = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL
void otrng_prekey_dake1_message_destroy(otrng_prekey_dake1_message_s *msg) {
  if (!msg) {
    return;
  }

  otrng_client_profile_destroy(msg->client_profile);
  otrng_ec_point_destroy(msg->I);
}

INTERNAL otrng_result otrng_prekey_dake2_message_deserialize(
    otrng_prekey_dake2_message_s *dst, const uint8_t *serialized,
    size_t serialized_len) {

  size_t w = 0;
  size_t read = 0;

  uint8_t message_type = 0;
  if (!otrng_parse_header(&message_type, serialized, serialized_len, &w)) {
    return OTRNG_ERROR;
  }

  if (message_type != OTRNG_PREKEY_DAKE2_MSG) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->client_instance_tag, serialized + w,
                                serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  const uint8_t *composite_identity_start = serialized + w;
  if (!otrng_deserialize_data(&dst->server_identity, &dst->server_identity_len,
                              serialized + w, serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_public_key(dst->server_pub_key, serialized + w,
                                    serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  /* Store the composite identity, so we can use it to generate `t` */
  dst->composite_identity_len = serialized + w - composite_identity_start;
  dst->composite_identity = malloc(dst->composite_identity_len);
  if (!dst->composite_identity) {
    return OTRNG_ERROR;
  }
  memcpy(dst->composite_identity, composite_identity_start,
         dst->composite_identity_len);

  if (!otrng_deserialize_ec_point(dst->S, serialized + w, serialized_len - w)) {
    return OTRNG_ERROR;
  }

  w += ED448_POINT_BYTES;

  if (!otrng_deserialize_ring_sig(dst->sigma, serialized + w,
                                  serialized_len - w, NULL)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL
void otrng_prekey_dake2_message_destroy(otrng_prekey_dake2_message_s *msg) {
  if (!msg) {
    return;
  }

  if (msg->composite_identity) {
    free(msg->composite_identity);
    msg->composite_identity = NULL;
  }

  if (msg->server_identity) {
    free(msg->server_identity);
    msg->server_identity = NULL;
  }

  otrng_ec_point_destroy(msg->S);
  otrng_ring_sig_destroy(msg->sigma);
}

INTERNAL otrng_result
otrng_prekey_dake3_message_asprint(uint8_t **serialized, size_t *serialized_len,
                                   const otrng_prekey_dake3_message_s *msg) {
  size_t ret_len =
      2 + 1 + 4 + RING_SIG_BYTES + (4 + msg->message_len) + ED448_POINT_BYTES;
  uint8_t *ret = malloc(ret_len);
  if (!ret) {
    return OTRNG_ERROR;
  }

  size_t w = 0;
  w += otrng_serialize_uint16(ret + w, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(ret + w, OTRNG_PREKEY_DAKE3_MSG);
  w += otrng_serialize_uint32(ret + w, msg->client_instance_tag);
  w += otrng_serialize_ring_sig(ret + w, msg->sigma);
  w += otrng_serialize_data(ret + w, msg->message, msg->message_len);

  *serialized = ret;
  if (serialized_len) {
    *serialized_len = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL
void otrng_prekey_dake3_message_destroy(otrng_prekey_dake3_message_s *msg) {
  if (!msg) {
    return;
  }

  free(msg->message);
  msg->message = NULL;

  otrng_ring_sig_destroy(msg->sigma);
}

INTERNAL otrng_result otrng_prekey_storage_status_message_deserialize(
    otrng_prekey_storage_status_message_s *dst, const uint8_t *serialized,
    size_t serialized_len) {
  size_t w = 0;
  size_t read = 0;

  uint8_t message_type = 0;
  if (!otrng_parse_header(&message_type, serialized, serialized_len, &w)) {
    return OTRNG_ERROR;
  }

  if (message_type != OTRNG_PREKEY_STORAGE_STATUS_MSG) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->client_instance_tag, serialized + w,
                                serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_uint32(&dst->stored_prekeys, serialized + w,
                                serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_bytes_array(dst->mac, sizeof(dst->mac), serialized + w,
                                     serialized_len - w)) {
    return OTRNG_ERROR;
  }

  w += sizeof(dst->mac);

  return OTRNG_SUCCESS;
}

INTERNAL
void otrng_prekey_storage_status_message_destroy(
    otrng_prekey_storage_status_message_s *msg) {
  if (!msg) {
    return;
  }

  msg->client_instance_tag = 0;
  msg->stored_prekeys = 0;
  sodium_memzero(msg->mac, sizeof(msg->mac));
}

INTERNAL
void otrng_prekey_publication_message_destroy(
    otrng_prekey_publication_message_s *msg) {
  if (!msg) {
    return;
  }

  if (msg->prekey_messages) {
    for (int i = 0; i < msg->num_prekey_messages; i++) {
      free(msg->prekey_messages[i]);
    }

    free(msg->prekey_messages);
    msg->prekey_messages = NULL;
  }

  otrng_client_profile_free(msg->client_profile);
  msg->client_profile = NULL;

  otrng_prekey_profile_free(msg->prekey_profile);
  msg->prekey_profile = NULL;
}

INTERNAL otrng_result otrng_prekey_ensemble_retrieval_message_deserialize(
    otrng_prekey_ensemble_retrieval_message_s *dst, const uint8_t *serialized,
    size_t serialized_len) {
  size_t w = 0;
  size_t read = 0;

  uint8_t message_type = 0;
  if (!otrng_parse_header(&message_type, serialized, serialized_len, &w)) {
    return OTRNG_ERROR;
  }

  if (message_type != OTRNG_PREKEY_ENSEMBLE_RETRIEVAL_MSG) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->instance_tag, serialized + w,
                                serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  uint8_t l;
  if (!otrng_deserialize_uint8(&l, serialized + w, serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  dst->ensembles = malloc(sizeof(prekey_ensemble_s *) * l);
  if (!dst->ensembles) {
    return OTRNG_ERROR;
  }

  dst->num_ensembles = l;

  for (int i = 0; i < l; i++) {
    dst->ensembles[i] = malloc(sizeof(prekey_ensemble_s));
    if (!dst->ensembles[i]) {
      return OTRNG_ERROR;
    }

    if (!otrng_prekey_ensemble_deserialize(dst->ensembles[i], serialized + w,
                                           serialized_len - w, &read)) {
      return OTRNG_ERROR;
    }

    w += read;
  }

  return OTRNG_SUCCESS;
}

INTERNAL
void otrng_prekey_ensemble_retrieval_message_destroy(
    otrng_prekey_ensemble_retrieval_message_s *msg) {
  if (!msg) {
    return;
  }

  if (msg->ensembles) {
    for (int i = 0; i < msg->num_ensembles; i++) {
      otrng_prekey_ensemble_free(msg->ensembles[i]);
    }
    free(msg->ensembles);
  }

  msg->ensembles = NULL;
}
