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
#include "deserialize.h"
#include "fingerprint.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"

#include <libotr/b64.h>

API otrng_prekey_client_s *
otrng_prekey_client_new(const char *server, const char *our_identity,
                        uint32_t instance_tag, const otrng_keypair_s *keypair,
                        const client_profile_s *profile) {
  if (!server) {
    return NULL;
  }

  if (!our_identity) {
    return NULL;
  }

  if (!instance_tag) {
    return NULL;
  }

  if (!profile) {
    return NULL;
  }

  otrng_prekey_client_s *ret = malloc(sizeof(otrng_prekey_client_s));
  if (!ret) {
    return NULL;
  }

  ret->instance_tag = instance_tag;
  ret->client_profile = profile;
  ret->keypair = keypair;
  ret->server_identity = otrng_strdup(server);
  ret->our_identity = otrng_strdup(our_identity);
  otrng_ecdh_keypair_destroy(ret->ephemeral_ecdh);

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
}

static otrng_err prekey_decode(const char *message, uint8_t **buffer,
                               size_t *buffer_len) {
  size_t l = strlen(message);

  if (!l || '.' != message[l - 1]) {
    return OTRNG_ERROR;
  }

  *buffer = malloc(((l - 1 + 3) / 4) * 3);
  if (!*buffer) {
    return OTRNG_ERROR;
  }

  *buffer_len = otrl_base64_decode(*buffer, message, l - 1);
  return OTRNG_SUCCESS;
}

static char *prekey_encode(const uint8_t *buffer, size_t buffer_len) {
  size_t base64_len = ((buffer_len + 2) / 3) * 4;
  char *ret = malloc(base64_len + 2);
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
  otrng_err success =
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
otrng_prekey_client_request_storage_status(otrng_prekey_client_s *client) {
  return start_dake_and_then_send(client,
                                  OTRNG_PREKEY_STORAGE_INFORMATION_REQUEST);
}

static uint8_t *otrng_prekey_client_get_expected_composite_phi(
    size_t *len, const otrng_prekey_client_s *client) {
  if (!client->server_identity || !client->our_identity) {
    return NULL;
  }

  size_t s =
      4 + strlen(client->server_identity) + 4 + strlen(client->our_identity);
  uint8_t *dst = malloc(s);
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

INTERNAL void kdf_init_with_usage(goldilocks_shake256_ctx_p hash,
                                  uint8_t usage) {
  hash_init_with_usage_and_domain_separation(hash, usage, "OTR-Prekey-Server");
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

  uint8_t *our_profile = NULL;
  size_t our_profile_len = 0;
  if (!otrng_client_profile_asprintf(&our_profile, &our_profile_len,
                                     client->client_profile)) {
    return otrng_false;
  }

  size_t tlen = 1 + 3 * 64 + 2 * ED448_POINT_BYTES;
  uint8_t *t = malloc(tlen);
  if (!t) {
    free(our_profile);
    return otrng_false;
  }

  *t = 0x0;
  size_t w = 1;

  goldilocks_shake256_ctx_p h1;
  kdf_init_with_usage(h1, 0x02);
  hash_update(h1, our_profile, our_profile_len);
  hash_final(h1, t + w, 64);
  hash_destroy(h1);
  free(our_profile);

  w += 64;

  // Both composite identity AND composite phi have the server's bare JID
  goldilocks_shake256_ctx_p h2;
  kdf_init_with_usage(h2, 0x03);
  hash_update(h2, msg->composite_identity, msg->composite_identity_len);
  hash_final(h2, t + w, 64);
  hash_destroy(h2);

  w += 64;

  w += otrng_serialize_ec_point(t + w, client->ephemeral_ecdh->pub);
  w += otrng_serialize_ec_point(t + w, msg->S);

  goldilocks_shake256_ctx_p h3;
  kdf_init_with_usage(h3, 0x04);
  hash_update(h3, composite_phi, composite_phi_len);
  hash_final(h3, t + w, 64);
  hash_destroy(h3);
  free(composite_phi);

  otrng_bool ret = otrng_rsig_verify_with_usage_and_domain(
      0x11, "OTR-Prekey-Server", msg->sigma, client->keypair->pub,
      msg->server_pub_key, client->ephemeral_ecdh->pub, t, tlen);
  free(t);

  return ret;
}

INTERNAL otrng_err
otrng_prekey_dake3_message_append_storage_information_request(
    otrng_prekey_dake3_message_s *msg, uint8_t prekey_mac[64]) {
  msg->message = malloc(2 + 1 + 64);
  msg->message_len = 67;
  if (!msg->message) {
    return OTRNG_ERROR;
  }
  uint8_t msg_type = 0x09;
  size_t w = 0;
  w += otrng_serialize_uint16(msg->message, OTRNG_PROTOCOL_VERSION_4);
  w += otrng_serialize_uint8(msg->message + w, msg_type);

  // MAC: KDF(usage_storage_info_MAC, prekey_mac_k || message type, 64)
  goldilocks_shake256_ctx_p hmac;
  kdf_init_with_usage(hmac, 0x0A);
  hash_update(hmac, prekey_mac, 64);
  hash_update(hmac, &msg_type, 1);
  hash_final(hmac, msg->message + w, 64);
  hash_destroy(hmac);

  return OTRNG_SUCCESS;
}

static char *send_dake3(const otrng_prekey_dake2_message_s *msg2,
                        otrng_prekey_client_s *client) {
  otrng_prekey_dake3_message_s msg[1];

  msg->client_instance_tag = client->instance_tag;

  size_t composite_phi_len = 0;
  uint8_t *composite_phi = otrng_prekey_client_get_expected_composite_phi(
      &composite_phi_len, client);

  uint8_t *our_profile = NULL;
  size_t our_profile_len = 0;
  if (!otrng_client_profile_asprintf(&our_profile, &our_profile_len,
                                     client->client_profile)) {
    return NULL;
  }

  size_t tlen = 1 + 3 * 64 + 2 * ED448_POINT_BYTES;
  uint8_t *t = malloc(tlen);
  if (!t) {
    free(our_profile);
    return NULL;
  }

  *t = 0x1;
  size_t w = 1;

  goldilocks_shake256_ctx_p h1;
  kdf_init_with_usage(h1, 0x05);
  hash_update(h1, our_profile, our_profile_len);
  hash_final(h1, t + w, 64);
  hash_destroy(h1);
  free(our_profile);

  w += 64;

  // Both composite identity AND composite phi have the server's bare JID
  goldilocks_shake256_ctx_p h2;
  kdf_init_with_usage(h2, 0x06);
  hash_update(h2, msg2->composite_identity, msg2->composite_identity_len);
  hash_final(h2, t + w, 64);
  hash_destroy(h2);

  w += 64;

  w += otrng_serialize_ec_point(t + w, client->ephemeral_ecdh->pub);
  w += otrng_serialize_ec_point(t + w, msg2->S);

  goldilocks_shake256_ctx_p h3;
  kdf_init_with_usage(h3, 0x07);
  hash_update(h3, composite_phi, composite_phi_len);
  hash_final(h3, t + w, 64);
  hash_destroy(h3);
  free(composite_phi);

  // H_a, sk_ha, {H_a, H_s, S}, t
  otrng_rsig_authenticate_with_usage_and_domain(
      0x11, "OTR-Prekey-Server", msg->sigma, client->keypair->priv,
      client->keypair->pub, client->keypair->pub, msg2->server_pub_key, msg2->S,
      t, tlen);
  free(t);

  // ECDH(i, S)
  uint8_t shared_secret[64] = {0};
  uint8_t ecdh_shared[ED448_POINT_BYTES] = {0};
  otrng_ecdh_shared_secret(ecdh_shared, client->ephemeral_ecdh, msg2->S);

  // SK = KDF(0x01, ECDH(i, S), 64)
  goldilocks_shake256_ctx_p hsk;
  kdf_init_with_usage(hsk, 0x01);
  hash_update(hsk, ecdh_shared, ED448_POINT_BYTES);
  hash_final(hsk, shared_secret, 64);
  hash_destroy(hsk);

  // prekey_mac_k = KDF(0x08, SK, 64)
  uint8_t prekey_mac[64] = {0};
  goldilocks_shake256_ctx_p hpk;
  kdf_init_with_usage(hpk, 0x08);
  hash_update(hpk, shared_secret, 64);
  hash_final(hpk, prekey_mac, 64);
  hash_destroy(hpk);

  // Put the MESSAGE in the message
  if (client->after_dake == OTRNG_PREKEY_STORAGE_INFORMATION_REQUEST) {
    if (!otrng_prekey_dake3_message_append_storage_information_request(
            msg, prekey_mac)) {
      return NULL;
    }
  } else {
    return NULL;
  }

  client->after_dake = 0;

  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
  otrng_err success =
      otrng_prekey_dake3_message_asprint(&serialized, &serialized_len, msg);
  otrng_prekey_dake3_message_destroy(msg);

  if (!success) {
    return NULL;
  }

  char *ret = prekey_encode(serialized, serialized_len);
  free(serialized);

  return ret;
}

static char *receive_dake2(const otrng_prekey_dake2_message_s *msg,
                           otrng_prekey_client_s *client) {
  if (!otrng_prekey_dake2_message_valid(msg, client)) {
    return NULL;
  }

  return send_dake3(msg, client);
}

static otrng_err parse_header(uint8_t *message_type, const uint8_t *buf,
                              size_t buflen, size_t *read) {
  size_t r = 0; // read
  size_t w = 0; // walked

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
  if (!parse_header(&message_type, decoded, decoded_len, NULL)) {
    return NULL;
  }

  char *ret = NULL;

  // DAKE 2
  if (message_type == 0x36) {
    otrng_prekey_dake2_message_s msg[1];

    if (!otrng_prekey_dake2_message_deserialize(msg, decoded, decoded_len)) {
      return NULL;
    }

    // TODO: check if it is for our instance tag

    ret = receive_dake2(msg, client);
    otrng_prekey_dake2_message_destroy(msg);
  }

  return ret;
}

API otrng_err otrng_prekey_client_receive(char **tosend, const char *server,
                                          const char *message,
                                          otrng_prekey_client_s *client) {

  // I should only process prekey server messages from who I am expecting.
  // This avoids treating a plaintext message "casa." from alice@itr.im as a
  // malformed prekey server message.
  if (strcmp(client->server_identity, server)) {
    return OTRNG_ERROR;
  }

  // If it fails to decode it was not a prekey server message.
  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
  if (!prekey_decode(message, &serialized, &serialized_len)) {
    return OTRNG_ERROR;
  }

  // Everything else, returns SUCCESS because we processed the message.
  // Even if there was na error processing it.
  *tosend = receive_decoded(serialized, serialized_len, client);
  free(serialized);

  return OTRNG_SUCCESS;
}

#define OTRNG_PREKEY_DAKE1_MSG 0x35
#define OTRNG_PREKEY_DAKE3_MSG 0x37

INTERNAL
otrng_err
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

INTERNAL otrng_err otrng_prekey_dake2_message_deserialize(
    otrng_prekey_dake2_message_s *dst, const uint8_t *serialized,
    size_t serialized_len) {

  size_t w = 0;
  size_t read = 0;

  uint8_t message_type = 0;
  if (!parse_header(&message_type, serialized, serialized_len, &w)) {
    return OTRNG_ERROR;
  }

  if (message_type != 0x36) {
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

  if (!otrng_deserialize_otrng_public_key(dst->server_pub_key, serialized + w,
                                          serialized_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  // Store the composite identity, so we can use it to generate `t`
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

  free(msg->composite_identity);
  msg->composite_identity = NULL;

  free(msg->server_identity);
  msg->server_identity = NULL;

  otrng_ec_point_destroy(msg->S);
  otrng_ring_sig_destroy(msg->sigma);
}

INTERNAL otrng_err
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
