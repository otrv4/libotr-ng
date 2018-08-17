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

#ifndef OTRNG_PREKEY_CLIENT_H
#define OTRNG_PREKEY_CLIENT_H

#include <stdint.h>

#include "auth.h"
#include "client_profile.h"
#include "constants.h"
#include "dake.h"
#include "prekey_ensemble.h"
#include "prekey_profile.h"
#include "shared.h"

typedef struct {
  uint32_t client_instance_tag;
  client_profile_p client_profile;
  ec_point_p I;
} otrng_prekey_dake1_message_s;

typedef struct {
  uint32_t client_instance_tag;

  uint8_t *composite_identity;
  size_t composite_identity_len;

  uint8_t *server_identity;
  size_t server_identity_len;
  otrng_public_key_p server_pub_key;
  ec_point_p S;
  ring_sig_p sigma;
} otrng_prekey_dake2_message_s;

typedef struct {
  uint32_t client_instance_tag;
  ring_sig_p sigma;
  uint8_t *message;
  size_t message_len;
} otrng_prekey_dake3_message_s;

typedef struct {
  uint8_t num_prekey_messages;
  dake_prekey_message_s **prekey_messages;
  client_profile_s *client_profile;
  otrng_prekey_profile_s *prekey_profile;
} otrng_prekey_publication_message_s;

typedef struct {
  uint32_t client_instance_tag;
  uint32_t stored_prekeys;
  uint8_t mac[DATA_MSG_MAC_BYTES];
} otrng_prekey_storage_status_message_s;

typedef struct {
  uint32_t client_instance_tag;
  uint8_t mac[DATA_MSG_MAC_BYTES];
} otrng_prekey_success_message_s;

typedef struct {
  uint32_t client_instance_tag;
  uint8_t mac[DATA_MSG_MAC_BYTES];
} otrng_prekey_failure_message_s;

typedef struct {
  char *identity;
  char *versions;
  uint32_t instance_tag;
} otrng_prekey_ensemble_query_retrieval_message_s;

typedef struct {
  uint32_t instance_tag;
  prekey_ensemble_s **ensembles;
  uint8_t num_ensembles;
} otrng_prekey_ensemble_retrieval_message_s;

typedef enum {
  OTRNG_PREKEY_STORAGE_INFORMATION_REQUEST = 1,
  OTRNG_PREKEY_PREKEY_PUBLICATION = 2,
} otrng_prekey_next_message_t;

typedef struct {
  void *ctx; // How calbacks can keep state
  void (*notify_error)(int error, void *ctx);
  void (*storage_status_received)(
      const otrng_prekey_storage_status_message_s *msg, void *ctx);
  void (*success_received)(void *ctx);
  void (*no_prekey_in_storage_received)(void *ctx);
  void (*prekey_ensembles_received)(prekey_ensemble_s *const *const ensembles,
                                    uint8_t num_ensembles, void *ctx);
  int (*build_prekey_publication_message)(
      otrng_prekey_publication_message_s *pub_msg, void *ctx);
} otrng_prekey_client_callbacks_s;

typedef struct {
  char *our_identity;
  uint32_t instance_tag;
  const otrng_keypair_s *keypair;
  const client_profile_s *client_profile;
  const otrng_prekey_profile_s *prekey_profile;
  ecdh_keypair_p ephemeral_ecdh;

  char *server_identity;
  otrng_public_key_p pub;

  uint8_t mac_key[MAC_KEY_BYTES];
  otrng_prekey_next_message_t after_dake;

  otrng_prekey_client_callbacks_s *callbacks;
} otrng_prekey_client_s;

API otrng_prekey_client_s *
otrng_prekey_client_new(const char *server, const char *our_identity,
                        uint32_t instance_tag, const otrng_keypair_s *keypair,
                        const client_profile_s *client_profile,
                        const otrng_prekey_profile_s *prekey_profile);

API void otrng_prekey_client_free(otrng_prekey_client_s *client);

API char *
otrng_prekey_client_request_storage_status(otrng_prekey_client_s *client);

API char *otrng_prekey_client_publish_prekeys(otrng_prekey_client_s *client);

API otrng_err otrng_prekey_client_receive(char **tosend, const char *server,
                                          const char *message,
                                          otrng_prekey_client_s *client);

INTERNAL otrng_err
otrng_prekey_dake1_message_asprint(uint8_t **serialized, size_t *serialized_len,
                                   const otrng_prekey_dake1_message_s *msg);

INTERNAL
void otrng_prekey_dake1_message_destroy(otrng_prekey_dake1_message_s *msg);

INTERNAL otrng_err otrng_prekey_dake2_message_deserialize(
    otrng_prekey_dake2_message_s *dst, const uint8_t *serialized,
    size_t serialized_len);

INTERNAL
void otrng_prekey_dake2_message_destroy(otrng_prekey_dake2_message_s *msg);

INTERNAL void kdf_init_with_usage(goldilocks_shake256_ctx_p hash,
                                  uint8_t usage);

INTERNAL otrng_err
otrng_prekey_dake3_message_append_storage_information_request(
    otrng_prekey_dake3_message_s *msg, uint8_t mac_key[MAC_KEY_BYTES]);

INTERNAL otrng_err
otrng_prekey_dake3_message_asprint(uint8_t **serialized, size_t *serialized_len,
                                   const otrng_prekey_dake3_message_s *msg);

INTERNAL
void otrng_prekey_dake3_message_destroy(otrng_prekey_dake3_message_s *msg);

INTERNAL otrng_err otrng_prekey_storage_status_message_deserialize(
    otrng_prekey_storage_status_message_s *dst, const uint8_t *serialized,
    size_t serialized_len);

INTERNAL
void otrng_prekey_storage_status_message_destroy(
    otrng_prekey_storage_status_message_s *msg);

INTERNAL
void otrng_prekey_publication_message_destroy(
    otrng_prekey_publication_message_s *msg);

API char *otrng_prekey_client_retrieve_prekeys(const char *identity,
                                               const char *versions,
                                               otrng_prekey_client_s *client);

INTERNAL otrng_err otrng_prekey_ensemble_query_retrieval_message_asprint(
    uint8_t **dst, size_t *len,
    const otrng_prekey_ensemble_query_retrieval_message_s *msg);

INTERNAL void otrng_prekey_ensemble_query_retrieval_message_destroy(
    otrng_prekey_ensemble_query_retrieval_message_s *msg);

INTERNAL otrng_err otrng_prekey_ensemble_retrieval_message_deserialize(
    otrng_prekey_ensemble_retrieval_message_s *dst, const uint8_t *serialized,
    size_t serialized_len);

INTERNAL
void otrng_prekey_ensemble_retrieval_message_destroy(
    otrng_prekey_ensemble_retrieval_message_s *msg);

#endif
