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

#ifndef OTRNG_PREKEY_CLIENT_H
#define OTRNG_PREKEY_CLIENT_H

#include "constants.h"
#include "prekey_ensemble.h"
#include "prekey_message.h"
#include "prekey_profile.h"
#include "shared.h"

struct otrng_client_s;

#define OTRNG_PREKEY_DAKE1_MSG 0x35
#define OTRNG_PREKEY_DAKE2_MSG 0x36
#define OTRNG_PREKEY_DAKE3_MSG 0x37
#define OTRNG_PREKEY_STORAGE_INFO_REQ_MSG 0x09
#define OTRNG_PREKEY_ENSEMBLE_QUERY_RETRIEVAL_MSG 0x10
#define OTRNG_PREKEY_STORAGE_STATUS_MSG 0x0B
#define OTRNG_PREKEY_SUCCESS_MSG 0x06
#define OTRNG_PREKEY_FAILURE_MSG 0x05
#define OTRNG_PREKEY_ENSEMBLE_RETRIEVAL_MSG 0x13
#define OTRNG_PREKEY_NO_PREKEY_IN_STORAGE_MSG 0x0E
#define OTRNG_PREKEY_PUBLICATION_MSG 0x08

#define OTRNG_DAKE3_MSG_LEN 67
#define OTRNG_PREKEY_SUCCESS_MSG_LEN 71
#define OTRNG_PREKEY_FAILURE_MSG_LEN 71

typedef enum {
  OTRNG_PREKEY_STORAGE_INFORMATION_REQUEST = 1,
  OTRNG_PREKEY_PREKEY_PUBLICATION = 2,
} otrng_prekey_next_message;

typedef struct {
  uint32_t client_instance_tag;
  otrng_client_profile_s *client_profile;
  ec_point I;
} otrng_prekey_dake1_message_s;

typedef struct {
  uint32_t client_instance_tag;

  uint8_t *composite_identity;
  size_t composite_identity_len;

  uint8_t *server_identity;
  size_t server_identity_len;
  otrng_public_key server_pub_key;
  ec_point S;
  ring_sig_s *sigma;
} otrng_prekey_dake2_message_s;

typedef struct {
  uint32_t client_instance_tag;
  ring_sig_s *sigma;
  uint8_t *msg;
  size_t msg_len;
} otrng_prekey_dake3_message_s;

typedef struct {
  uint8_t num_prekey_messages;
  prekey_message_s **prekey_messages;
  otrng_client_profile_s *client_profile;
  otrng_prekey_profile_s *prekey_profile;
} otrng_prekey_publication_message_s;

typedef struct {
  uint32_t client_instance_tag;
  uint32_t stored_prekeys;
  uint8_t mac[DATA_MSG_MAC_BYTES];
} otrng_prekey_storage_status_message_s;

typedef struct {
  uint32_t client_instance_tag;
  uint8_t success_mac[DATA_MSG_MAC_BYTES];
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

typedef struct {
  unsigned int max_published_prekey_message;
  unsigned int minimum_stored_prekey_message;
  otrng_bool publish_client_profile;
  otrng_bool publish_prekey_profile;
} otrng_prekey_publication_policy_s;

typedef struct {
  void *ctx; /* How calbacks can keep state */
  void (*notify_error)(struct otrng_client_s *client, int error, void *ctx);
  void (*storage_status_received)(
      struct otrng_client_s *client,
      const otrng_prekey_storage_status_message_s *msg, void *ctx);
  void (*success_received)(struct otrng_client_s *client, void *ctx);
  void (*failure_received)(struct otrng_client_s *client, void *ctx);
  void (*no_prekey_in_storage_received)(struct otrng_client_s *client,
                                        void *ctx);
  void (*low_prekey_messages_in_storage)(struct otrng_client_s *client,
                                         char *server_identity, void *ctx);
  void (*prekey_ensembles_received)(struct otrng_client_s *client,
                                    prekey_ensemble_s *const *const ensembles,
                                    uint8_t num_ensembles, void *ctx);
  int (*build_prekey_publication_message)(
      struct otrng_client_s *client,
      otrng_prekey_publication_message_s *pub_msg,
      otrng_prekey_publication_policy_s *publication_policy, void *ctx);
} otrng_prekey_client_callbacks_s;

typedef struct {
  char *our_identity;
  uint32_t instance_tag;
  const otrng_keypair_s *keypair;
  const otrng_client_profile_s *client_profile;
  const otrng_prekey_profile_s *prekey_profile;
  ecdh_keypair_s *ephemeral_ecdh;

  otrng_prekey_publication_policy_s *publication_policy;

  char *server_identity;
  otrng_public_key pub;

  uint8_t mac_key[MAC_KEY_BYTES];
  otrng_prekey_next_message after_dake;

  otrng_prekey_client_callbacks_s *callbacks;
} otrng_prekey_client_s;

API void otrng_prekey_client_init(otrng_prekey_client_s *prekey_client,
                                  const char *server, const char *our_identity,
                                  uint32_t instance_tag,
                                  const otrng_keypair_s *keypair,
                                  const otrng_client_profile_s *client_profile,
                                  const otrng_prekey_profile_s *prekey_profile,
                                  unsigned int max_published_prekey_message,
                                  unsigned int minimum_stored_prekey_message);

API otrng_prekey_client_s *otrng_prekey_client_new(void);

API void otrng_prekey_client_free(otrng_prekey_client_s *client);

API char *
otrng_prekey_client_request_storage_information(otrng_prekey_client_s *client);

API char *otrng_prekey_client_publish(otrng_prekey_client_s *client);

API otrng_bool otrng_prekey_client_receive(char **to_send, const char *server,
                                           const char *msg,
                                           struct otrng_client_s *client);

API void otrng_prekey_client_set_prekey_profile_publication(
    otrng_prekey_client_s *client);

API void otrng_prekey_client_set_client_profile_publication(
    otrng_prekey_client_s *client);

INTERNAL
otrng_prekey_dake2_message_s *otrng_prekey_dake2_message_new(void);

INTERNAL
otrng_prekey_dake3_message_s *otrng_prekey_dake3_message_new(void);

API char *otrng_prekey_client_retrieve_prekeys(const char *identity,
                                               const char *versions,
                                               otrng_prekey_client_s *client);

INTERNAL otrng_result otrng_prekey_success_message_deserialize(
    otrng_prekey_success_message_s *dst, const uint8_t *source,
    size_t source_len);

API void otrng_prekey_client_add_prekey_messages_for_publication(
    struct otrng_client_s *client, otrng_prekey_publication_message_s *msg);

#ifdef OTRNG_PREKEY_CLIENT_PRIVATE

tstatic char *send_dake3(const otrng_prekey_dake2_message_s *dake_2,
                         struct otrng_client_s *client);

tstatic otrng_result otrng_prekey_dake1_message_serialize(
    uint8_t **ser, size_t *ser_len, const otrng_prekey_dake1_message_s *msg);

tstatic void
otrng_prekey_dake1_message_destroy(otrng_prekey_dake1_message_s *msg);

tstatic void otrng_prekey_dake2_message_init(otrng_prekey_dake2_message_s *msg);

tstatic otrng_result otrng_prekey_dake2_message_deserialize(
    otrng_prekey_dake2_message_s *dst, const uint8_t *ser, size_t ser_len);

tstatic void
otrng_prekey_dake2_message_destroy(otrng_prekey_dake2_message_s *msg);

tstatic otrng_result
otrng_prekey_dake3_message_append_storage_information_request(
    otrng_prekey_dake3_message_s *msg, uint8_t mac_key[MAC_KEY_BYTES]);

tstatic otrng_result otrng_prekey_dake3_message_serialize(
    uint8_t **ser, size_t *ser_len, const otrng_prekey_dake3_message_s *msg);

tstatic void otrng_prekey_dake3_message_init(otrng_prekey_dake3_message_s *msg);

tstatic void
otrng_prekey_dake3_message_destroy(otrng_prekey_dake3_message_s *msg);

tstatic otrng_result otrng_prekey_storage_status_message_deserialize(
    otrng_prekey_storage_status_message_s *dst, const uint8_t *ser,
    size_t ser_len);

tstatic void otrng_prekey_storage_status_message_destroy(
    otrng_prekey_storage_status_message_s *msg);

tstatic otrng_result otrng_prekey_ensemble_retrieval_message_deserialize(
    otrng_prekey_ensemble_retrieval_message_s *dst, const uint8_t *ser,
    size_t ser_len);

tstatic void otrng_prekey_ensemble_retrieval_message_destroy(
    otrng_prekey_ensemble_retrieval_message_s *msg);

#endif

#endif
