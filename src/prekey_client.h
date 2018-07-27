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
#include "prekey_profile.h"
#include "shared.h"

typedef struct {
  uint32_t client_instance_tag;
  client_profile_p client_profile;
  ec_point_p I;
} otrng_prekey_dake1_message_s;

typedef struct {
  uint32_t client_instance_tag;
  uint8_t *server_identity;
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
  uint8_t num_prekeys;
  dake_prekey_message_s **prekey_messages;
  client_profile_s *client_profile;
  otrng_prekey_profile_s *prekey_profile;
  uint8_t mac[DATA_MSG_MAC_BYTES];
} otrng_prekey_publication_message_s;

typedef struct {
  uint8_t mac[DATA_MSG_MAC_BYTES];
} otrng_prekey_storage_information_request_message_s;

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

typedef enum {
  OTRNG_PREKEY_STORAGE_INFORMATION_REQUEST = 1,
} otrng_prekey_next_message_t;

typedef struct {
  uint32_t instance_tag;
  const client_profile_s *client_profile;
  ecdh_keypair_p ephemeral_ecdh;

  char *server_identity;
  otrng_prekey_next_message_t after_dake;
} otrng_prekey_client_s;

API otrng_prekey_client_s *
otrng_prekey_client_new(const char *server, uint32_t instance_tag,
                        const client_profile_s *profile);

API void otrng_prekey_client_free(otrng_prekey_client_s *client);

API char *
otrng_prekey_client_request_storage_status(otrng_prekey_client_s *client);

INTERNAL
otrng_err
otrng_prekey_dake1_message_asprint(uint8_t **serialized, size_t *serialized_len,
                                   const otrng_prekey_dake1_message_s *msg);

INTERNAL
void otrng_prekey_dake1_message_destroy(otrng_prekey_dake1_message_s *msg);

#endif
