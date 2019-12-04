/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
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

/**
 * TODO: concurrency comment
 */

#ifndef OTRNG_PREKEY_CLIENT_MESSAGES_H
#define OTRNG_PREKEY_CLIENT_MESSAGES_H

#include "shared.h"

#include "client_profile.h"
#include "prekey_ensemble.h"
#include "prekey_message.h"
#include "prekey_profile.h"

#define OTRNG_PREKEY_FAILURE_MSG 0x05
#define OTRNG_PREKEY_SUCCESS_MSG 0x06
#define OTRNG_PREKEY_PUBLICATION_MSG 0x08
#define OTRNG_PREKEY_STORAGE_INFO_REQ_MSG 0x09
#define OTRNG_PREKEY_STORAGE_STATUS_MSG 0x0B
#define OTRNG_PREKEY_NO_PREKEY_IN_STORAGE_MSG 0x0E
#define OTRNG_PREKEY_ENSEMBLE_QUERY_RETRIEVAL_MSG 0x10
#define OTRNG_PREKEY_ENSEMBLE_RETRIEVAL_MSG 0x13

#define OTRNG_PREKEY_SUCCESS_MSG_LEN 71
#define OTRNG_PREKEY_FAILURE_MSG_LEN 71

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
  char *identity;
  prekey_ensemble_s **ensembles;
  uint8_t num_ensembles;
} otrng_prekey_ensemble_retrieval_message_s;

INTERNAL otrng_result otrng_prekey_success_message_deserialize(
    otrng_prekey_success_message_s *dst, const uint8_t *source,
    size_t source_len);

INTERNAL otrng_result otrng_prekey_storage_status_message_deserialize(
    otrng_prekey_storage_status_message_s *dst, const uint8_t *ser,
    size_t ser_len);

INTERNAL void otrng_prekey_storage_status_message_destroy(
    otrng_prekey_storage_status_message_s *msg);

INTERNAL otrng_result otrng_prekey_ensemble_retrieval_message_deserialize(
    otrng_prekey_ensemble_retrieval_message_s *dst, const uint8_t *ser,
    size_t ser_len);

INTERNAL void otrng_prekey_ensemble_retrieval_message_destroy(
    otrng_prekey_ensemble_retrieval_message_s *msg);

INTERNAL void otrng_prekey_ensemble_query_retrieval_message_serialize(
    /*@notnull@*/ uint8_t **dst, /*@notnull@*/ size_t *len,
    /*@notnull@*/ const otrng_prekey_ensemble_query_retrieval_message_s *msg);

INTERNAL void otrng_prekey_ensemble_query_retrieval_message_destroy(
    /*@notnull@*/ otrng_prekey_ensemble_query_retrieval_message_s *msg);

INTERNAL /*@notnull@*/ otrng_prekey_publication_message_s *
otrng_prekey_publication_message_new(void);

INTERNAL void otrng_prekey_publication_message_destroy(
    /*@notnull@*/ otrng_prekey_publication_message_s *msg);

INTERNAL otrng_bool otrng_prekey_storage_status_message_valid(
    /*@notnull@*/ const otrng_prekey_storage_status_message_s *msg,
    /*@notnull@*/ const uint8_t mac_key[MAC_KEY_BYTES]);

#ifdef OTRNG_PREKEY_CLIENT_MESSAGES_PRIVATE

#endif

#endif
