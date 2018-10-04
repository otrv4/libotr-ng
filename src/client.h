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

#ifndef OTRNG_CLIENT_H
#define OTRNG_CLIENT_H

#ifndef S_SPLINT_S
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <libotr/context.h>
#pragma clang diagnostic pop
#endif

#include "list.h"
#include "otrng.h"
#include "prekey_client.h"
#include "shared.h"

// TODO: @client REMOVE
typedef struct otrng_conversation_s {
  void *conversation_id; /* Data in the messaging application context that
                          represents a conversation and should map directly to
                          it. For example, in libpurple-based apps (like
                          Pidgin) this could be a PurpleConversation */

  char *recipient;
  otrng_s *conn;
} otrng_conversation_s;

typedef struct otrng_client_id_s {
  const char *protocol;
  const char *account;
} otrng_client_id_s;

/* A client handle messages from/to a sender to/from multiple recipients. */
typedef struct otrng_client_s {
  list_element_s *conversations;

  otrng_prekey_client_s *prekey_client;

  otrng_client_id_s client_id;

  struct otrng_global_state_s *global_state;
  otrng_keypair_s *keypair;
  otrng_public_key *forging_key;

  // TODO: @client One or many?
  otrng_client_profile_s *client_profile;
  otrng_client_profile_s *exp_client_profile;
  otrng_prekey_profile_s *prekey_profile;
  otrng_prekey_profile_s *exp_prekey_profile;
  list_element_s *our_prekeys; /* otrng_stored_prekeys_s */

  unsigned int max_stored_msg_keys;
  unsigned int max_published_prekey_msg;
  unsigned int minimum_stored_prekey_msg;

  uint64_t profiles_extra_valid_time;
  uint64_t client_profile_exp_time;
  uint64_t prekey_profile_exp_time;

  otrng_bool (*should_heartbeat)(int last_sent);
  size_t padding;

  /* This flag will be set when there is anything that should be published
     to prekey servers */
  otrng_bool should_publish;
  otrng_bool is_publishing;
  uint32_t prekey_msgs_num_to_publish;

  // OtrlPrivKey *privkeyv3; // ???
  // otrng_instag_s *instag; // TODO: @client Store the instance tag here rather
  // than use v3 User State as a store for instance tags
} otrng_client_s;

typedef struct {
  uint32_t id;
  uint32_t sender_instance_tag;
  ecdh_keypair_s *our_ecdh;
  dh_keypair_s *our_dh;
} otrng_stored_prekeys_s;

API otrng_client_s *otrng_client_new(const otrng_client_id_s client_id);

API void otrng_client_free(otrng_client_s *client);

API otrng_conversation_s *otrng_client_get_conversation(int force_create,
                                                        const char *recipient,
                                                        otrng_client_s *client);

API otrng_bool otrng_conversation_is_encrypted(otrng_conversation_s *conv);

API otrng_bool otrng_conversation_is_finished(otrng_conversation_s *conv);

API char *otrng_client_query_message(const char *recipient, const char *msg,
                                     otrng_client_s *client);

API otrng_result otrng_client_send(char **new_msg, const char *msg,
                                   const char *recipient,
                                   otrng_client_s *client);

API otrng_result otrng_client_send_non_interactive_auth(
    char **new_msg, const prekey_ensemble_s *ensemble, const char *recipient,
    otrng_client_s *client);

API otrng_result otrng_client_send_fragment(otrng_message_to_send_s **new_msg,
                                            const char *msg, int mms,
                                            const char *recipient,
                                            otrng_client_s *client);

API otrng_result otrng_client_smp_start(char **to_send, const char *recipient,
                                        const unsigned char *question,
                                        const size_t q_len,
                                        const unsigned char *secret,
                                        size_t secret_len,
                                        otrng_client_s *client);

API otrng_result otrng_client_smp_respond(char **to_send, const char *recipient,
                                          const unsigned char *secret,
                                          size_t secret_len,
                                          otrng_client_s *client);

API otrng_result otrng_client_receive(char **new_msg, char **to_display,
                                      const char *msg, const char *recipient,
                                      otrng_client_s *client,
                                      otrng_bool *should_ignore);

API otrng_result otrng_client_disconnect(char **new_msg, const char *recipient,
                                         otrng_client_s *client);

API otrng_result otrng_expire_encrypted_session(char **new_msg,
                                                const char *recipient,
                                                int expiration_time,
                                                otrng_client_s *client);

/**
 * @brief Expires old fragments based on a threshhold in seconds.
 *
 *  @params
 *  [expiration_time] The expiration time in seconds
 *  [client] The otrng client instance.
 *
 * @return 0 if success, 2 if any error happened.
 *
 * @details Details around this function if any
 **/
API otrng_result otrng_client_expire_fragments(int expiration_time,
                                               otrng_client_s *client);

API otrng_result otrng_client_get_our_fingerprint(otrng_fingerprint fp,
                                                  const otrng_client_s *client);

API otrng_prekey_client_s *
otrng_client_get_prekey_client(const char *server_identity,
                               otrng_prekey_client_callbacks_s *callbacks,
                               otrng_client_s *client);

INTERNAL void otrng_client_store_my_prekey_message(
    uint32_t id, uint32_t instance_tag, const ecdh_keypair_s *ecdh_pair,
    const dh_keypair_s *dh_pair, otrng_client_s *client);

API prekey_message_s **
otrng_client_build_prekey_messages(uint8_t num_messages, otrng_client_s *client,
                                   ec_scalar **ecdh_keys, dh_mpi **dh_keys);

INTERNAL otrng_result otrng_client_get_account_and_protocol(
    char **account, char **protocol, const otrng_client_s *client);

INTERNAL OtrlPrivKey *
otrng_client_get_private_key_v3(const otrng_client_s *client);

INTERNAL otrng_keypair_s *otrng_client_get_keypair_v4(otrng_client_s *client);

INTERNAL otrng_result otrng_client_add_private_key_v4(
    otrng_client_s *client, const uint8_t sym[ED448_PRIVATE_BYTES]);

INTERNAL otrng_public_key *otrng_client_get_forging_key(otrng_client_s *client);

INTERNAL void otrng_client_ensure_forging_key(otrng_client_s *client);

INTERNAL otrng_result otrng_client_add_forging_key(
    otrng_client_s *client, const otrng_public_key forging_key);

API otrng_client_profile_s *
otrng_client_get_client_profile(otrng_client_s *client);

API otrng_client_profile_s *
otrng_client_build_default_client_profile(otrng_client_s *client);

API otrng_result otrng_client_add_client_profile(
    otrng_client_s *client, const otrng_client_profile_s *profile);

API const otrng_client_profile_s *
otrng_client_get_exp_client_profile(otrng_client_s *client);

API otrng_result otrng_client_add_exp_client_profile(
    otrng_client_s *client, const otrng_client_profile_s *exp_profile);

API otrng_prekey_profile_s *
otrng_client_get_prekey_profile(otrng_client_s *client);

API otrng_prekey_profile_s *
otrng_client_build_default_prekey_profile(otrng_client_s *client);

API otrng_result otrng_client_add_prekey_profile(
    otrng_client_s *client, const otrng_prekey_profile_s *profile);

API const otrng_prekey_profile_s *
otrng_client_get_exp_prekey_profile(otrng_client_s *client);

API otrng_result otrng_client_add_exp_prekey_profile(
    otrng_client_s *client, const otrng_prekey_profile_s *exp_profile);

INTERNAL unsigned int
otrng_client_get_instance_tag(const otrng_client_s *client);

INTERNAL otrng_result otrng_client_add_instance_tag(otrng_client_s *client,
                                                    unsigned int instag);

INTERNAL const otrng_stored_prekeys_s *
otrng_client_get_my_prekeys_by_id(uint32_t id, const otrng_client_s *client);

INTERNAL void
otrng_client_delete_my_prekey_message_by_id(uint32_t id,
                                            otrng_client_s *client);

API void otrng_client_set_padding(size_t granularity, otrng_client_s *client);

API void otrng_client_set_max_stored_msg_keys(unsigned int max_stored_msg_keys,
                                              otrng_client_s *client);

API otrng_result
otrng_client_get_max_published_prekey_msg(otrng_client_s *client);

API void otrng_client_state_set_max_published_prekey_msg(
    unsigned int max_published_prekey_msg, otrng_client_s *client);

API void otrng_client_state_set_minimum_stored_prekey_msg(
    unsigned int minimum_stored_prekey_msg, otrng_client_s *client);

API otrng_result
otrng_client_get_minimum_stored_prekey_msg(otrng_client_s *client);

API void
otrng_client_set_profiles_extra_valid_time(uint64_t profiles_extra_valid_time,
                                           otrng_client_s *client);

API otrng_result
otrng_client_get_client_profile_exp_time(otrng_client_s *client);

API void
otrng_client_set_client_profile_exp_time(uint64_t client_profile_exp_time,
                                         otrng_client_s *client);

API otrng_result
otrng_client_get_prekey_profile_exp_time(otrng_client_s *client);

API void
otrng_client_set_prekey_profile_exp_time(uint64_t prekey_profile_exp_time,
                                         otrng_client_s *client);

API void otrng_client_start_publishing(otrng_client_s *client);
API otrng_bool otrng_client_should_publish(otrng_client_s *client);
API void otrng_client_failed_published(otrng_client_s *client);
API void otrng_client_published(otrng_client_s *client);

/* tstatic int v3_privkey_generate(otrng_client_s *client, FILE *privf); */

/* tstatic int v3_instag_generate(otrng_client_s *client, FILE *privf); */

#ifdef DEBUG_API

API void otrng_client_debug_print(FILE *, int, otrng_client_s *);

API void otrng_conversation_debug_print(FILE *, int, otrng_conversation_s *);

/* API void otrng_client_debug_print(FILE *, int, otrng_client_s *); */
API void otrng_stored_prekeys_debug_print(FILE *, int,
                                          otrng_stored_prekeys_s *);

#endif

#ifdef OTRNG_CLIENT_PRIVATE
#endif

#endif
