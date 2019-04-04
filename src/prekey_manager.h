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

/**
 * The functions in this file only operate on their arguments, and doesn't touch
 * any global state. It is safe to call these functions concurrently from
 * different threads, as long as arguments pointing to the same memory areas are
 * not used from different threads.
 *
 * Since the prekey client is a large subsystem, it touches on a lot of OTR
 * structures. Thus, to be safe, it's better to follow the same recommendations
 * as outlined in messaging.h
 */

#ifndef OTRNG_PREKEY_MANAGER_H
#define OTRNG_PREKEY_MANAGER_H

#include "error.h"
#include "keys.h"
#include "list.h"
#include "prekey_client_dake.h"
#include "prekey_client_messages.h"
#include "shared.h"

struct otrng_client_s;
struct otrng_prekey_request_s;

#define OTRNG_PREKEY_CLIENT_MALFORMED_MSG 1
#define OTRNG_PREKEY_CLIENT_INVALID_DAKE2 2
#define OTRNG_PREKEY_CLIENT_INVALID_STORAGE_STATUS 3
#define OTRNG_PREKEY_CLIENT_INVALID_SUCCESS 4
#define OTRNG_PREKEY_CLIENT_INVALID_FAILURE 5

typedef struct {
  unsigned int max_published_prekey_message;
  unsigned int minimum_stored_prekey_message;
  otrng_bool publish_client_profile;
  otrng_bool publish_prekey_profile;
} otrng_prekey_publication_policy_s;

typedef struct {
  /*@notnull@*/ char *domain;

  /*@notnull@*/ char *identity;
  otrng_fingerprint fpr;
} otrng_prekey_server_s;

typedef otrng_result (*otrng_prekey_next_message)(
    /*@notnull@*/ struct otrng_client_s *client,
    /*@notnull@*/ struct otrng_prekey_request_s *request,
    /*@notnull@*/ otrng_prekey_dake3_message_s *dake_3);

/*
  This struct represents one single DAKE client interaction with a prekey
  server.

  It will be created when needed to create a new request to a prekey server, and
  then destroyed after the request is done.
*/
typedef struct otrng_prekey_request_s {
  /*@null@*/ void *ctx;

  /* The request does NOT own the server instance */
  /*@notnull@*/ otrng_prekey_server_s *server;

  /*@notnull@*/ ecdh_keypair_s *ephemeral_ecdh;

  uint8_t mac_key[MAC_KEY_BYTES];
  uint8_t mac_proof_key[MAC_KEY_BYTES];

  /*@notnull@*/ otrng_prekey_next_message after_dake;
} otrng_prekey_request_s;

typedef struct {
  /*
     Returns the domain for a specific account. The caller does NOT take
     ownership of the memory for the returned value
  */
  const char *(*domain_for_account)(struct otrng_client_s *client, void *ctx);

  /*
     Will be called on any error condition. If the error is not associated with
     a specific request, ctx will be NULL. Otherwise it will be the ctx from the
     request
  */
  void (*notify_error)(struct otrng_client_s *client, int error, void *ctx);

  /*
    Will be called when the DAKE process is finished and a publication message
    needs to be put together. It's expected that
    otrng_prekey_add_prekey_messages_for_publication will be called at the end
    of this callback.
   */
  int (*build_prekey_publication_message)(
      struct otrng_client_s *client,
      otrng_prekey_publication_message_s *pub_msg, void *ctx);

  /*
     Will be called when we receive a success message, after a publication
     message
  */
  void (*success_received)(struct otrng_client_s *client, void *ctx);

  /*
     Will be called when we receive a failure message, after a publication
     message
  */
  void (*failure_received)(struct otrng_client_s *client, void *ctx);

  /*
    Will be called if the amount of prekey messages in storage is lower than the
    configured minimum amount for this prekey manager.
  */
  void (*low_prekey_messages_in_storage)(struct otrng_client_s *client,
                                         void *ctx);

  /*
    Will be called when the storage status message is received correctly.
  */
  void (*storage_status_received)(
      struct otrng_client_s *client,
      const otrng_prekey_storage_status_message_s *msg, void *ctx);

  void (*no_prekey_in_storage_received)(struct otrng_client_s *client,
                                        const char *identity);

  void (*prekey_ensembles_received)(struct otrng_client_s *client,
                                    prekey_ensemble_s *const *const ensembles,
                                    uint8_t num_ensembles,
                                    const char *identity);

} otrng_prekey_callbacks_s;

typedef struct {
  /* The persistent identiy we are using to send messages to prekey servers.
     It will be used to generate phi. */
  /*@notnull@*/ char *our_identity;

  /*@notnull@*/ struct otrng_client_s *client;

  /* This list contains otrng_prekey_server_s entries. An empty list will be
   * NULL */
  /*@null@*/ list_element_s *server_identities;

  /* This contains the prekey request when a request for an account is active -
   * otherwise it will be NULL */
  /*@null@*/ otrng_prekey_request_s *request_for_account;

  /* If request_for_account is not NULL, this contains the time when it was
   * set - this allows us to clean it, if it hasn't been removed for a while
   */
  time_t request_for_account_at;

  /*@null@*/ list_element_s *pending_fragments;

  /*@notnull@*/ otrng_prekey_publication_policy_s *publication_policy;

  /*@notnull@*/ otrng_prekey_callbacks_s *callbacks;
} otrng_prekey_manager_s;

/**
 * @brief Will start the process of publishing new data to the prekey server for
 *    this account
 *
 * @param [new_msg] the non-NULL location where the message to send on the
 *    network should be stored. the caller takes over ownership of the string
 *    pointed to by new_msg in the case of a successful return
 * @param [client] the non-NULL OTR client
 * @param [ctx]  the optional context for callbacks
 *
 * @return whether the operation was successful or not. if not successful,
 *    new_msg will point to NULL.
 **/
API otrng_result
otrng_prekey_publish(/*@notnull@*/ char **new_msg,
                     /*@notnull@*/ struct otrng_client_s *client,
                     /*@null@*/ void *ctx);

/**
 * @brief Will start the process of checking how many prekeys are currently
 *    stored on the server
 *
 * @param [new_msg] the non-NULL location where the message to send on the
 *    network should be stored. the caller takes over ownership of the string
 *    pointed to by new_msg in the case of a successful return
 * @param [client] the non-NULL OTR client
 * @param [ctx]  the optional context for callbacks
 *
 * @return whether the operation was successful or not. if not successful,
 *    new_msg will point to NULL.
 **/
API otrng_result otrng_prekey_request_storage_information(
    /*@notnull@*/ char **new_msg,
    /*@notnull@*/ struct otrng_client_s *client,
    /*@null@*/ void *ctx);

/**
 * @brief Starts the process of retrieving prekeys for a specific identity.
 *
 * @param [new_msg] the non-NULL location where the message to send on the
 *    network should be stored. The caller takes over ownership of the string
 *    pointed to by new_msg in the case of a successful return.
 * @param [client] the non-NULL OTR client
 * @param [identity_for] the non-NULL identity of the peer for whom to look up
 *    prekeys
 * @param [versions] the non-NULL string containing the valid versions for the
 *    prekeys requested
 **/
API void
otrng_prekey_retrieve_prekeys(/*@notnull@*/ char **new_msg,
                              /*@notnull@*/ struct otrng_client_s *client,
                              /*@notnull@*/ const char *identity_for,
                              /*@notnull@*/ const char *versions);

/**
 * @brief Should be called when receiving new messages. It will handle OTR
 *Prekey messages.
 *
 * @param [to_send] the non-NULL location where the message to send on the
 *    network should be stored. The caller takes over ownership of the string
 *    pointed to by to_send in the case of a successful return.
 * @param [client] the non-NULL OTR client
 * @param [from] the non-NULL identity of the peer who sent the message
 * @param [msg] the non-NULL message that was received.
 *
 * @return otrng_true if the message was handled, otrng_false if it was not.
 **/
API otrng_bool otrng_prekey_receive(/*@notnull@*/ char **to_send,
                                    /*@notnull@*/ struct otrng_client_s *client,
                                    /*@notnull@*/ const char *from,
                                    /*@notnull@*/ const char *msg);

/**
 * @brief Ensure's that a prekey manager has been created and initialized
 *
 * @param [client] the non-NULL OTR client
 * @param [identity] the non-NULL identity that will be used as the sender
 *    for its Prekey messages. The manager does NOT take ownership of the
 *    identity string.
 *
 * @return otrng_true if a new manager was created, otherwise otrng_false
 **/
API otrng_bool
otrng_prekey_ensure_manager(/*@notnull@*/ struct otrng_client_s *client,
                            /*@notnull@*/ const char *identity);

/**
 * @brief Will return otrng_true if we already know what server identity
 *    to use for this the specified domain.
 *
 * Note that this function assumes a prekey manager exists already.
 *
 * @param [client] the non-NULL OTR client
 * @param [domain] the non-NULL domain to look for a server identity for
 *
 * @return otrng_true if the domain is already covered by a server identity
 **/
API otrng_bool otrng_prekey_has_server_identity_for(
    /*@notnull@*/ const struct otrng_client_s *client,
    /*@notnull@*/ const char *domain);

/**
 * @brief Will return the otrng_prekey_server_s if we already know what server
 *identity to use for this the specified domain.
 *
 * Note that this function assumes a prekey manager exists already.
 *
 * @param [client] the non-NULL OTR client
 * @param [domain] the non-NULL domain to look for a server identity for
 *
 * @return the otrng_prekey_server_s if we have a server identity, or NULL
 **/
API /*@null@*/ otrng_prekey_server_s *otrng_prekey_get_server_identity_for(
    /*@notnull@*/ const struct otrng_client_s *client,
    /*@notnull@*/ const char *domain);

/**
 * @brief Will add the provided information as the canonical identity and public
 *    key for the domain in question.
 *
 * The public key is assumed to be fully trusted when this function is called,
 * thus a plugin should allow the user to verify the key _before_ submitting
 * it to this function.
 *
 * @param [client] the non-NULL OTR client
 * @param [domain] the non-NULL domain that this server identity is responsible
 *    for. The string is NOT taken ownership of.
 * @param [identity] the non-NULL identity for this server The string is NOT
 *    taken ownership of.
 * @param [fpr] the non-NULL fingerprint of the server
 **/
API void otrng_prekey_provide_server_identity_for(
    /*@notnull@*/ struct otrng_client_s *client,
    /*@notnull@*/ const char *domain,
    /*@notnull@*/ const char *identity,
    /*@notnull@*/ const otrng_fingerprint fpr);

/**
 * @brief Called from the plugin to specify that a publication message has been
 *    prepared and is ready for publication. It will most likely be called from
 *    the callback for build_prekey_publication_message.
 *
 * @param [client] the non-NULL OTR client
 * @param [msg] the non-NULL publication message that contains the data
 **/
API void otrng_prekey_add_prekey_messages_for_publication(
    /*@notnull@*/ struct otrng_client_s *client,
    /*@notnull@*/ otrng_prekey_publication_message_s *msg);

API void otrng_prekey_set_client_profile_publication(
    /*@notnull@*/ struct otrng_client_s *client);

API void otrng_prekey_set_prekey_profile_publication(
    /*@notnull@*/ struct otrng_client_s *client);

INTERNAL void
otrng_prekey_manager_free(/*@null@*/ otrng_prekey_manager_s *manager);

/**
 * @brief Should be called regularly to see that the request_for_account
 *    request hasn't expired.
 **/
INTERNAL void
otrng_prekey_check_account_request(/*@notnull@*/ struct otrng_client_s *client);

#ifdef OTRNG_PREKEY_MANAGER_PRIVATE

tstatic void dake3_message_append_storage_information_request(
    otrng_prekey_dake3_message_s *dake_3, uint8_t mac_key[MAC_KEY_BYTES]);
tstatic otrng_result
storage_request_after_dake(/*@notnull@*/ struct otrng_client_s *client,
                           /*@notnull@*/ otrng_prekey_request_s *request,
                           /*@notnull@*/ otrng_prekey_dake3_message_s *dake_3);

tstatic /*@null@*/ otrng_prekey_request_s *
create_prekey_request(otrng_prekey_server_s *server, void *ctx);

tstatic char *send_dake3(struct otrng_client_s *client,
                         otrng_prekey_request_s *request,
                         const otrng_prekey_dake2_message_s *msg);

#endif

#endif
