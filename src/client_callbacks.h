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

#ifndef OTRNG_CLIENT_CALLBACKS_H
#define OTRNG_CLIENT_CALLBACKS_H

#include "fingerprint.h"
#include "shared.h"
#include "str.h"

typedef enum {
  OTRNG_SMP_EVENT_NONE = 0,
  OTRNG_SMP_EVENT_ASK_FOR_SECRET = 1,
  OTRNG_SMP_EVENT_ASK_FOR_ANSWER = 2,
  OTRNG_SMP_EVENT_IN_PROGRESS = 3,
  OTRNG_SMP_EVENT_SUCCESS = 4,
  OTRNG_SMP_EVENT_CHEATED = 5,
  OTRNG_SMP_EVENT_FAILURE = 6,
  OTRNG_SMP_EVENT_ABORT = 7,
  OTRNG_SMP_EVENT_ERROR = 8,
} otrng_smp_event;

typedef enum {
  OTRNG_ERROR_NONE = 0,
  OTRNG_ERROR_UNREADABLE_EVENT = 1,
  OTRNG_ERROR_NOT_IN_PRIVATE_EVENT = 2,
  OTRNG_ERROR_MALFORMED_EVENT = 4,
} otrng_error_event;

typedef enum {
  OTRNG_MSG_EVENT_NONE = 0,
  /* Flagged when trying to send a plaintext message with a policy that requires
     encryption. */
  OTRNG_MSG_EVENT_ENCRYPTION_REQUIRED = 1,
  /* Flagged when there was an error while trying to encrypt a data message. */
  OTRNG_MSG_EVENT_ENCRYPTION_ERROR = 2,
  /* Flagged when a heartbeat message is received. */
  OTRNG_MSG_EVENT_HEARTBEAT_RECEIVED = 3,
  /* Flagged when a heartbeat message is sent. */
  OTRNG_MSG_EVENT_HEARTBEAT_SENT = 4,
  OTRNG_MSG_EVENT_WRONG_INSTANCE = 5,
  /* Flagged when trying to publish too many prekey messages. */
  OTRNG_MSG_EVENT_INCORRECT_AMMOUNT_PREKEYS = 6,
  /* Flagged when trying to send a data message not in an encrypted state. */
  OTRNG_MSG_EVENT_SENDING_NOT_IN_ENCRYPTED_STATE = 7,
  /* Flagged when received an invalid data message. */
  OTRNG_MSG_EVENT_INVALID_MSG = 8,
  /* Flagged when received a prekey message with an incorrect instance tag. */
  OTRNG_MSG_EVENT_MALFORMED_PREKEY = 9,
  /* Flagged when trying to store more message keys than allowed. */
  OTRNG_MSG_EVENT_MSG_KEYS_STORAGE_FULL = 10,
  /* Flagged when receiving a message unencrypted. */
  OTRNG_MSG_EVENT_RCV_UNENCRYPTED = 11,
  /* Flagged when received a data message in the FINISH state. */
  OTRNG_MSG_EVENT_CONNECTION_ENDED = 12,
} otrng_msg_event;

typedef enum {
  /* Tear down the session but don't restart it */
  OTRNG_SESSION_EXPIRY_DO_TEARDOWN = 0,
  /* Don't do anything */
  OTRNG_SESSION_EXPIRY_DO_NOTHING = 1,
  /* These options are not implemented yet */
  /* /\* Tear down the session and restart by sending a query message *\/ */
  /* OTRNG_SESSION_EXPIRY_DO_RESTART_WITH_QUERY = 2, */
  /* /\* Tear down the session and restart by sending an identity message *\/ */
  /* OTRNG_SESSION_EXPIRY_DO_RESTART_WITH_IDENTITY = 3, */
} otrng_expiration_policy;

typedef struct otrng_shared_session_state_s {
  char *identifier1;
  char *identifier2;
  char *password;
} otrng_shared_session_state_s;

typedef struct otrng_policy_s {
  uint8_t allows;
  uint8_t type;
} otrng_policy_s;

typedef enum {
  /* This error message type will be used when it's impossible to start a
     conversation through a query message */
  OTRNG_ERROR_MESSAGE_FAILURE_START = 0,
} otrng_localized_error_message_type;

/* Forward declaration */
struct otrng_client_s;
struct otrng_s;
struct otrng_client_id_s;

typedef struct otrng_client_callbacks_s {
  /* REQUIRED */
  void (*create_instag)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*create_privkey_v3)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*create_privkey_v4)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*create_forging_key)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*create_client_profile)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*store_expired_client_profile)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*load_expired_client_profile)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*store_expired_prekey_profile)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*load_expired_prekey_profile)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*create_prekey_profile)(struct otrng_client_s *client);

  /* OPTIONAL */
  void (*gone_secure)(const struct otrng_s *);

  /* OPTIONAL */
  void (*gone_insecure)(const struct otrng_s *);

  /* OPTIONAL */
  void (*fingerprint_seen)(const otrng_fingerprint, const struct otrng_s *);

  /* OPTIONAL */
  void (*fingerprint_seen_v3)(const otrng_fingerprint_v3,
                              const struct otrng_s *);

  /* Update the authentication UI and prompt the user to enter a shared secret.
   *      The sender application should call otrl_message_initiate_smp,
   *      passing NULL as the question.
   *      When the receiver application resumes the SM protocol by calling
   *      otrl_message_respond_smp with the secret answer. */
  /* OPTIONAL */
  void (*smp_ask_for_secret)(const struct otrng_s *);

  /* Same as smp_ask_for_secret but sender calls otrl_message_initiate_smp_q
   * instead) */
  /* OPTIONAL */
  void (*smp_ask_for_answer)(const uint8_t *question, const size_t q_len,
                             const struct otrng_s *);

  /* Update the authentication UI with respect to SMP events
   * These are the possible events:
   * - OTRL_SMPEVENT_CHEATED
   *      abort the current auth and update the auth progress dialog
   *      with progress_percent. otrl_message_abort_smp should be called to
   *      stop the SM protocol.
   * - OTRL_SMPEVENT_INPROGRESS       and
   *   OTRL_SMPEVENT_SUCCESS          and
   *   OTRL_SMPEVENT_FAILURE          and
   *   OTRL_SMPEVENT_ABORT
   *      update the auth progress dialog with progress_percent
   * - OTRL_SMPEVENT_ERROR
   *      (same as OTRL_SMPEVENT_CHEATED)
   * */
  /* OPTIONAL */
  void (*smp_update)(const otrng_smp_event event,
                     const uint8_t progress_percent, const struct otrng_s *);

  /* REQUIRED */
  /* Display the error message with respect to the received event
   */
  void (*display_error_message)(const otrng_error_event event,
                                string_p *to_display, const struct otrng_s *);

  /* REQUIRED */
  /* Handle diverse events
   */
  void (*handle_event)(const otrng_msg_event event);

  /* OPTIONAL */
  /* We received a request from the buddy to use the current "extra"
   * symmetric key.  The key will be passed in symkey, of length
   * EXTRA_SYMMETRIC_KEY_BYTES.  The requested use, as well as use-specific
   * data will be passed so that the applications can communicate other
   * information (some id for the data transfer, for example). */
  void (*received_extra_symm_key)(const struct otrng_s *, unsigned int use,
                                  const unsigned char *use_data,
                                  size_t use_data_len,
                                  const unsigned char *extra_sym_key);

  /* Provide a shared session state from the underlying network protocol.
   * This is used to authenticate the DAKE. Optionally, a password can be added
   * to this shared session state.
   * The protocol will take care of freeing the members of this struct. */
  /* REQUIRED */
  otrng_shared_session_state_s (*get_shared_session_state)(
      const struct otrng_s *conv);

  /* REQUIRED */
  void (*load_privkey_v4)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*load_privkey_v3)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*load_client_profile)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*load_prekey_profile)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*store_client_profile)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*store_prekey_profile)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*load_prekey_messages)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*store_prekey_messages)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*store_privkey_v4)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*store_privkey_v3)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*load_forging_key)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*store_forging_key)(struct otrng_client_s *client);

  /* OPTIONAL */
  /* Return the OTRv4 policy for the given client. */
  otrng_policy_s (*define_policy)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*store_fingerprints_v4)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*load_fingerprints_v4)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*store_fingerprints_v3)(struct otrng_client_s *client);

  /* REQUIRED */
  void (*load_fingerprints_v3)(struct otrng_client_s *client);

  /* OPTIONAL - the string returned will transfer ownership to the caller */
  string_p (*localized_error_message)(
      struct otrng_client_s *client,
      otrng_localized_error_message_type message_type);

  /* REQUIRED */
  uint32_t (*session_expiration_time_for)(const struct otrng_s *);

  /* OPTIONAL - if not provided, will tear down the session */
  otrng_expiration_policy (*session_expiration_policy_for)(const struct otrng_s *);

  /* REQUIRED - Send the given IM to the given conversation */
  void (*inject_message)(const struct otrng_s *, const string_p message);
} otrng_client_callbacks_s;

INTERNAL int
otrng_client_callbacks_ensure_needed_exist(const otrng_client_callbacks_s *cb);

INTERNAL void
otrng_client_callbacks_create_instag(const otrng_client_callbacks_s *cb,
                                     struct otrng_client_s *client);

INTERNAL void
otrng_client_callbacks_gone_secure(const otrng_client_callbacks_s *cb,
                                   const struct otrng_s *conv);

INTERNAL void
otrng_client_callbacks_gone_insecure(const otrng_client_callbacks_s *cb,
                                     const struct otrng_s *conv);

INTERNAL void
otrng_client_callbacks_fingerprint_seen(const otrng_client_callbacks_s *cb,
                                        const otrng_fingerprint fp,
                                        const struct otrng_s *conv);

INTERNAL void
otrng_client_callbacks_fingerprint_seen_v3(const otrng_client_callbacks_s *cb,
                                           const otrng_fingerprint_v3 fp,
                                           const struct otrng_s *conv);

INTERNAL void
otrng_client_callbacks_smp_ask_for_answer(const otrng_client_callbacks_s *cb,
                                          const char *question,
                                          const struct otrng_s *conv);

INTERNAL void
otrng_client_callbacks_smp_ask_for_secret(const otrng_client_callbacks_s *cb,
                                          const struct otrng_s *conv);

INTERNAL void otrng_client_callbacks_smp_update(
    const otrng_client_callbacks_s *cb, const otrng_smp_event event,
    const uint8_t progress_percent, const struct otrng_s *conv);

INTERNAL void otrng_client_callbacks_display_error_message(
    const otrng_client_callbacks_s *cb, const otrng_error_event event,
    string_p *to_display, const struct otrng_s *conv);

INTERNAL void
otrng_client_callbacks_handle_event(const otrng_client_callbacks_s *cb,
                                    const otrng_msg_event event);

INTERNAL otrng_policy_s otrng_client_callbacks_define_policy(
    const otrng_client_callbacks_s *cb, struct otrng_client_s *client);

#ifdef DEBUG_API
API void otrng_client_callbacks_debug_print(FILE *, int,
                                            const otrng_client_callbacks_s *);
#endif

#ifdef OTRNG_CLIENT_CALLBACKS_PRIVATE
#endif

#endif
