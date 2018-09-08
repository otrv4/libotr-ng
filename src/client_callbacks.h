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

#ifndef OTRNG_CLIENT_CALLBACKS_H
#define OTRNG_CLIENT_CALLBACKS_H

#include "fingerprint.h"
#include "shared.h"

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
} otrng_smp_event_t;

typedef struct otrng_conversation_state_s otrng_client_conversation_s;

typedef struct otrng_shared_session_state_s {
  char *identifier1;
  char *identifier2;
  char *password;
} otrng_shared_session_state_s;

// Forward declaration
struct otrng_client_state_s;

typedef struct otrng_client_callbacks_s {
  /* Get account and protocol from a given client_id */
  otrng_result (*get_account_and_protocol)(char **account, char **protocol,
                                           const void *client_id);

  /* Create an instance tag */
  void (*create_instag)(const void *client_opdata);

  /* Create a OTRv3 private key */
  void (*create_privkey_v3)(const void *client_opdata);

  /* Create a OTRv4 private key */
  void (*create_privkey_v4)(const void *client_opdata);

  /* Create a client profile */
  void (*create_client_profile)(struct otrng_client_state_s *state,
                                const void *client_opdata);

  /* Create a prekey profile */
  void (*create_prekey_profile)(struct otrng_client_state_s *state,
                                const void *client_opdata);

  /* Create a shared prekey */
  void (*create_shared_prekey)(struct otrng_client_state_s *state,
                               const void *client_opdata);

  /* A connection has entered a secure state. */
  void (*gone_secure)(const otrng_client_conversation_s *);

  /* A connection has left a secure state. */
  void (*gone_insecure)(const otrng_client_conversation_s *);

  /* A fingerprint was seen in this connection. */
  void (*fingerprint_seen)(const otrng_fingerprint_p,
                           const otrng_client_conversation_s *);

  /* A v3 fingerprint was seen in this connection. */
  void (*fingerprint_seen_v3)(const otrng_fingerprint_v3_p,
                              const otrng_client_conversation_s *);

  /* Update the authentication UI and prompt the user to enter a shared secret.
   *      The sender application should call otrl_message_initiate_smp,
   *      passing NULL as the question.
   *      When the receiver application resumes the SM protocol by calling
   *      otrl_message_respond_smp with the secret answer. */
  void (*smp_ask_for_secret)(const otrng_client_conversation_s *);

  /* Same as smp_ask_for_secret but sender calls otrl_message_initiate_smp_q
   * instead) */
  void (*smp_ask_for_answer)(const uint8_t *question, const size_t q_len,
                             const otrng_client_conversation_s *);

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
  void (*smp_update)(const otrng_smp_event_t event,
                     const uint8_t progress_percent,
                     const otrng_client_conversation_s *);

  /* We received a request from the buddy to use the current "extra"
   * symmetric key.  The key will be passed in symkey, of length
   * EXTRA_SYMMETRIC_KEY_BYTES.  The requested use, as well as use-specific
   * data will be passed so that the applications can communicate other
   * information (some id for the data transfer, for example). */
  void (*received_extra_symm_key)(const otrng_client_conversation_s *,
                                  unsigned int use,
                                  const unsigned char *use_data,
                                  size_t use_data_len,
                                  const unsigned char *extra_sym_key);

  /* Provide a shared session state from the underlying network protocol.
   * This is used to authenticate the DAKE. Optionally, a password can be added
   * to this shared session state.
   * The protocol will take care of freeing the members of this struct. */
  otrng_shared_session_state_s (*get_shared_session_state)(
      const otrng_client_conversation_s *conv);

} otrng_client_callbacks_s, otrng_client_callbacks_p[1];

INTERNAL void
otrng_client_callbacks_create_privkey_v4(const otrng_client_callbacks_s *cb,
                                         const void *client_opdata);

INTERNAL void
otrng_client_callbacks_create_privkey_v3(const otrng_client_callbacks_s *cb,
                                         const void *client_opdata);

INTERNAL void
otrng_client_callbacks_create_client_profile(const otrng_client_callbacks_s *cb,
                                             struct otrng_client_state_s *state,
                                             const void *client_opdata);

INTERNAL void
otrng_client_callbacks_create_prekey_profile(const otrng_client_callbacks_s *cb,
                                             struct otrng_client_state_s *state,
                                             const void *client_opdata);

INTERNAL void
otrng_client_callbacks_create_shared_prekey(const otrng_client_callbacks_s *cb,
                                            struct otrng_client_state_s *state,
                                            const void *client_opdata);

INTERNAL void
otrng_client_callbacks_create_instag(const otrng_client_callbacks_s *cb,
                                     const void *client_opdata);

INTERNAL void
otrng_client_callbacks_gone_secure(const otrng_client_callbacks_s *cb,
                                   const otrng_client_conversation_s *conv);

INTERNAL void
otrng_client_callbacks_gone_insecure(const otrng_client_callbacks_s *cb,
                                     const otrng_client_conversation_s *conv);

INTERNAL void otrng_client_callbacks_fingerprint_seen(
    const otrng_client_callbacks_s *cb, const otrng_fingerprint_p fp,
    const otrng_client_conversation_s *conv);

INTERNAL void otrng_client_callbacks_fingerprint_seen_v3(
    const otrng_client_callbacks_s *cb, const otrng_fingerprint_v3_p fp,
    const otrng_client_conversation_s *conv);

INTERNAL void otrng_client_callbacks_smp_ask_for_answer(
    const otrng_client_callbacks_s *cb, const char *question,
    const otrng_client_conversation_s *conv);

INTERNAL void otrng_client_callbacks_smp_ask_for_secret(
    const otrng_client_callbacks_s *cb,
    const otrng_client_conversation_s *conv);

INTERNAL void otrng_client_callbacks_smp_update(
    const otrng_client_callbacks_s *cb, const otrng_smp_event_t event,
    const uint8_t progress_percent, const otrng_client_conversation_s *conv);

#ifdef DEBUG_API
API void otrng_client_callbacks_debug_print(FILE *, int,
                                            const otrng_client_callbacks_s *);
#endif

#ifdef OTRNG_CLIENT_CALLBACKS_PRIVATE
#endif

#endif
