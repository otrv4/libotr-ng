#ifndef OTRV4_CLIENT_CALLBACKS_H
#define OTRV4_CLIENT_CALLBACKS_H

#include "fingerprint.h"
#include "shared.h"

typedef enum {
  OTRV4_SMPEVENT_NONE = 0,
  OTRV4_SMPEVENT_ASK_FOR_SECRET = 1,
  OTRV4_SMPEVENT_ASK_FOR_ANSWER = 2,
  OTRV4_SMPEVENT_IN_PROGRESS = 3,
  OTRV4_SMPEVENT_SUCCESS = 4,
  OTRV4_SMPEVENT_CHEATED = 5,
  OTRV4_SMPEVENT_FAILURE = 6,
  OTRV4_SMPEVENT_ABORT = 7,
  OTRV4_SMPEVENT_ERROR = 8,
} otrv4_smp_event_t;

typedef struct otrv4_conversation_state_t otrv4_client_conversation_t;

typedef struct otrv4_client_callbacks_t {
  /* Create a private key for the given accountname/protocol if
   * desired. */
  void (*create_privkey)(
      void *client_opdata); // TODO: This should receive a otrv4_client_state_t

  /* A connection has entered a secure state. */
  void (*gone_secure)(const otrv4_client_conversation_t *);

  /* A connection has left a secure state. */
  void (*gone_insecure)(const otrv4_client_conversation_t *);

  /* A fingerprint was seen in this connection. */
  void (*fingerprint_seen)(const otrv4_fingerprint_t,
                           const otrv4_client_conversation_t *);

  /* A OTR3 fingerprint was seen in this connection. */
  void (*fingerprint_seen_otr3)(const otrv3_fingerprint_t,
                                const otrv4_client_conversation_t *);

  /* Update the authentication UI and prompt the user to enter a shared secret.
   *      The sender application should call otrl_message_initiate_smp,
   *      passing NULL as the question.
   *      When the receiver application resumes the SM protocol by calling
   *      otrl_message_respond_smp with the secret answer. */
  void (*smp_ask_for_secret)(const otrv4_client_conversation_t *);

  /* Same as smp_ask_for_secret but sender calls otrl_message_initiate_smp_q
   * instead) */
  void (*smp_ask_for_answer)(const char *question,
                             const otrv4_client_conversation_t *);

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
  void (*smp_update)(const otrv4_smp_event_t event,
                     const uint8_t progress_percent,
                     const otrv4_client_conversation_t *);
} otrv4_client_callbacks_t;

INTERNAL void
otrv4_client_callbacks_create_privkey(const otrv4_client_callbacks_t *cb,
                                      void *client_opdata);

INTERNAL void
otrv4_client_callbacks_gone_secure(const otrv4_client_callbacks_t *cb,
                                   const otrv4_client_conversation_t *conv);

INTERNAL void
otrv4_client_callbacks_gone_insecure(const otrv4_client_callbacks_t *cb,
                                     const otrv4_client_conversation_t *conv);

INTERNAL void otrv4_client_callbacks_fingerprint_seen(
    const otrv4_client_callbacks_t *cb, const otrv4_fingerprint_t fp,
    const otrv4_client_conversation_t *conv);

INTERNAL void otrv4_client_callbacks_fingerprint_seen_otr3(
    const otrv4_client_callbacks_t *cb, const otrv3_fingerprint_t fp,
    const otrv4_client_conversation_t *conv);

INTERNAL void otrv4_client_callbacks_smp_ask_for_answer(
    const otrv4_client_callbacks_t *cb, const char *question,
    const otrv4_client_conversation_t *conv);

INTERNAL void otrv4_client_callbacks_smp_ask_for_secret(
    const otrv4_client_callbacks_t *cb,
    const otrv4_client_conversation_t *conv);

INTERNAL void otrv4_client_callbacks_smp_update(
    const otrv4_client_callbacks_t *cb, const otrv4_smp_event_t event,
    const uint8_t progress_percent, const otrv4_client_conversation_t *conv);

#ifdef OTRV4_CLIENT_CALLBACKS_PRIVATE
#endif

#endif
