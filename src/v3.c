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

#define OTRNG_V3_PRIVATE

#include "v3.h"
#include "otrng.h"

tstatic void create_privkey_cb_v3(const otrng_conversation_state_s *otr) {
  if (!otr || !otr->client)
    return;
  otrng_client_callbacks_create_privkey(otr->client->callbacks,
                                        otr->client->client_id);
}

tstatic void gone_secure_cb_v3(const otrng_conversation_state_s *otr) {
  if (!otr || !otr->client)
    return;
  otrng_client_callbacks_gone_secure(
      otr->client->callbacks,
      otr->client->client_id); // TODO: should be conversation_id
}

tstatic void gone_insecure_cb_v3(const otrng_conversation_state_s *otr) {
  if (!otr || !otr->client)
    return;
  otrng_client_callbacks_gone_insecure(
      otr->client->callbacks,
      otr->client->client_id); // TODO: should be conversation_id
}

tstatic void fingerprint_seen_cb_v3(const v3_fingerprint_p fp,
                                    const otrng_conversation_state_s *otr) {
  if (!otr || !otr->client)
    return;
  otrng_client_callbacks_fingerprint_seen_v3(
      otr->client->callbacks, fp,
      otr->client->client_id); // TODO: should be conversation_id
}

tstatic void handle_smp_event_cb_v3(const otrng_smp_event_t event,
                                    const uint8_t progress_percent,
                                    const char *question,
                                    const otrng_conversation_state_s *otr) {
  if (!otr || !otr->client)
    return;
  switch (event) {
  case OTRNG_SMPEVENT_ASK_FOR_SECRET:
    otrng_client_callbacks_smp_ask_for_secret(
        otr->client->callbacks,
        otr->client->client_id); // TODO: should be conversation_id
    break;
  case OTRNG_SMPEVENT_ASK_FOR_ANSWER:
    otrng_client_callbacks_smp_ask_for_answer(
        otr->client->callbacks, question,
        otr->client->client_id); // TODO: should be conversation_id
    break;
  case OTRNG_SMPEVENT_CHEATED:
  case OTRNG_SMPEVENT_IN_PROGRESS:
  case OTRNG_SMPEVENT_SUCCESS:
  case OTRNG_SMPEVENT_FAILURE:
  case OTRNG_SMPEVENT_ABORT:
  case OTRNG_SMPEVENT_ERROR:
    otrng_client_callbacks_smp_update(
        otr->client->callbacks, event, progress_percent,
        otr->client->client_id); // TODO: should be conversation_id
    break;
  default:
    // OTRNG_SMPEVENT_NONE. Should not be used.
    break;
  }
}

tstatic void received_symkey_cb_v3(const otrng_conversation_state_s *otr,
                                   unsigned int use,
                                   const unsigned char *usedata,
                                   size_t usedatalen,
                                   const unsigned char *extra_key) {
#ifdef DEBUG
  printf("Received symkey use: %08x\n", use);
  printf("Usedata lenght: %zu\n", usedatalen);
  printf("Usedata: ");
  for (int i = 0; i < usedatalen; i++) {
    printf("%02x", usedata[i]);
  }
  printf("\n");
  printf("Symkey: ");
  for (int i = 0; i < HASH_BYTES; i++) {
    printf("0x%02x, ", extra_key[i]);
  }
  printf("\n");
#endif
}

tstatic OtrlPolicy op_policy(void *opdata, ConnContext *context) {
  // TODO: should we use OTRL_POLICY_DEFAULT?;
  // TODO: Should an error restart AKE?
  return OTRL_POLICY_ALLOW_V3 | OTRL_POLICY_WHITESPACE_START_AKE;
}

static char *injected_to_send = NULL;

tstatic void from_injected_to_send(char **to_send) {
  if (!to_send || !injected_to_send)
    return;

  // TODO: As this is stored from a callback it MAY be the case a message
  // was lost (if the callback was invoked multiple times before we consume
  // this injected_to_send). Ideally this would be a list.
  *to_send = otrng_strdup(injected_to_send);
  free(injected_to_send);
  injected_to_send = NULL;
}

tstatic void op_inject(void *opdata, const char *accountname,
                       const char *protocol, const char *recipient,
                       const char *message) {
  // TODO: This is where we should ADD a new element to the list.
  // We are just ignoring for now.
  if (injected_to_send) {
    free(injected_to_send);
    injected_to_send = NULL;
  }

  if (message)
    injected_to_send = otrng_strdup(message);
}

/* Create a private key for the given accountname/protocol if
 * desired. */
tstatic void op_create_privkey(void *opdata, const char *accountname,
                               const char *protocol) {
  create_privkey_cb_v3(opdata);
}

/* Report whether you think the given user is online.  Return 1 if
 * you think he is, 0 if you think he isn't, -1 if you're not sure.
 *
 * If you return 1, messages such as heartbeats or other
 * notifications may be sent to the user, which could result in "not
 * logged in" errors if you're wrong. */
tstatic int op_is_logged_in(void *opdata, const char *accountname,
                            const char *protocol, const char *recipient) {
  return 1; // We always think the person is logged in, otherwise it wont send
            // disconnect TLVs, for example.
}

/* When the list of ConnContexts changes (including a change in
 * state), this is called so the UI can be updated. */
tstatic void op_update_context_list(void *opdata) {}

/* A new fingerprint for the given user has been received. */
tstatic void op_new_fingerprint(void *opdata, OtrlUserState us,
                                const char *accountname, const char *protocol,
                                const char *username,
                                unsigned char fingerprint[20]) {
  fingerprint_seen_cb_v3(fingerprint, opdata);
}

/* The list of known fingerprints has changed.  Write them to disk. */
tstatic void op_write_fingerprints(void *opdata) {}

/* A ConnContext has entered a secure state. */
tstatic void op_gone_secure(void *opdata, ConnContext *context) {
  gone_secure_cb_v3(opdata);
}

/* A ConnContext has left a secure state. */
tstatic void op_gone_insecure(void *opdata, ConnContext *context) {
  gone_insecure_cb_v3(opdata);
}

/* We have completed an authentication, using the D-H keys we
 * already knew.  is_reply indicates whether we initiated the AKE. */
tstatic void op_still_secure(void *opdata, ConnContext *context, int is_reply) {
  gone_secure_cb_v3(opdata);
}

/* Find the maximum message size supported by this protocol. */
tstatic int op_max_message_size(void *opdata, ConnContext *context) {
  return 10000;
}

/* Return a newly allocated string containing a human-friendly
 * representation for the given account */
tstatic const char *op_account_name(void *opdata, const char *account,
                                    const char *protocol) {
  return "ACCOUNT NAME";
}

/* Deallocate a string returned by account_name */
tstatic void op_account_name_free(void *opdata, const char *account_name) {}

/* We received a request from the buddy to use the current "extra"
 * symmetric key.  The key will be passed in symkey, of length
 * OTRL_EXTRAKEY_BYTES.  The requested use, as well as use-specific
 * data will be passed so that the applications can communicate other
 * information (some id for the data transfer, for example). */
tstatic void op_received_symkey(void *opdata, ConnContext *context,
                                unsigned int use, const unsigned char *usedata,
                                size_t usedatalen,
                                const unsigned char *extra_key) {
  received_symkey_cb_v3(opdata, use, usedata, usedatalen, extra_key);
}

/* Return a string according to the error event. This string will then
 * be concatenated to an OTR header to produce an OTR protocol error
 * message. The following are the possible error events:
 * - OTRL_ERRCODE_ENCRYPTION_ERROR
 * 		occured while encrypting a message
 * - OTRL_ERRCODE_MSG_NOT_IN_PRIVATE
 * 		sent encrypted message to somebody who is not in
 * 		a mutual OTR session
 * - OTRL_ERRCODE_MSG_UNREADABLE
 *		sent an unreadable encrypted message
 * - OTRL_ERRCODE_MSG_MALFORMED
 * 		message sent is malformed */
tstatic const char *op_otr_error_message(void *opdata, ConnContext *context,
                                         OtrlErrorCode err_code) {
  printf("ERROR MESSAGE CB V3\n");
  return "ERROR MESSAGE";
}

/* Deallocate a string returned by otr_error_message */
tstatic void op_otr_error_message_free(void *opdata, const char *err_msg) {}

/* Return a string that will be prefixed to any resent message. If this
 * function is not provided by the application then the default prefix,
 * "[resent]", will be used.
 * */
tstatic const char *op_resent_msg_prefix(void *opdata, ConnContext *context) {
  return NULL;
}

/* Deallocate a string returned by resent_msg_prefix */
tstatic void op_resent_msg_prefix_free(void *opdata, const char *prefix) {}

/* Update the authentication UI with respect to SMP events
 * These are the possible events:
 * - OTRL_SMPEVENT_ASK_FOR_SECRET
 *      prompt the user to enter a shared secret. The sender application
 *      should call otrl_message_initiate_smp, passing NULL as the question.
 *      When the receiver application resumes the SM protocol by calling
 *      otrl_message_respond_smp with the secret answer.
 * - OTRL_SMPEVENT_ASK_FOR_ANSWER
 *      (same as OTRL_SMPEVENT_ASK_FOR_SECRET but sender calls
 *      otrl_message_initiate_smp_q instead)
 * - OTRL_SMPEVENT_CHEATED
 *      abort the current auth and update the auth progress dialog
 *      with progress_percent. otrl_message_abort_smp should be called to
 *      stop the SM protocol.
 * - OTRL_SMPEVENT_INPROGRESS 	and
 *   OTRL_SMPEVENT_SUCCESS 		and
 *   OTRL_SMPEVENT_FAILURE    	and
 *   OTRL_SMPEVENT_ABORT
 *      update the auth progress dialog with progress_percent
 * - OTRL_SMPEVENT_ERROR
 *      (same as OTRL_SMPEVENT_CHEATED)
 * */
tstatic void op_handle_smp_event(void *opdata, OtrlSMPEvent smp_event,
                                 ConnContext *context,
                                 unsigned short progress_percent,
                                 char *question) {
  otrng_smp_event_t event = OTRNG_SMPEVENT_NONE;
  switch (smp_event) {
  case OTRL_SMPEVENT_ASK_FOR_SECRET:
    event = OTRNG_SMPEVENT_ASK_FOR_SECRET;
    break;
  case OTRL_SMPEVENT_ASK_FOR_ANSWER:
    event = OTRNG_SMPEVENT_ASK_FOR_ANSWER;
    break;
  case OTRL_SMPEVENT_CHEATED:
    event = OTRNG_SMPEVENT_CHEATED;
    break;
  case OTRL_SMPEVENT_IN_PROGRESS:
    event = OTRNG_SMPEVENT_IN_PROGRESS;
    break;
  case OTRL_SMPEVENT_SUCCESS:
    event = OTRNG_SMPEVENT_SUCCESS;
    break;
  case OTRL_SMPEVENT_FAILURE:
    event = OTRNG_SMPEVENT_FAILURE;
    break;
  case OTRL_SMPEVENT_ABORT:
    event = OTRNG_SMPEVENT_ABORT;
    break;
  case OTRL_SMPEVENT_ERROR:
    event = OTRNG_SMPEVENT_ERROR;
    break;
  case OTRL_SMPEVENT_NONE:
    event = OTRNG_SMPEVENT_NONE;
    break;
  }

  handle_smp_event_cb_v3(event, progress_percent, question, opdata);
}

/* Handle and send the appropriate message(s) to the sender/recipient
 * depending on the message events. All the events only require an opdata,
 * the event, and the context. The message and err will be NULL except for
 * some events (see below). The possible events are:
 * - OTRL_MSGEVENT_ENCRYPTION_REQUIRED
 *      Our policy requires encryption but we are trying to send
 *      an unencrypted message out.
 * - OTRL_MSGEVENT_ENCRYPTION_ERROR
 *      An error occured while encrypting a message and the message
 *      was not sent.
 * - OTRL_MSGEVENT_CONNECTION_ENDED
 *      Message has not been sent because our buddy has ended the
 *      private conversation. We should either close the connection,
 *      or refresh it.
 * - OTRL_MSGEVENT_SETUP_ERROR
 *      A private conversation could not be set up. A gcry_error_t
 *      will be passed.
 * - OTRL_MSGEVENT_MSG_REFLECTED
 *      Received our own OTR messages.
 * - OTRL_MSGEVENT_MSG_RESENT
 *      The previous message was resent.
 * - OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE
 *      Received an encrypted message but cannot read
 *      it because no private connection is established yet.
 * - OTRL_MSGEVENT_RCVDMSG_UNREADABLE
 *      Cannot read the received message.
 * - OTRL_MSGEVENT_RCVDMSG_MALFORMED
 *      The message received contains malformed data.
 * - OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD
 *      Received a heartbeat.
 * - OTRL_MSGEVENT_LOG_HEARTBEAT_SENT
 *      Sent a heartbeat.
 * - OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR
 *      Received a general OTR error. The argument 'message' will
 *      also be passed and it will contain the OTR error message.
 * - OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED
 *      Received an unencrypted message. The argument 'message' will
 *      also be passed and it will contain the plaintext message.
 * - OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED
 *      Cannot recognize the type of OTR message received.
 * - OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE
 *      Received and discarded a message intended for another instance. */
tstatic void op_handle_msg_event(void *opdata, OtrlMessageEvent msg_event,
                                 ConnContext *context, const char *message,
                                 gcry_error_t err) {
  printf("MSG EVENT V3\n");
}

/* Create a instance tag for the given accountname/protocol if
 * desired. */
tstatic void op_create_instag(void *opdata, const char *accountname,
                              const char *protocol) {}

/* Called immediately before a data message is encrypted, and after a data
 * message is decrypted. The OtrlConvertType parameter has the value
 * OTRL_CONVERT_SENDING or OTRL_CONVERT_RECEIVING to differentiate these
 * cases. */
tstatic void op_convert_msg(void *opdata, ConnContext *context,
                            OtrlConvertType convert_type, char **dest,
                            const char *src) {}

/* Deallocate a string returned by convert_msg. */
tstatic void op_convert_free(void *opdata, ConnContext *context, char *dest) {}

/* When timer_control is called, turn off any existing periodic
 * timer.
 *
 * Additionally, if interval > 0, set a new periodic timer
 * to go off every interval seconds.  When that timer fires, you
 * must call otrl_message_poll(user_state, uiops, uiopdata); from the
 * main libotr thread.
 *
 * The timing does not have to be exact; this timer is used to
 * provide forward secrecy by cleaning up stale private state that
 * may otherwise stick around in memory.  Note that the
 * timer_control callback may be invoked from otrl_message_poll
 * itself, possibly to indicate that interval == 0 (that is, that
 * there's no more periodic work to be done at this time).
 *
 * If you set this callback to NULL, then you must ensure that your
 * application calls otrl_message_poll(user_state, uiops, uiopdata);
 * from the main libotr thread every definterval seconds (where
 * definterval can be obtained by calling
 * definterval = otrl_message_poll_get_default_interval(user_state);
 * right after creating the user_state).  The advantage of
 * implementing the timer_control callback is that the timer can be
 * turned on by libotr only when it's needed.
 *
 * It is not a problem (except for a minor performance hit) to call
 * otrl_message_poll more often than requested, whether
 * timer_control is implemented or not.
 *
 * If you fail to implement the timer_control callback, and also
 * fail to periodically call otrl_message_poll, then you open your
 * users to a possible forward secrecy violation: an attacker that
 * compromises the user's computer may be able to decrypt a handful
 * of long-past messages (the first messages of an OTR
 * conversation).
 */
tstatic void op_timer_control(void *opdata, unsigned int interval) {}

static OtrlMessageAppOps null_ops = {
    op_policy,
    op_create_privkey,
    op_is_logged_in,
    op_inject,
    op_update_context_list,
    op_new_fingerprint,
    op_write_fingerprints,
    op_gone_secure,
    op_gone_insecure,
    op_still_secure,
    op_max_message_size,
    op_account_name,
    op_account_name_free,
    op_received_symkey,
    op_otr_error_message,
    op_otr_error_message_free,
    op_resent_msg_prefix,
    op_resent_msg_prefix_free,
    op_handle_smp_event,
    op_handle_msg_event,
    op_create_instag,
    op_convert_msg,
    op_convert_free,
    op_timer_control,
};

INTERNAL otrng_v3_conn_s *otrng_v3_conn_new(otrng_client_state_s *state,
                                            const char *peer) {
  otrng_v3_conn_s *ret = malloc(sizeof(otrng_v3_conn_s));
  if (!ret)
    return NULL;

  ret->state = state;
  ret->ops = &null_ops; // This cant be null
  ret->ctx = NULL;
  ret->opdata = NULL;

  ret->peer = otrng_strdup(peer);

  return ret;
}

INTERNAL void otrng_v3_conn_free(otrng_v3_conn_s *conn) {
  if (!conn)
    return;

  conn->ctx = NULL;
  conn->ops = NULL;
  conn->opdata = NULL;

  free(conn->peer);
  conn->peer = NULL;

  free(conn);
  conn = NULL;
}

INTERNAL otrng_err otrng_v3_send_message(char **newmessage, const char *message,
                                         const tlv_list_s *tlvs,
                                         otrng_v3_conn_s *conn) {
  // TODO: convert TLVs
  OtrlTLV *tlvsv3 = NULL;

  if (!conn)
    return ERROR;

  int err = otrl_message_sending(
      conn->state->user_state, conn->ops, conn->opdata,
      conn->state->account_name, conn->state->protocol_name, conn->peer,
      OTRL_INSTAG_RECENT, message, tlvsv3, newmessage, OTRL_FRAGMENT_SEND_SKIP,
      &conn->ctx, NULL, NULL);

  if (!err)
    return SUCCESS;

  return ERROR;
}

INTERNAL otrng_err otrng_v3_receive_message(string_p *to_send,
                                            string_p *to_display,
                                            tlv_list_s **tlvs,
                                            const string_p message,
                                            otrng_v3_conn_s *conn) {
  int ignore_message;
  OtrlTLV *tlvsv3 = NULL; // TODO: convert to v4 tlvs
  *to_send = NULL;

  if (!conn)
    return ERROR;

  char *newmessage = NULL;
  ignore_message = otrl_message_receiving(
      conn->state->user_state, conn->ops, conn->opdata,
      conn->state->account_name, conn->state->protocol_name, conn->peer,
      message, &newmessage, &tlvsv3, &conn->ctx, NULL, NULL);

  (void)ignore_message;

  from_injected_to_send(to_send);

  if (to_display && newmessage)
    *to_display = otrng_strdup(newmessage);

  otrl_tlv_free(tlvsv3);
  otrl_message_free(newmessage);

  // TODO: Here we can use contextp to get information we might need about the
  // state, for example (context->msgstate)

  return SUCCESS;
}

INTERNAL void otrng_v3_close(string_p *to_send, otrng_v3_conn_s *conn) {
  // TODO: there is also: otrl_message_disconnect, which only disconnects one
  // instance
  otrl_message_disconnect_all_instances(conn->state->user_state, conn->ops,
                                        conn->opdata, conn->state->account_name,
                                        conn->state->protocol_name, conn->peer);

  from_injected_to_send(to_send);
}

INTERNAL otrng_err otrng_v3_send_symkey_message(
    string_p *to_send, otrng_v3_conn_s *conn, unsigned int use,
    const unsigned char *usedata, size_t usedatalen, unsigned char *extra_key) {
  otrl_message_symkey(conn->state->user_state, conn->ops, conn->opdata,
                      conn->ctx, use, usedata, usedatalen, extra_key);
  from_injected_to_send(to_send);

  return SUCCESS;
}

INTERNAL otrng_err otrng_v3_smp_start(string_p *to_send,
                                      const uint8_t *question, size_t q_len,
                                      const uint8_t *secret, size_t secretlen,
                                      otrng_v3_conn_s *conn) {
  string_p q = NULL;
  if (question && q_len > 0) {
    q = malloc(q_len + 1);
    if (!q) {
      return ERROR;
    }
    q = memcpy(q, question, q_len);
    q[q_len] = 0;
  }

  if (question)
    otrl_message_initiate_smp_q(conn->state->user_state, conn->ops,
                                conn->opdata, conn->ctx, q, secret, secretlen);
  else
    otrl_message_initiate_smp(conn->state->user_state, conn->ops, conn->opdata,
                              conn->ctx, secret, secretlen);

  from_injected_to_send(to_send);
  return SUCCESS;
}

INTERNAL otrng_err otrng_v3_smp_continue(string_p *to_send,
                                         const uint8_t *secret,
                                         const size_t secretlen,
                                         otrng_v3_conn_s *conn) {
  otrl_message_respond_smp(conn->state->user_state, conn->ops, conn->opdata,
                           conn->ctx, secret, secretlen);

  from_injected_to_send(to_send);
  return SUCCESS;
}

INTERNAL otrng_err otrng_v3_smp_abort(otrng_v3_conn_s *conn) {
  otrl_message_abort_smp(conn->state->user_state, conn->ops, conn->opdata,
                         conn->ctx);
  return SUCCESS;
}
