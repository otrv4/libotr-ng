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

#define OTRNG_V3_PRIVATE

#include "v3.h"
#include "alloc.h"
#include "messaging.h"
#include "otrng.h"

tstatic void create_privkey_cb_v3(const otrng_v3_conn_s *conn) {
  if (!conn || !conn->client) {
    return;
  }

  otrng_client_callbacks_create_privkey_v3(
      conn->client->global_state->callbacks, conn->client->client_id);
}

tstatic void create_instag_cb_v3(const otrng_s *conv) {
  if (!conv || !conv->client) {
    return;
  }

  otrng_client_callbacks_create_instag(conv->client->global_state->callbacks,
                                       conv->client->client_id);
}

tstatic void gone_secure_cb_v3(const otrng_s *conv) {
  if (!conv || !conv->client) {
    return;
  }

  otrng_client_callbacks_gone_secure(conv->client->global_state->callbacks,
                                     conv);
}

tstatic void gone_insecure_cb_v3(const otrng_s *conv) {
  if (!conv || !conv->client) {
    return;
  }

  otrng_client_callbacks_gone_insecure(conv->client->global_state->callbacks,
                                       conv);
}

tstatic void fingerprint_seen_cb_v3(const otrng_fingerprint_v3_p fp,
                                    const otrng_s *conv) {
  if (!conv || !conv->client) {
    return;
  }

  otrng_client_callbacks_fingerprint_seen_v3(
      conv->client->global_state->callbacks, fp, conv);
}

tstatic void handle_smp_event_cb_v3(const otrng_smp_event_t event,
                                    const uint8_t progress_percent,
                                    const char *question, const otrng_s *conv) {
  if (!conv || !conv->client) {
    return;
  }

  switch (event) {
  case OTRNG_SMP_EVENT_ASK_FOR_SECRET:
    otrng_client_callbacks_smp_ask_for_secret(
        conv->client->global_state->callbacks, conv);
    break;
  case OTRNG_SMP_EVENT_ASK_FOR_ANSWER:
    otrng_client_callbacks_smp_ask_for_answer(
        conv->client->global_state->callbacks, question, conv);
    break;
  case OTRNG_SMP_EVENT_CHEATED:
  case OTRNG_SMP_EVENT_IN_PROGRESS:
  case OTRNG_SMP_EVENT_SUCCESS:
  case OTRNG_SMP_EVENT_FAILURE:
  case OTRNG_SMP_EVENT_ABORT:
  case OTRNG_SMP_EVENT_ERROR:
    otrng_client_callbacks_smp_update(conv->client->global_state->callbacks,
                                      event, progress_percent, conv);
    break;
  default:
    /* OTRNG_SMP_EVENT_NONE. Should not be used. */
    break;
  }
}

tstatic void received_symkey_cb_v3(const otrng_s *conv, unsigned int use,
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
  (void)conv;
  (void)use;
  (void)usedata;
  (void)usedatalen;
  (void)extra_key;
  
  // TODO: Add a callback
}

tstatic OtrlPolicy op_policy(void *opdata, ConnContext *context) {
  // TODO: @policy should we use OTRL_POLICY_DEFAULT?;
  // TODO: @policy Should an error restart AKE?
  (void)opdata;
  (void)context;
  return OTRL_POLICY_ALLOW_V3 | OTRL_POLICY_WHITESPACE_START_AKE;
}

tstatic void op_inject(void *opdata, const char *accountname,
                       const char *protocol, const char *recipient,
                       const char *message) {
  otrng_s *otr = opdata;

  (void)accountname;
  (void)protocol;
  (void)recipient;
  
  if (!opdata) {
    return;
  }

  otrng_v3_store_injected_message(message, otr->v3_conn);
}

/* Create a private key for the given accountname/protocol if
 * desired. */
tstatic void op_create_privkey(void *opdata, const char *accountname,
                               const char *protocol) {
  otrng_s *otr = opdata;

  (void)accountname;
  (void)protocol;
  
  if (!otr) {
    return;
  }

  create_privkey_cb_v3(otr->v3_conn);
}

/* Report whether you think the given user is online.  Return true if
 * you think he is, false if you think he isn't, -1 if you're not sure.
 *
 * If you return true, messages such as heartbeats or other
 * notifications may be sent to the user, which could result in "not
 * logged in" errors if you're wrong. */
tstatic int op_is_logged_in(void *opdata, const char *accountname,
                            const char *protocol, const char *recipient) {
  (void)opdata;
  (void)accountname;
  (void)protocol;
  (void)recipient;

  // TODO: implement
  return otrng_true; /* We always think the person is logged in, otherwise it
               wont send disconnect TLVs, for example. */
}

/* When the list of ConnContexts changes (including a change in
 * state), this is called so the UI can be updated. */
tstatic void op_update_context_list(void *opdata) {
  (void)opdata;
}

/* A new fingerprint for the given user has been received. */
tstatic void op_new_fingerprint(void *opdata, OtrlUserState us,
                                const char *accountname, const char *protocol,
                                const char *username,
                                unsigned char fingerprint[20]) {
  otrng_s *otr = opdata;

  (void)us;
  (void)accountname;
  (void)protocol;
  (void)username;

  if (!otr) {
    return;
  }

  fingerprint_seen_cb_v3(fingerprint, otr);
}

/* The list of known fingerprints has changed.  Write them to disk. */
tstatic void op_write_fingerprints(void *opdata) {
  (void)opdata;
}

/* A ConnContext has entered a secure state. */
tstatic void op_gone_secure(void *opdata, ConnContext *context) {
  otrng_s *otr = opdata;

  (void)context;
  
  if (!otr) {
    return;
  }

  gone_secure_cb_v3(otr);
}

/* A ConnContext has left a secure state. */
tstatic void op_gone_insecure(void *opdata, ConnContext *context) {
  otrng_s *otr = opdata;

  (void)context;
  
  if (!otr) {
    return;
  }

  gone_insecure_cb_v3(otr);
}

/* We have completed an authentication, using the D-H keys we
 * already knew.  is_reply indicates whether we initiated the AKE. */
tstatic void op_still_secure(void *opdata, ConnContext *context, int is_reply) {
  otrng_s *otr = opdata;

  (void)context;
  (void)is_reply;
  
  if (!otr) {
    return;
  }

  gone_secure_cb_v3(otr);
}

/* Find the maximum message size supported by this protocol. */
tstatic int op_max_message_size(void *opdata, ConnContext *context) {
  (void)opdata;
  (void)context;
  // TODO
  return 10000;
}

/* Return a newly allocated string containing a human-friendly
 * representation for the given account */
tstatic const char *op_account_name(void *opdata, const char *account,
                                    const char *protocol) {
  (void)opdata;
  (void)account;
  (void)protocol;
  // TODO
  return "ACCOUNT NAME";
}

/* Deallocate a string returned by account_name */
tstatic void op_account_name_free(void *opdata, const char *account_name) {
  (void)opdata;
  (void)account_name;
  // TODO
}

/* We received a request from the buddy to use the current "extra"
 * symmetric key.  The key will be passed in symkey, of length
 * OTRL_EXTRAKEY_BYTES.  The requested use, as well as use-specific
 * data will be passed so that the applications can communicate other
 * information (some id for the data transfer, for example). */
tstatic void op_received_symkey(void *opdata, ConnContext *context,
                                unsigned int use, const unsigned char *usedata,
                                size_t usedatalen,
                                const unsigned char *extra_key) {
  otrng_s *otr = opdata;

  (void)context;
  
  if (!otr) {
    return;
  }

  received_symkey_cb_v3(otr, use, usedata, usedatalen, extra_key);
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
  (void)opdata;
  (void)context;
  (void)err_code;
  printf("ERROR MESSAGE CB V3\n");
  return "ERROR MESSAGE";
}

/* Deallocate a string returned by otr_error_message */
tstatic void op_otr_error_message_free(void *opdata, const char *err_msg) {
  (void)opdata;
  (void)err_msg;
}

/* Return a string that will be prefixed to any resent message. If this
 * function is not provided by the application then the default prefix,
 * "[resent]", will be used.
 * */
tstatic const char *op_resent_msg_prefix(void *opdata, ConnContext *context) {
  (void)opdata;
  (void)context;
  return NULL;
}

/* Deallocate a string returned by resent_msg_prefix */
tstatic void op_resent_msg_prefix_free(void *opdata, const char *prefix) {
  (void)opdata;
  (void)prefix;
}

static otrng_smp_event_t convert_smp_event(OtrlSMPEvent smp_event) {
  switch (smp_event) {
  case OTRL_SMPEVENT_ASK_FOR_SECRET:
    return OTRNG_SMP_EVENT_ASK_FOR_SECRET;
    break;
  case OTRL_SMPEVENT_ASK_FOR_ANSWER:
    return OTRNG_SMP_EVENT_ASK_FOR_ANSWER;
    break;
  case OTRL_SMPEVENT_CHEATED:
    return OTRNG_SMP_EVENT_CHEATED;
    break;
  case OTRL_SMPEVENT_IN_PROGRESS:
    return OTRNG_SMP_EVENT_IN_PROGRESS;
    break;
  case OTRL_SMPEVENT_SUCCESS:
    return OTRNG_SMP_EVENT_SUCCESS;
    break;
  case OTRL_SMPEVENT_FAILURE:
    return OTRNG_SMP_EVENT_FAILURE;
    break;
  case OTRL_SMPEVENT_ABORT:
    return OTRNG_SMP_EVENT_ABORT;
    break;
  case OTRL_SMPEVENT_ERROR:
    return OTRNG_SMP_EVENT_ERROR;
    break;
  case OTRL_SMPEVENT_NONE:
  default:
    return OTRNG_SMP_EVENT_NONE;
  }

  return OTRNG_SMP_EVENT_NONE;
}

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
  otrng_s *otr = opdata;

  (void)context;
  
  if (!otr) {
    return;
  }

  handle_smp_event_cb_v3(convert_smp_event(smp_event), progress_percent,
                         question, otr);
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
  (void)opdata;
  (void)context;
  (void)message;
  (void)err;
  switch (msg_event) {
  case OTRL_MSGEVENT_ENCRYPTION_REQUIRED:
    printf("OTRL_MSGEVENT_ENCRYPTION_REQUIRED");
    break;
  case OTRL_MSGEVENT_ENCRYPTION_ERROR:
    printf("OTRL_MSGEVENT_ENCRYPTION_ERROR");
    break;
  case OTRL_MSGEVENT_CONNECTION_ENDED:
    printf("OTRL_MSGEVENT_CONNECTION_ENDED");
    break;
  case OTRL_MSGEVENT_SETUP_ERROR:
    printf("OTRL_MSGEVENT_SETUP_ERROR");
    break;
  case OTRL_MSGEVENT_MSG_REFLECTED:
    printf("OTRL_MSGEVENT_MSG_REFLECTED");
    break;
  case OTRL_MSGEVENT_MSG_RESENT:
    printf("OTRL_MSGEVENT_MSG_RESENT");
    break;
  case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE:
    printf("OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE");
    break;
  case OTRL_MSGEVENT_RCVDMSG_UNREADABLE:
    printf("OTRL_MSGEVENT_RCVDMSG_UNREADABLE");
    break;
  case OTRL_MSGEVENT_RCVDMSG_MALFORMED:
    printf("OTRL_MSGEVENT_RCVDMSG_MALFORMED");
    break;
  case OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD:
    printf("OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD");
    break;
  case OTRL_MSGEVENT_LOG_HEARTBEAT_SENT:
    printf("OTRL_MSGEVENT_LOG_HEARTBEAT_SENT");
    break;
  case OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR:
    printf("OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR");
    break;
  case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED:
    printf("OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED");
    break;
  case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED:
    printf("OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED");
    break;
  case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE:
    printf("OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE");
    break;
  case OTRL_MSGEVENT_NONE:
    printf("OTRL_MSGEVENT_NONE");
  }

  printf(" received\n");
}

/* Create a instance tag for the given accountname/protocol if
 * desired. */
tstatic void op_create_instag(void *opdata, const char *accountname,
                              const char *protocol) {
  otrng_s *otr = opdata;

  (void)accountname;
  (void)protocol;
  
  if (!otr) {
    return;
  }

  create_instag_cb_v3(otr);
}

/* Called immediately before a data message is encrypted, and after a data
 * message is decrypted. The OtrlConvertType parameter has the value
 * OTRL_CONVERT_SENDING or OTRL_CONVERT_RECEIVING to differentiate these
 * cases. */
tstatic void op_convert_msg(void *opdata, ConnContext *context,
                            OtrlConvertType convert_type, char **dest,
                            const char *src) {
  (void)opdata;
  (void)context;
  (void)convert_type;
  (void)dest;
  (void)src;
}

/* Deallocate a string returned by convert_msg. */
tstatic void op_convert_free(void *opdata, ConnContext *context, char *dest) {
  (void)opdata;
  (void)context;
  (void)dest;
}

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
tstatic void op_timer_control(void *opdata, unsigned int interval) {
  (void)opdata;
  (void)interval;
}

// For every callback, we se opdata = otrng_s*
// TODO: This callback adapter should be in client.c, since it is who knows
// what type opdata is.
static OtrlMessageAppOps v3_callbacks = {
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

INTERNAL otrng_v3_conn_s *otrng_v3_conn_new(otrng_client_s *client,
                                            const char *peer) {
  otrng_v3_conn_s *ret = otrng_xmalloc(sizeof(otrng_v3_conn_s));

  ret->client = client;
  ret->ops = &v3_callbacks;
  ret->ctx = NULL;
  ret->opdata = NULL;
  ret->injected_message = NULL;

  ret->peer = otrng_xstrdup(peer);

  return ret;
}

INTERNAL void otrng_v3_conn_free(otrng_v3_conn_s *conn) {
  if (!conn) {
    return;
  }

  free(conn->injected_message);
  free(conn->peer);
  free(conn);
}

INTERNAL otrng_result otrng_v3_send_message(char **newmessage,
                                            const char *message,
                                            const tlv_list_s *tlvs,
                                            otrng_v3_conn_s *conn) {
  // TODO: @client convert TLVs
  OtrlTLV *tlvsv3 = NULL;
  char *account_name = NULL;
  char *protocol_name = NULL;
  int err;

  (void)tlvs;
  
  if (!conn) {
    return OTRNG_ERROR;
  }

  if (!otrng_client_get_account_and_protocol(&account_name, &protocol_name,
                                             conn->client)) {
    return OTRNG_ERROR;
  }

  err = otrl_message_sending(
      conn->client->global_state->user_state_v3, conn->ops, conn->opdata,
      account_name, protocol_name, conn->peer, OTRL_INSTAG_RECENT, message,
      tlvsv3, newmessage, OTRL_FRAGMENT_SEND_SKIP, &conn->ctx, NULL, NULL);

  free(account_name);
  free(protocol_name);

  if (!err) {
    return OTRNG_SUCCESS;
  }

  return OTRNG_ERROR;
}

INTERNAL otrng_result otrng_v3_receive_message(char **to_send,
                                               char **to_display,
                                               tlv_list_s **tlvs,
                                               const char *message,
                                               otrng_v3_conn_s *conn) {
  int ignore_message;
  OtrlTLV *tlvs_v3 = NULL;
  char *account_name = NULL;
  char *protocol_name = NULL;
  char *newmessage = NULL;

  (void)tlvs;
  
  *to_send = NULL;

  if (!conn) {
    return OTRNG_ERROR;
  }

  if (!otrng_client_get_account_and_protocol(&account_name, &protocol_name,
                                             conn->client)) {
    return OTRNG_ERROR;
  }

  ignore_message = otrl_message_receiving(
      conn->client->global_state->user_state_v3, conn->ops, conn->opdata,
      account_name, protocol_name, conn->peer, message, &newmessage, &tlvs_v3,
      &conn->ctx, NULL, NULL);

  free(account_name);
  free(protocol_name);

  (void)ignore_message;

  *to_send = otrng_v3_retrieve_injected_message(conn);

  if (to_display && newmessage) {
    *to_display = otrng_xstrdup(newmessage);
  }

  if (otrl_tlv_find(tlvs_v3, OTRL_TLV_DISCONNECTED)) {
    // Recreates what is should be because we dont have access to it from
    // otrng_s
    // TODO: this needs to be refactored so we have access to otrng_s
    /* otrng_conversation_state_p s = {{ */
    /*     .client = conn->client, */
    /*     .peer = conn->peer, */
    /*     .their_instance_tag = 0, // TODO: Is it used? */
    /* }}; */

    /* gone_insecure_cb_v3(s); */
  }

  // TODO: Copy from tlvs_v3 to tlvs.

  otrl_tlv_free(tlvs_v3);
  otrl_message_free(newmessage);

  // TODO: @client Here we can use contextp to get information we might need
  // about the state, for example (context->msgstate)

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_v3_close(char **to_send, otrng_v3_conn_s *conn) {
  // TODO: @client there is also: otrl_message_disconnect, which only
  // disconnects one instance

  char *account_name = NULL;
  char *protocol_name = NULL;

  // TODO: Error?
  otrng_client_get_account_and_protocol(&account_name, &protocol_name,
                                        conn->client);

  otrl_message_disconnect_all_instances(
      conn->client->global_state->user_state_v3, conn->ops, conn->opdata,
      account_name, protocol_name, conn->peer);
  free(account_name);
  free(protocol_name);

  *to_send = otrng_v3_retrieve_injected_message(conn);
}

INTERNAL otrng_result otrng_v3_send_symkey_message(
    char **to_send, otrng_v3_conn_s *conn, unsigned int use,
    const unsigned char *usedata, size_t usedatalen, unsigned char *extra_key) {
  otrl_message_symkey(conn->client->global_state->user_state_v3, conn->ops,
                      conn->opdata, conn->ctx, use, usedata, usedatalen,
                      extra_key);

  *to_send = otrng_v3_retrieve_injected_message(conn);
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_v3_smp_start(char **to_send,
                                         const uint8_t *question, size_t q_len,
                                         const uint8_t *secret,
                                         size_t secretlen,
                                         otrng_v3_conn_s *conn) {
  char *q = NULL;
  if (question && q_len > 0) {
    q = otrng_xmalloc(q_len + 1);
    q = memcpy(q, question, q_len);
    q[q_len] = 0;
  }

  if (question) {
    otrl_message_initiate_smp_q(conn->client->global_state->user_state_v3,
                                conn->ops, conn->opdata, conn->ctx, q, secret,
                                secretlen);
  } else {
    otrl_message_initiate_smp(conn->client->global_state->user_state_v3,
                              conn->ops, conn->opdata, conn->ctx, secret,
                              secretlen);
  }

  *to_send = otrng_v3_retrieve_injected_message(conn);
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_v3_smp_continue(char **to_send,
                                            const uint8_t *secret,
                                            const size_t secretlen,
                                            otrng_v3_conn_s *conn) {
  otrl_message_respond_smp(conn->client->global_state->user_state_v3, conn->ops,
                           conn->opdata, conn->ctx, secret, secretlen);

  *to_send = otrng_v3_retrieve_injected_message(conn);
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_v3_smp_abort(otrng_v3_conn_s *conn) {
  otrl_message_abort_smp(conn->client->global_state->user_state_v3, conn->ops,
                         conn->opdata, conn->ctx);
  return OTRNG_SUCCESS;
}

tstatic void otrng_v3_store_injected_message(const char *message,
                                             otrng_v3_conn_s *conn) {
  if (!message) {
    return;
  }

  // TODO: @client This is where we should ADD a new element to the list.
  // We are just ignoring for now.
  if (conn->injected_message && message) {
    free(conn->injected_message);
  }

  conn->injected_message = otrng_xstrdup(message);
}

tstatic char *otrng_v3_retrieve_injected_message(otrng_v3_conn_s *conn) {
  // TODO: @client As this is stored from a callback it MAY be the case a
  // message was lost (if the callback was invoked multiple times before we
  // consume this injected_message). Ideally this would be a list.
  char *to_send = conn->injected_message;
  conn->injected_message = NULL;

  return to_send;
}
