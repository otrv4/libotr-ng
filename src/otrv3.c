#include "otrv3.h"
#include "otrv4.h"

static void gone_secure_cb(const otrv4_t *otr) {
  if (!otr || !otr->callbacks)
    return;

  otr->callbacks->gone_secure(otr);
}

static void gone_insecure_cb(const otrv4_t *otr) {
  if (!otr || !otr->callbacks)
    return;

  otr->callbacks->gone_insecure(otr);
}

static void fingerprint_seen_cb(const otrv3_fingerprint_t fp,
                                const otrv4_t *otr) {
  if (!otr || !otr->callbacks)
    return;

  otr->callbacks->fingerprint_seen_otr3(fp, otr);
}

static void handle_smp_event_cb(const otr4_smp_event_t event,
                                const uint8_t progress_percent,
                                const char *question, const otrv4_t *otr) {
  if (!otr->callbacks)
    return;

  otr->callbacks->handle_smp_event(event, progress_percent, question, otr);
}

static OtrlPolicy op_policy(void *opdata, ConnContext *context) {
  // TODO: should we use OTRL_POLICY_DEFAULT?;
  // TODO: Should an error restart AKE?
  return OTRL_POLICY_ALLOW_V3 | OTRL_POLICY_WHITESPACE_START_AKE;
}

static char *injected_to_send = NULL;

static void op_inject(void *opdata, const char *accountname,
                      const char *protocol, const char *recipient,
                      const char *message) {
  if (injected_to_send) {
    free(injected_to_send);
    injected_to_send = NULL;
  }

  if (message)
    injected_to_send = otrv4_strdup(message);
}

/* Create a private key for the given accountname/protocol if
 * desired. */
static void op_create_privkey(void *opdata, const char *accountname,
                              const char *protocol) {}

/* Report whether you think the given user is online.  Return 1 if
 * you think he is, 0 if you think he isn't, -1 if you're not sure.
 *
 * If you return 1, messages such as heartbeats or other
 * notifications may be sent to the user, which could result in "not
 * logged in" errors if you're wrong. */
static int op_is_logged_in(void *opdata, const char *accountname,
                           const char *protocol, const char *recipient) {
  return -1;
}

/* When the list of ConnContexts changes (including a change in
 * state), this is called so the UI can be updated. */
static void op_update_context_list(void *opdata) {}

/* A new fingerprint for the given user has been received. */
static void op_new_fingerprint(void *opdata, OtrlUserState us,
                               const char *accountname, const char *protocol,
                               const char *username,
                               unsigned char fingerprint[20]) {
  fingerprint_seen_cb(fingerprint, opdata);
}

/* The list of known fingerprints has changed.  Write them to disk. */
static void op_write_fingerprints(void *opdata) {}

/* A ConnContext has entered a secure state. */
static void op_gone_secure(void *opdata, ConnContext *context) {
  gone_secure_cb(opdata);
}

/* A ConnContext has left a secure state. */
static void op_gone_insecure(void *opdata, ConnContext *context) {
  gone_insecure_cb(opdata);
}

/* We have completed an authentication, using the D-H keys we
 * already knew.  is_reply indicates whether we initiated the AKE. */
static void op_still_secure(void *opdata, ConnContext *context, int is_reply) {
  // Nothing
}

/* Find the maximum message size supported by this protocol. */
static int op_max_message_size(void *opdata, ConnContext *context) {
  return 10000;
}

/* Return a newly allocated string containing a human-friendly
 * representation for the given account */
static const char *op_account_name(void *opdata, const char *account,
                                   const char *protocol) {
  return "ACCOUNT NAME";
}

/* Deallocate a string returned by account_name */
static void op_account_name_free(void *opdata, const char *account_name) {}

/* We received a request from the buddy to use the current "extra"
 * symmetric key.  The key will be passed in symkey, of length
 * OTRL_EXTRAKEY_BYTES.  The requested use, as well as use-specific
 * data will be passed so that the applications can communicate other
 * information (some id for the data transfer, for example). */
static void op_received_symkey(void *opdata, ConnContext *context,
                               unsigned int use, const unsigned char *usedata,
                               size_t usedatalen, const unsigned char *symkey) {
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
static const char *op_otr_error_message(void *opdata, ConnContext *context,
                                        OtrlErrorCode err_code) {
  printf("ERROR MESSAGE CB V3\n");
  return "ERROR MESSAGE";
}

/* Deallocate a string returned by otr_error_message */
static void op_otr_error_message_free(void *opdata, const char *err_msg) {}

/* Return a string that will be prefixed to any resent message. If this
 * function is not provided by the application then the default prefix,
 * "[resent]", will be used.
 * */
static const char *op_resent_msg_prefix(void *opdata, ConnContext *context) {
  return NULL;
}

/* Deallocate a string returned by resent_msg_prefix */
static void op_resent_msg_prefix_free(void *opdata, const char *prefix) {}

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
static void op_handle_smp_event(void *opdata, OtrlSMPEvent smp_event,
                                ConnContext *context,
                                unsigned short progress_percent,
                                char *question) {
  otr4_smp_event_t event = OTRV4_SMPEVENT_NONE;
  switch (smp_event) {
  case OTRL_SMPEVENT_ASK_FOR_SECRET:
    event = OTRV4_SMPEVENT_ASK_FOR_SECRET;
    break;
  case OTRL_SMPEVENT_ASK_FOR_ANSWER:
    event = OTRV4_SMPEVENT_ASK_FOR_ANSWER;
    break;
  case OTRL_SMPEVENT_CHEATED:
    event = OTRV4_SMPEVENT_CHEATED;
    break;
  case OTRL_SMPEVENT_IN_PROGRESS:
    event = OTRV4_SMPEVENT_IN_PROGRESS;
    break;
  case OTRL_SMPEVENT_SUCCESS:
    event = OTRV4_SMPEVENT_SUCCESS;
    break;
  case OTRL_SMPEVENT_FAILURE:
    event = OTRV4_SMPEVENT_FAILURE;
    break;
  case OTRL_SMPEVENT_ABORT:
    event = OTRV4_SMPEVENT_ABORT;
    break;
  case OTRL_SMPEVENT_ERROR:
    event = OTRV4_SMPEVENT_ERROR;
    break;
  case OTRL_SMPEVENT_NONE:
    event = OTRV4_SMPEVENT_NONE;
    break;
  }

  handle_smp_event_cb(event, progress_percent, question, opdata);
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
static void op_handle_msg_event(void *opdata, OtrlMessageEvent msg_event,
                                ConnContext *context, const char *message,
                                gcry_error_t err) {
  printf("MSG EVENT V3\n");
}

/* Create a instance tag for the given accountname/protocol if
 * desired. */
static void op_create_instag(void *opdata, const char *accountname,
                             const char *protocol) {}

/* Called immediately before a data message is encrypted, and after a data
 * message is decrypted. The OtrlConvertType parameter has the value
 * OTRL_CONVERT_SENDING or OTRL_CONVERT_RECEIVING to differentiate these
 * cases. */
static void op_convert_msg(void *opdata, ConnContext *context,
                           OtrlConvertType convert_type, char **dest,
                           const char *src) {}

/* Deallocate a string returned by convert_msg. */
static void op_convert_free(void *opdata, ConnContext *context, char *dest) {}

/* When timer_control is called, turn off any existing periodic
 * timer.
 *
 * Additionally, if interval > 0, set a new periodic timer
 * to go off every interval seconds.  When that timer fires, you
 * must call otrl_message_poll(userstate, uiops, uiopdata); from the
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
 * application calls otrl_message_poll(userstate, uiops, uiopdata);
 * from the main libotr thread every definterval seconds (where
 * definterval can be obtained by calling
 * definterval = otrl_message_poll_get_default_interval(userstate);
 * right after creating the userstate).  The advantage of
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
static void op_timer_control(void *opdata, unsigned int interval) {}

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

otr3_conn_t *otr3_conn_new(const char *protocol, const char *account,
                           const char *peer) {
  otr3_conn_t *ret = malloc(sizeof(otr3_conn_t));
  if (!ret)
    return NULL;

  ret->userstate = NULL;
  ret->ops = &null_ops; // This cant be null
  ret->ctx = NULL;
  ret->opdata = NULL;

  ret->protocol = otrv4_strdup(protocol);
  ret->account = otrv4_strdup(account);
  ret->peer = otrv4_strdup(peer);

  return ret;
}

void otr3_conn_free(otr3_conn_t *conn) {
  if (!conn)
    return;

  conn->ctx = NULL;
  conn->ops = NULL;
  conn->userstate = NULL;
  conn->opdata = NULL;

  free(conn->protocol);
  conn->protocol = NULL;

  free(conn->account);
  conn->account = NULL;

  free(conn->peer);
  conn->peer = NULL;

  free(conn);
}

otr4_err_t otrv3_send_message(char **newmessage, const char *message,
                              tlv_t *tlvs, otr3_conn_t *conn) {
  // TODO: convert TLVs
  OtrlTLV *tlvsv3 = NULL;

  if (!conn)
    return OTR4_ERROR;

  int err = otrl_message_sending(
      conn->userstate, conn->ops, conn->opdata, conn->account, conn->protocol,
      conn->peer, OTRL_INSTAG_BEST, message, tlvsv3, newmessage,
      OTRL_FRAGMENT_SEND_SKIP, &conn->ctx, NULL, NULL);

  if (!err)
    return OTR4_SUCCESS;

  return OTR4_ERROR;
}

otr4_err_t otrv3_receive_message(string_t *to_send, string_t *to_display,
                                 tlv_t **tlvs, const string_t message,
                                 otr3_conn_t *conn) {
  int ignore_message;
  OtrlTLV *tlvsv3 = NULL; // TODO: convert to v4 tlvs

  if (!conn)
    return OTR4_ERROR;

  char *newmessage = NULL;
  ignore_message = otrl_message_receiving(
      conn->userstate, conn->ops, conn->opdata, conn->account, conn->protocol,
      conn->peer, message, &newmessage, &tlvsv3, &conn->ctx, NULL, NULL);

  (void)ignore_message;

  if (to_send && injected_to_send) {
    *to_send = otrv4_strdup(injected_to_send);
    free(injected_to_send);
    injected_to_send = NULL;
  }

  if (to_display && newmessage)
    *to_display = otrv4_strdup(newmessage);

  otrl_tlv_free(tlvsv3);
  otrl_message_free(newmessage);

  // TODO: Here we can use contextp to get information we might need about the
  // state, for example (context->msgstate)

  return OTR4_SUCCESS;
}

otr4_err_t otrv3_smp_start(string_t *to_send, const char *question,
                           const uint8_t *secret, size_t secretlen,
                           otr3_conn_t *conn) {
  if (question)
    otrl_message_initiate_smp_q(conn->userstate, conn->ops, conn->opdata,
                                conn->ctx, question, secret, secretlen);
  else
    otrl_message_initiate_smp(conn->userstate, conn->ops, conn->opdata,
                              conn->ctx, secret, secretlen);

  if (to_send && injected_to_send) {
    *to_send = otrv4_strdup(injected_to_send);
    free(injected_to_send);
    injected_to_send = NULL;
  }

  return OTR4_SUCCESS;
}
