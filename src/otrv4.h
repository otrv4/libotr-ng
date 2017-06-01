#ifndef OTRV4_H
#define OTRV4_H

#include <stdbool.h>

#include "fingerprint.h"
#include "key_management.h"
#include "keys.h"
#include "otrv3.h"
#include "smp.h"
#include "str.h"
#include "user_profile.h"

#define OTR4_INIT                                                              \
  do {                                                                         \
    otrv3_init();                                                              \
    dh_init();                                                                 \
  } while (0);

#define OTR4_FREE                                                              \
  do {                                                                         \
    dh_free();                                                                 \
  } while (0);

static int otrl_initialized = 0;
static inline void otrv3_init(void) {
  if (otrl_initialized)
    return;

  if (otrl_init(OTRL_VERSION_MAJOR, OTRL_VERSION_MINOR, OTRL_VERSION_SUB))
    exit(1);

  otrl_initialized = 1;
}

typedef struct connection otrv4_t; /* Forward declare */

typedef enum {
  OTRV4_STATE_NONE = 0,
  OTRV4_STATE_START = 1,
  OTRV4_STATE_AKE_IN_PROGRESS = 2,
  OTRV4_STATE_ENCRYPTED_MESSAGES = 3,
  OTRV4_STATE_WAITING_AUTH_I = 5,
  OTRV4_STATE_WAITING_AUTH_R = 6,
  OTRV4_STATE_FINISHED = 4
} otrv4_state;

typedef enum {
  OTRV4_ALLOW_NONE = 0,
  OTRV4_ALLOW_V3 = 1,
  OTRV4_ALLOW_V4 = 2
} otrv4_supported_version;

typedef enum {
  OTRV4_VERSION_NONE = 0,
  OTRV4_VERSION_3 = 3,
  OTRV4_VERSION_4 = 4
} otrv4_version_t;

typedef struct { int allows; } otrv4_policy_t;

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
} otr4_smp_event_t;

// TODO: These callbacks could receive a "otrv4_conversation_t" with only
//(proto, account, peer) and keep the otrv4_t private;
typedef struct {
  /* Create private keys V3 and V4. */
  void (*create_privkey)(const otrv4_t *);

  /* A connection has entered a secure state. */
  void (*gone_secure)(const otrv4_t *);

  /* A connection has left a secure state. */
  void (*gone_insecure)(const otrv4_t *);

  /* A fingerprint was seen in this connection. */
  void (*fingerprint_seen)(const otrv4_fingerprint_t, const otrv4_t *);

  /* An OTR3 fingerprint was seen in this connection. */
  void (*fingerprint_seen_otr3)(const otrv3_fingerprint_t, const otrv4_t *);

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
   * - OTRL_SMPEVENT_INPROGRESS       and
   *   OTRL_SMPEVENT_SUCCESS          and
   *   OTRL_SMPEVENT_FAILURE          and
   *   OTRL_SMPEVENT_ABORT
   *      update the auth progress dialog with progress_percent
   * - OTRL_SMPEVENT_ERROR
   *      (same as OTRL_SMPEVENT_CHEATED)
   * */
  void (*handle_smp_event)(const otr4_smp_event_t event,
                           const uint8_t progress_percent, const char *question,
                           const otrv4_t *conn);

} otrv4_callbacks_t;

struct connection {
  otrv4_state state;
  int supported_versions;

  int our_instance_tag;
  int their_instance_tag;

  user_profile_t *profile;
  user_profile_t *their_profile;

  otrv4_version_t running_version;

  otrv4_keypair_t *keypair;
  key_manager_t *keys;
  const otrv4_callbacks_t *callbacks;

  otr3_conn_t *otr3_conn;

  smp_context_t smp;
}; // otrv4_t

typedef enum {
  IN_MSG_NONE = 0,
  IN_MSG_PLAINTEXT = 1,
  IN_MSG_TAGGED_PLAINTEXT = 2,
  IN_MSG_QUERY_STRING = 3,
  IN_MSG_OTR_ENCODED = 4
} otrv4_in_message_type_t;

typedef enum {
  OTRV4_WARN_NONE = 0,
  OTRV4_WARN_RECEIVED_UNENCRYPTED
} otrv4_warning_t;

typedef struct {
  string_t to_display;
  string_t to_send;
  tlv_t *tlvs;
  otrv4_warning_t warning;
} otrv4_response_t;

typedef struct {
  otrv4_supported_version version;
  uint8_t type;
} otrv4_header_t;

otrv4_t *otrv4_new(otrv4_keypair_t *keypair, otrv4_policy_t policy);
void otrv4_destroy(otrv4_t *otr);
void otrv4_free(/*@only@ */ otrv4_t *otr);

otr4_err_t otrv4_build_query_message(string_t *dst, const string_t message,
                                     const otrv4_t *otr);

otr4_err_t otrv4_build_whitespace_tag(string_t *whitespace_tag,
                                      const string_t message,
                                      const otrv4_t *otr);

otrv4_response_t *otrv4_response_new(void);

void otrv4_response_free(otrv4_response_t *response);

otrv4_in_message_type_t get_message_type(const string_t message);

otr4_err_t extract_header(otrv4_header_t *dst, const uint8_t *buffer,
                          const size_t bufflen);

otr4_err_t otrv4_receive_message(otrv4_response_t *response,
                                 const string_t message, otrv4_t *otr);

otr4_err_t otrv4_send_message(string_t *to_send, const string_t message,
                              tlv_t *tlvs, otrv4_t *otr);

otr4_err_t otrv4_close(string_t *to_send, otrv4_t *otr);

otr4_err_t otrv4_smp_start(string_t *to_send, const string_t question,
                           const uint8_t *secret, const size_t secretlen,
                           otrv4_t *otr);

otr4_err_t otrv4_smp_continue(string_t *to_send, const uint8_t *secret,
                              const size_t secretlen, otrv4_t *otr);

otr4_err_t otrv4_smp_abort(otrv4_t *otr);

// TODO: These should be private.
// Remove dependency on otr and it should work.
tlv_t *otrv4_smp_initiate(otrv4_t *otr, const string_t question,
                          const uint8_t *secret, size_t secretlen);

tlv_t *otrv4_process_smp(otrv4_t *otr, const tlv_t *tlv);

tlv_t *otrv4_smp_provide_secret(otrv4_t *otr, const uint8_t *secret,
                                const size_t secretlen);

#endif
