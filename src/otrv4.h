#ifndef OTRV4_H
#define OTRV4_H

#include "client_state.h"
#include "fragment.h"
#include "key_management.h"
#include "keys.h"
#include "otrv3.h"
#include "smp.h"
#include "str.h"
#include "user_profile.h"

#define UNUSED_ARG(x) (void)x

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
  OTRV4_STATE_ENCRYPTED_MESSAGES = 2,
  OTRV4_STATE_WAITING_AUTH_I = 3,
  OTRV4_STATE_WAITING_AUTH_R = 4,
  OTRV4_STATE_FINISHED = 5
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

// clang-format off
typedef struct { int allows; } otrv4_policy_t;
// clang-format on

// TODO: This is a single instance conversation. Make it multi-instance.
typedef struct otr4_conversation_state_t {
  /* void *opdata; // Could have a conversation opdata to point to a, say
   PurpleConversation */

  struct otr4_client_state_t *client;
  char *peer;
  uint16_t their_instance_tag;
} otr4_conversation_state_t;

struct connection {
  /* Contains: client (private key, instance tag, and callbacks) and
   conversation state */
  otr4_conversation_state_t *conversation;
  otr3_conn_t *otr3_conn;

  otrv4_state state;
  int supported_versions;

  uint32_t our_instance_tag;
  uint32_t their_instance_tag;

  user_profile_t *profile;
  user_profile_t *their_profile;

  otrv4_version_t running_version;

  key_manager_t *keys;
  smp_context_t smp;

  fragment_context_t *frag_ctx;
}; /* otrv4_t */

// clang-format off
// TODO: this a mock
typedef struct {
  string_t prekey_message;
} otrv4_server_t;
// clang-format on

typedef enum {
  IN_MSG_NONE = 0,
  IN_MSG_PLAINTEXT = 1,
  IN_MSG_TAGGED_PLAINTEXT = 2,
  IN_MSG_QUERY_STRING = 3,
  IN_MSG_OTR_ENCODED = 4,
  IN_MSG_OTR_ERROR = 5
} otrv4_in_message_type_t;

typedef enum {
  OTRV4_WARN_NONE = 0,
  OTRV4_WARN_RECEIVED_UNENCRYPTED,
  OTRV4_WARN_RECEIVED_NOT_VALID
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

otrv4_t *otrv4_new(struct otr4_client_state_t *state, otrv4_policy_t policy);
void otrv4_destroy(otrv4_t *otr);
void otrv4_free(/*@only@ */ otrv4_t *otr);

otrv4_err_t otrv4_build_query_message(string_t *dst, const string_t message,
                                      const otrv4_t *otr);

otrv4_err_t otrv4_build_whitespace_tag(string_t *whitespace_tag,
                                       const string_t message,
                                       const otrv4_t *otr);

otrv4_response_t *otrv4_response_new(void);

void otrv4_response_free(otrv4_response_t *response);

otrv4_in_message_type_t get_message_type(const string_t message);

otrv4_err_t extract_header(otrv4_header_t *dst, const uint8_t *buffer,
                           const size_t bufflen);

otrv4_err_t otrv4_receive_message(otrv4_response_t *response,
                                  const string_t message, otrv4_t *otr);

otrv4_err_t otrv4_prepare_to_send_message(string_t *to_send,
                                          const string_t message, tlv_t **tlvs,
                                          uint8_t flags, otrv4_t *otr);

otrv4_err_t otrv4_close(string_t *to_send, otrv4_t *otr);

otrv4_err_t otrv4_send_symkey_message(string_t *to_send, unsigned int use,
                                      const unsigned char *usedata,
                                      size_t usedatalen, uint8_t *extra_key,
                                      otrv4_t *otr);

otrv4_err_t otrv4_smp_start(string_t *to_send, const string_t question,
                            const size_t q_len, const uint8_t *secret,
                            const size_t secretlen, otrv4_t *otr);

otrv4_err_t otrv4_smp_continue(string_t *to_send, const uint8_t *secret,
                               const size_t secretlen, otrv4_t *otr);

otrv4_err_t otrv4_smp_abort(string_t *to_send, otrv4_t *otr);

// TODO: change to the real func: unexpose these and make them
// static
void reply_with_prekey_msg_from_server(otrv4_server_t *server,
                                       otrv4_response_t *response);

otrv4_err_t start_non_interactive_dake(otrv4_server_t *server, otrv4_t *otr);

otrv4_err_t send_non_interactive_auth_msg(string_t *dst, otrv4_t *otr,
                                          const string_t message);

const char *otr_error_message(otrv4_err_code_t err_code);

otrv4_err_t otrv4_heartbeat_checker(string_t *to_send, otrv4_t *otr);

#endif
