#ifndef OTRNG_OTRNG_H
#define OTRNG_OTRNG_H

#include "client_state.h"
#include "fragment.h"
#include "key_management.h"
#include "keys.h"
#include "v3.h"
#include "shared.h"
#include "smp.h"
#include "str.h"
#include "user_profile.h"

#define UNUSED_ARG(x) (void)x

#define OTRNG_INIT                                                             \
  do {                                                                         \
    otrng_v3_init();                                                           \
    otrng_dh_init();                                                           \
  } while (0);

#define OTRNG_FREE                                                             \
  do {                                                                         \
    otrng_dh_free();                                                           \
  } while (0);

// TODO: how is this type chosen?
#define POLICY_ALLOW_V3 0x04
#define POLICY_ALLOW_V4 0x05

/* Analogous to v1 and v3 policies */
#define POLICY_NEVER 0x00
#define POLICY_OPPORTUNISTIC (POLICY_ALLOW_V3 | POLICY_ALLOW_V4)
#define POLICY_MANUAL (OTRL_POLICY_ALLOW_V3 | OTRL_POLICY_ALLOW_V4)
#define POLICY_ALWAYS (OTRL_POLICY_ALLOW_V3 | OTRL_POLICY_ALLOW_V4)
#define POLICY_DEFAULT POLICY_OPPORTUNISTIC

typedef struct connection otrng_t; /* Forward declare */

typedef enum {
  OTRNG_STATE_NONE = 0,
  OTRNG_STATE_START = 1,
  OTRNG_STATE_ENCRYPTED_MESSAGES = 2,
  OTRNG_STATE_WAITING_AUTH_I = 3,
  OTRNG_STATE_WAITING_AUTH_R = 4,
  OTRNG_STATE_FINISHED = 5
} otrng_state;

typedef enum {
  OTRNG_ALLOW_NONE = 0,
  OTRNG_ALLOW_V3 = 1,
  OTRNG_ALLOW_V4 = 2
} otrng_supported_version;

typedef enum {
  OTRNG_VERSION_NONE = 0,
  OTRNG_VERSION_3 = 3,
  OTRNG_VERSION_4 = 4
} otrng_version_t;

// clang-format off
typedef struct { int allows; } otrng_policy_t;
// clang-format on

// TODO: This is a single instance conversation. Make it multi-instance.
typedef struct otrng_conversation_state_t {
  /* void *opdata; // Could have a conversation opdata to point to a, say
   PurpleConversation */

  struct otrng_client_state_t *client;
  char *peer;
  uint16_t their_instance_tag;
} otrng_conversation_state_t;

struct connection {
  /* Contains: client (private key, instance tag, and callbacks) and
   conversation state */
  otrng_conversation_state_t *conversation;
  otrng_v3_conn_t *v3_conn;

  otrng_state state;
  int supported_versions;

  uint32_t our_instance_tag;
  uint32_t their_instance_tag;

  user_profile_t *profile;
  user_profile_t *their_profile;

  otrng_version_t running_version;

  key_manager_t *keys;
  smp_context_t smp;

  fragment_context_t *frag_ctx;
}; /* otrng_t */

// clang-format off
// TODO: this a mock
typedef struct {
  string_t prekey_message;
} otrng_server_t;
// clang-format on

typedef enum {
  IN_MSG_NONE = 0,
  IN_MSG_PLAINTEXT = 1,
  IN_MSG_TAGGED_PLAINTEXT = 2,
  IN_MSG_QUERY_STRING = 3,
  IN_MSG_OTR_ENCODED = 4,
  IN_MSG_OTR_ERROR = 5
} otrng_in_message_type_t;

typedef enum {
  OTRNG_WARN_NONE = 0,
  OTRNG_WARN_RECEIVED_UNENCRYPTED,
  OTRNG_WARN_RECEIVED_NOT_VALID
} otrng_warning_t;

typedef struct {
  string_t to_display;
  string_t to_send;
  tlv_t *tlvs;
  otrng_warning_t warning;
} otrng_response_t;

typedef struct {
  otrng_supported_version version;
  uint8_t type;
} otrng_header_t;

INTERNAL otrng_t *otrng_new(struct otrng_client_state_t *state,
                            otrng_policy_t policy);

INTERNAL void otrng_free(/*@only@ */ otrng_t *otr);

INTERNAL otrng_err_t otrng_build_query_message(string_t *dst,
                                               const string_t message,
                                               const otrng_t *otr);

INTERNAL otrng_response_t *otrng_response_new(void);

INTERNAL void otrng_response_free(otrng_response_t *response);

INTERNAL otrng_err_t otrng_receive_message(otrng_response_t *response,
                                           const string_t message,
                                           otrng_t *otr);

INTERNAL otrng_err_t otrng_prepare_to_send_message(string_t *to_send,
                                                   const string_t message,
                                                   tlv_t **tlvs, uint8_t flags,
                                                   otrng_t *otr);

INTERNAL otrng_err_t otrng_close(string_t *to_send, otrng_t *otr);

INTERNAL otrng_err_t otrng_smp_start(string_t *to_send, const string_t question,
                                     const size_t q_len, const uint8_t *secret,
                                     const size_t secretlen, otrng_t *otr);

INTERNAL otrng_err_t otrng_smp_continue(string_t *to_send,
                                        const uint8_t *secret,
                                        const size_t secretlen, otrng_t *otr);

INTERNAL otrng_err_t otrng_expire_session(string_t *to_send, otrng_t *otr);

API otrng_err_t otrng_build_whitespace_tag(string_t *whitespace_tag,
                                           const string_t message,
                                           const otrng_t *otr);

API otrng_err_t otrng_send_symkey_message(string_t *to_send, unsigned int use,
                                          const unsigned char *usedata,
                                          size_t usedatalen, uint8_t *extra_key,
                                          otrng_t *otr);

API otrng_err_t otrng_smp_abort(string_t *to_send, otrng_t *otr);

// TODO: change to the real func: unexpose these and make them
// static
API void otrng_reply_with_prekey_msg_from_server(otrng_server_t *server,
                                                 otrng_response_t *response);

API otrng_err_t otrng_start_non_interactive_dake(otrng_server_t *server,
                                                 otrng_t *otr);

API otrng_err_t otrng_send_non_interactive_auth_msg(string_t *dst, otrng_t *otr,
                                                    const string_t message);

API otrng_err_t otrng_heartbeat_checker(string_t *to_send, otrng_t *otr);

API void otrng_v3_init(void);

#ifdef OTRNG_OTRNG_PRIVATE

tstatic void otrng_destroy(otrng_t *otr);

tstatic otrng_in_message_type_t get_message_type(const string_t message);

tstatic otrng_err_t extract_header(otrng_header_t *dst, const uint8_t *buffer,
                                   const size_t bufflen);

#endif

#endif
