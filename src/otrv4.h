#ifndef OTRV4_H
#define OTRV4_H

#include <stdbool.h>

#include "dake.h"
#include "str.h"
#include "key_management.h"

#define OTR4_INIT do { \
  dh_init(); \
} while (0);

#define OTR4_FREE do { \
  dh_free(); \
} while (0);

typedef enum {
  OTRV4_STATE_START = 1,
  OTRV4_STATE_AKE_IN_PROGRESS = 2,
  OTRV4_STATE_ENCRYPTED_MESSAGES = 3,
  OTRV4_STATE_FINISHED = 4
} otrv4_state;

typedef enum {
  OTRV4_ALLOW_NONE = 0,
  OTRV4_ALLOW_V3 = 1,
  OTRV4_ALLOW_V4 = 2
} otrv4_supported_version;

typedef struct {
  otrv4_state state;
  int supported_versions;
} otrv4_protocol_t;

otrv4_protocol_t *
protocol_start(int versions, ...);

typedef enum {
  OTRV4_VERSION_NONE = 0,
  OTRV4_VERSION_3 = 3,
  OTRV4_VERSION_4 = 4
} otrv4_version_t;

typedef struct {
  int allows;
} otrv4_policy_t;

typedef struct {
  int our_instance_tag;
  int their_instance_tag;

  otrv4_protocol_t *protocol;

  user_profile_t *profile;
  cs_keypair_s *keypair;
  otrv4_version_t running_version;

  key_manager_t keys;
} otrv4_t;

typedef enum {
  IN_MSG_NONE = 0,
  IN_MSG_PLAINTEXT = 1,
  IN_MSG_TAGGED_PLAINTEXT = 2,
  IN_MSG_QUERY_STRING = 3,
  IN_MSG_CYPHERTEXT = 4
} otrv4_in_message_type_t;

typedef enum {
  OTRV4_WARN_NONE = 0,
  OTRV4_WARN_RECEIVED_UNENCRYPTED
} otrv4_warning_t;

typedef struct {
  string_t to_display;
  string_t to_send;
  otrv4_warning_t warning;
} otrv4_response_t;

typedef struct {
  otrv4_supported_version version;
  uint8_t type;
} otrv4_header_t;

otrv4_t* otrv4_new(cs_keypair_s *keypair);
void otrv4_destroy(otrv4_t *otr);
void otrv4_free(/*@only@*/ otrv4_t *otr);

bool otrv4_start(otrv4_t *otr, otrv4_policy_t policy);
void otrv4_version_support_v3(otrv4_t *otr);

void
otrv4_build_query_message
(string_t *dst, const otrv4_t *otr, const string_t message, size_t message_len);

bool
otrv4_build_whitespace_tag
(string_t *whitespace_tag, const otrv4_t *otr, const string_t message, size_t message_len);

otrv4_response_t*
otrv4_response_new(void);

void
otrv4_response_free(otrv4_response_t * response);

bool
otrv4_receive_message
(otrv4_response_t* response, const string_t received, size_t message_lenn, otrv4_t *otr);

bool
otrv4_send_message(uint8_t **to_send, const uint8_t *message, size_t message_len, otrv4_t *otr);

#endif
