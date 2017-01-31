#include <stdbool.h>

#include "dake.h"
#include "str.h"

#ifndef OTRV4_H
#define OTRV4_H

typedef enum {
  OTR_STATE_START = 1,
  OTR_STATE_AKE_IN_PROGRESS = 2,
  OTR_STATE_ENCRYPTED_MESSAGES = 3
} stateFlag;

typedef enum {
  OTR_ALLOW_V3 = 1,
  OTR_ALLOW_V4 = 2
} supportVersion;

typedef enum {
  OTR_VERSION_NONE = 0,
  OTR_VERSION_3 = 3,
  OTR_VERSION_4 = 4
} otrv4_version;

typedef struct {
  cs_keypair_s *keypair;
  stateFlag state;
  int supported_versions;
  otrv4_version running_version;
  /*@null@*/ string_t message_to_display;
  /*@null@*/ dake_pre_key_t *pre_key;
} otrv4_t;

typedef enum {
  IN_MSG_PLAINTEXT = 1,
  IN_MSG_TAGGED_PLAINTEXT = 2,
  IN_MSG_QUERY_STRING = 3,
  IN_MSG_CYPHERTEXT = 4
} otrv4_in_message_type;

typedef struct {
  otrv4_in_message_type type;
  /*@null@*/ string_t raw_text;
} otrv4_in_message_t;

typedef enum {
  OTR_WARN_NONE = 0,
  OTR_WARN_RECEIVED_UNENCRYPTED
} otrv4_warning_t;

typedef struct {
  string_t to_display;
  string_t to_send;
  otrv4_warning_t warning;
} response_t;

otrv4_t* otrv4_new(cs_keypair_s *keypair);
void otrv4_free(/*@only@*/ otrv4_t *otr);

bool otrv4_start(otrv4_t *otr);
void otrv4_version_support_v3(otrv4_t *otr);

void otrv4_build_query_message(/*@unique@*/ string_t *dst, const otrv4_t *otr, const string_t message);
bool otrv4_build_whitespace_tag(/*@unique@*/ string_t whitespace_tag, const otrv4_t *otr, const string_t message);

void
otrv4_response_free(response_t *response);

response_t*
otrv4_receive_message(otrv4_t *otr, const string_t message);

#endif
