#include "dake.h"

typedef enum {
  OTR_STATE_START = 1,
  OTR_STATE_AKE_IN_PROGRESS = 2,
  OTR_STATE_ENCRYPTED_MESSAGES = 3
} stateFlag ;

typedef enum {
  OTR_ALLOW_V3 = 1,
  OTR_ALLOW_V4 = 2
} supportVersion ;

typedef enum {
  V3 = 3,
  V4 = 4
} otrv4_version;

typedef struct {
  stateFlag state;
  int supported_versions;
  otrv4_version running_version;
  /*@null@*/ char *message_to_display;
  char *message_to_respond;
  /*@null@*/ char *warning;
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
  /*@null@*/ char *raw_text;
} otrv4_in_message_t;

otrv4_t *otrv4_new(void);
void otrv4_free(/*@only@*/ otrv4_t *otr);

int otrv4_start(otrv4_t *otr);
void otrv4_version_support_v3(otrv4_t *otr);

void otrv4_build_query_message(/*@unique@*/ char * query_message, const otrv4_t *otr, const char *message);
int otrv4_build_whitespace_tag(/*@unique@*/ char * whitespace_tag, const otrv4_t *otr, const char *message);

void otrv4_receive_message(otrv4_t *otr, const char *message);
