#include "dake.h"

typedef enum {
  OTR_STATE_START = 1,
  OTR_STATE_AKE_IN_PROGRESS = 2
} stateFlag ;

typedef enum {
  OTR_ALLOW_V3 = 1,
  OTR_ALLOW_V4 = 2
} supportVersion ;

typedef enum {
  V3 = 3,
  V4 = 4
} otr_version;

typedef struct {
  stateFlag state;
  int supported_versions;
  otr_version running_version;
  /*@null@*/ char *message_to_display;
  /*@null@*/ char *warning;
  /*@null@*/ dake_pre_key_t *pre_key;
} otr_t;

typedef enum {
  IN_MSG_PLAINTEXT = 1,
  IN_MSG_TAGGED_PLAINTEXT = 2,
  IN_MSG_QUERY_STRING = 3
} otr_in_message_type;

typedef struct {
  otr_in_message_type type;
  /*@null@*/ char *raw_text;
} otr_in_message_t;

otr_t *otr_new(void);
void otr_free(/*@only@*/ otr_t *otr);

int otr_start(otr_t *otr);
void otr_version_support_v3(otr_t *otr);

void otr_build_query_message(/*@unique@*/ char * query_message, const otr_t *otr, const char *message);
int otr_build_whitespace_tag(/*@unique@*/ char * whitespace_tag, const otr_t *otr, const char *message);

void otr_receive_message(otr_t *otr, const char *message);
