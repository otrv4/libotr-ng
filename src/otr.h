#define OTR_V3 3
#define OTR_V4 4

#define OTRSTATE_START "OTR_STATE_START"

typedef struct {
  int version;
  char *state;
  int *supported_versions;
} otr;

otr *otr_malloc(void);

int otr_start(otr *otr);
void otr_build_query_message(char * query_message, const otr *otr, const char *message);
void otr_build_whitespace_tag(char * whitespace_tag, const otr *otr, const char *message);
void otr_version_downgrade(otr *otr);

void otr_free(otr *otr);
