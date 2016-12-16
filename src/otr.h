#define OTR_ALLOW_V3 1
#define OTR_ALLOW_V4 2

#define OTR_STATE_START 1

typedef struct {
  int *state;
  int *supported_versions;
} otr;

otr *otr_new(void);

int otr_start(otr *otr);
void otr_build_query_message(char * query_message, const otr *otr, const char *message);
int otr_build_whitespace_tag(char * whitespace_tag, const otr *otr, const char *message);
void otr_version_support_v3(otr *otr);

void otr_free(otr *otr);
