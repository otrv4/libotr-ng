#define OTR_ALLOW_V3 1
#define OTR_ALLOW_V4 2

static const int OTR_STATE_START = 1;
static const int OTR_STATE_AKE_IN_PROGRESS = 2;

typedef struct {
  const int *state;
  int *supported_versions;
  char *message_to_display;
} otr_t;

otr_t *otr_new(void);
void otr_free(otr_t *otr);

int otr_start(otr_t *otr);
void otr_version_support_v3(otr_t *otr);

void otr_build_query_message(char * query_message, const otr_t *otr, const char *message);
int otr_build_whitespace_tag(char * whitespace_tag, const otr_t *otr, const char *message);

void otr_receive_message(otr_t *otr, const char *message);
