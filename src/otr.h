#define OTR_V4 4

#define OTRSTATE_START "OTR_STATE_START"

typedef struct {
  int version;
  char *state;
} otr;

otr *otr_malloc(void);

int otr_start(otr *otr);
void otr_build_query_message(char * query_message, otr *otr, char *message);

void otr_free(otr *otr);
