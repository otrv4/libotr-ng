#include "instance_tag.h"
#include "str.h"

#include <libotr/instag.h>

otrv4_instag_t *otr4_instag_generate(const char *account,
                                     const char *protocol) {

  otrv4_instag_t *instag = malloc(sizeof(otrv4_instag_t));
  if (!instag) {
    return NULL;
  }

  instag->account = otrv4_strdup(account);
  instag->protocol = otrv4_strdup(protocol);

  instag->value = otrl_instag_get_new();

  return instag;
}

void otr4_instag_free(otrv4_instag_t *instag) {
  free(instag->account);
  instag->account = NULL;

  free(instag->protocol);
  instag->protocol = NULL;

  free(instag);
}
