#include "str.h"
#include "instance_tag.h"

#include <libotr/instag.h>

int otr4_instag_generate(otrv4_instag_t *instag, char * account, char *protocol) {

  instag->account = otrv4_strdup(account);
  instag->protocol = otrv4_strdup(protocol);

  instag->value = otrl_instag_get_new();

  return 0;
}
