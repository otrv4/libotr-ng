#include "instance_tag.h"
#include "str.h"

#include <stdio.h>
#include <libotr/instag.h>

int otrv4_instag_get(otrv4_instag_t *otrv4_instag, char *account,
                     char *protocol, FILE *filename) {

  OtrlUserState us = otrl_userstate_create();
  if (otrl_instag_read_FILEp(us, filename)) {
    return 1;
  }

  OtrlInsTag *tmp_instag;
  tmp_instag = otrl_instag_find(us, account, protocol);

  if (!tmp_instag) {
    if (otrl_instag_generate_FILEp(us, filename, account, protocol)) {
      return 1;
    }

    tmp_instag = otrl_instag_find(us, account, protocol);
    otrv4_instag->account = tmp_instag ->accountname;
    otrv4_instag->protocol = tmp_instag ->protocol;
    otrv4_instag->value = tmp_instag ->instag;

    return 0;
  }

  otrv4_instag->account = tmp_instag->accountname;
  otrv4_instag->protocol = tmp_instag->protocol;
  otrv4_instag->value = tmp_instag->instag;

  free(us);
  return 0;
}

void otr4_instag_free(otrv4_instag_t *instag) {
  free(instag->account);
  instag->account = NULL;

  free(instag->protocol);
  instag->protocol = NULL;

  free(instag);
}
