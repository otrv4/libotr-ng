#include <libotr/instag.h>
#include <stdbool.h>
#include <stdio.h>

#include "instance_tag.h"
#include "str.h"

// TODO: return bool?
bool otrv4_instag_get(otrv4_instag_t *otrv4_instag, const char *account,
                      const char *protocol, FILE *filename) {

  OtrlUserState us = otrl_userstate_create();
  if (otrl_instag_read_FILEp(us, filename)) {
    free(us);
    return false;
  }

  OtrlInsTag *tmp_instag;
  tmp_instag = otrl_instag_find(us, account, protocol);

  if (!tmp_instag) {
    if (otrl_instag_generate_FILEp(us, filename, account, protocol)) {
      free(us);
      free(tmp_instag);
      tmp_instag = NULL;
      return false;
    }
    tmp_instag = otrl_instag_find(us, account, protocol);
  }

  otrv4_instag->account = tmp_instag->accountname;
  otrv4_instag->protocol = tmp_instag->protocol;
  otrv4_instag->value = tmp_instag->instag;

  free(us);
  free(tmp_instag);
  tmp_instag = NULL;

  return true;
}

void otr4_instag_free(otrv4_instag_t *instag) {
  if (!instag)
    return;

  free(instag->account);
  instag->account = NULL;

  free(instag->protocol);
  instag->protocol = NULL;

  free(instag);
}
