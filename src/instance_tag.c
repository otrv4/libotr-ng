#include <libotr/instag.h>
#include <string.h>

#define OTRNG_INSTANCE_TAG_PRIVATE

#include "instance_tag.h"
#include "str.h"

API otrng_bool_t otrng_instag_get(otrng_instag_t *otrng_instag,
                                  const char *account, const char *protocol,
                                  FILE *filename) {

  OtrlUserState us = otrl_userstate_create();

  if (otrl_instag_read_FILEp(us, filename)) {
    otrl_userstate_free(us);
    return otrng_false;
  }

  OtrlInsTag *tmp_instag;
  tmp_instag = otrl_instag_find(us, account, protocol);

  if (!tmp_instag) {
    if (otrl_instag_generate_FILEp(us, filename, account, protocol)) {
      otrl_userstate_free(us);
      return otrng_false;
    }
    tmp_instag = otrl_instag_find(us, account, protocol);
  }

  otrng_instag->account = otrng_strdup(tmp_instag->accountname);
  otrng_instag->protocol = otrng_strdup(tmp_instag->protocol);
  otrng_instag->value = tmp_instag->instag;

  otrl_userstate_free(us);

  return otrng_true;
}

API void otrng_instag_free(otrng_instag_t *instag) {
  if (!instag)
    return;

  free(instag->account);
  instag->account = NULL;

  free(instag->protocol);
  instag->protocol = NULL;

  free(instag);
  instag = NULL;
}
