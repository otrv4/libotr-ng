/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef S_SPLINT_S
#include <libotr/instag.h>
#endif

#include <string.h>

#define OTRNG_INSTANCE_TAG_PRIVATE

#include "instance_tag.h"
#include "str.h"

API otrng_bool otrng_instag_get(otrng_instag_s *otrng_instag,
                                const char *account, const char *protocol,
                                FILE *filename) {
  OtrlInsTag *tmp_instag;
  OtrlUserState us = otrl_userstate_create();

  if (!us) {
    return otrng_false;
  }

  if (otrl_instag_read_FILEp(us, filename)) {
    otrl_userstate_free(us);
    return otrng_false;
  }

  tmp_instag = otrl_instag_find(us, account, protocol);

  if (!tmp_instag) {
    if (otrl_instag_generate_FILEp(us, filename, account, protocol)) {
      otrl_userstate_free(us);
      return otrng_false;
    }
    tmp_instag = otrl_instag_find(us, account, protocol);
  }

  otrng_instag->account = otrng_xstrdup(tmp_instag->accountname);
  otrng_instag->protocol = otrng_xstrdup(tmp_instag->protocol);
  otrng_instag->value = tmp_instag->instag;

  otrl_userstate_free(us);

  return otrng_true;
}

API void otrng_instag_free(otrng_instag_s *instag) {
  if (!instag) {
    return;
  }

  free(instag->account);
  free(instag->protocol);
  free(instag);
}

INTERNAL otrng_bool otrng_instance_tag_valid(uint32_t instance_tag) {
  return (instance_tag > OTRNG_MIN_VALID_INSTAG);
}
