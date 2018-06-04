/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
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

#include "prekey_ensemble.h"

INTERNAL otrng_err
otrng_prekey_ensemble_validate(const prekey_ensemble_s *dst) {
  // TODO
  return SUCCESS;
}

INTERNAL void otrng_prekey_ensemble_destroy(prekey_ensemble_s *dst) {
  otrng_client_profile_destroy(dst->client_profile);
  otrng_prekey_profile_destroy(dst->prekey_profile);

  for (uint8_t i = 0; i < dst->num_messages; i++) {
    otrng_dake_prekey_message_free(dst->messages[i]);
    dst->messages[i] = NULL;
  }

  free(dst->messages);
  dst->messages = NULL;
  dst->num_messages = 0;
}

INTERNAL void otrng_prekey_ensemble_free(prekey_ensemble_s *dst) {
  if (!dst)
    return;

  otrng_prekey_ensemble_destroy(dst);
  free(dst);
}
