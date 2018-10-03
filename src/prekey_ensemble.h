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

#ifndef OTRNG_PREKEY_ENSEMBLE_H
#define OTRNG_PREKEY_ENSEMBLE_H

#include <stdint.h>

#include "client_profile.h"
#include "dake.h"
#include "error.h"
#include "prekey_profile.h"

typedef struct {
  otrng_client_profile_s *client_profile;
  otrng_prekey_profile_s *prekey_profile;
  dake_prekey_message_s *message;
} prekey_ensemble_s;

INTERNAL prekey_ensemble_s *otrng_prekey_ensemble_new(void);

INTERNAL otrng_result
otrng_prekey_ensemble_validate(const prekey_ensemble_s *destination);

INTERNAL otrng_result otrng_prekey_ensemble_deserialize(
    prekey_ensemble_s *destination, const uint8_t *source, size_t source_len,
    size_t *nread);

INTERNAL void otrng_prekey_ensemble_free(prekey_ensemble_s *destination);

INTERNAL void otrng_prekey_ensemble_destroy(prekey_ensemble_s *destination);

#endif
