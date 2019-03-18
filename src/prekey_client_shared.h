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

/**
 * TODO: concurrency comment
 */

#ifndef OTRNG_PREKEY_CLIENT_SHARED_H
#define OTRNG_PREKEY_CLIENT_SHARED_H

#include <stdint.h>

#include "alloc.h"
#include "error.h"
#include "shared.h"
#include "xyz_prekey_client.h"

INTERNAL otrng_result otrng_prekey_parse_header(uint8_t *msg_type,
                                                const uint8_t *buf,
                                                size_t buflen,
                                                /*@null@*/ size_t *read);

INTERNAL uint8_t *otrng_prekey_client_get_expected_composite_phi(
    size_t *len, const xyz_otrng_prekey_client_s *client);

#ifdef OTRNG_PREKEY_CLIENT_SHARED_PRIVATE

#endif

#endif
