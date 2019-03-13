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
 * The functions in this file only operate on their arguments, and doesn't touch
 * any global state. It is safe to call these functions concurrently from
 * different threads, as long as arguments pointing to the same memory areas are
 * not used from different threads.
 */

#ifndef OTRNG_INSTANCE_TAG_H
#define OTRNG_INSTANCE_TAG_H

#include <stdint.h>
#include <stdio.h>

#include "error.h"
#include "shared.h"

#define OTRNG_MIN_VALID_INSTAG 0x00000100

typedef struct otrng_instag_s {
  char *account;
  char *protocol;
  unsigned int value;
} otrng_instag_s;

API otrng_bool otrng_instag_get(otrng_instag_s *otrng_instag,
                                const char *account, const char *protocol,
                                FILE *filename);

API void otrng_instag_free(otrng_instag_s *instag);

INTERNAL otrng_bool otrng_instance_tag_valid(uint32_t instance_tag);

#ifdef OTRNG_INSTANCE_TAG_PRIVATE
#endif

#endif
