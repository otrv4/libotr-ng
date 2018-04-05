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

#ifndef OTRNG_INSTANCE_TAG_H
#define OTRNG_INSTANCE_TAG_H

#include <stdint.h>
#include <stdio.h>

#include "error.h"
#include "shared.h"

#define MIN_VALID_INSTAG 0x00000100

typedef struct {
  char *account;
  char *protocol;
  unsigned int value;
} otrng_instag_t;

API otrng_bool_t otrng_instag_get(otrng_instag_t *otrng_instag,
                                  const char *account, const char *protocol,
                                  FILE *filename);

API void otrng_instag_free(otrng_instag_t *instag);

#ifdef OTRNG_INSTANCE_TAG_PRIVATE
#endif

#endif
