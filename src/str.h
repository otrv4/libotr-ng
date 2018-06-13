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

#ifndef OTRNG_STR_H
#define OTRNG_STR_H

#include <stddef.h>
#include <stdint.h>

#include "shared.h"

#define string_p char *

INTERNAL /*@null@*/ uint8_t *otrng_memdup(const uint8_t *s, const size_t len);

INTERNAL /*@null@*/ char *otrng_strndup(const char *s, size_t s_len);

INTERNAL char *otrng_strdup(const char *s);

INTERNAL /*@null@*/ char *otrng_stpcpy(char *dest, const char *src);

#ifdef OTRNG_STR_PRIVATE
#endif

#endif
