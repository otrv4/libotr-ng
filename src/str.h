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

#ifndef OTRNG_STR_H
#define OTRNG_STR_H

#include <stddef.h>
#include <stdint.h>

#include "shared.h"

#define string_p char *

INTERNAL /*@notnull@*/ /*@only@*/ void *
otrng_xmemdup(/*@notnull@*/ const void *s, const size_t len);

INTERNAL /*@notnull@*/ /*@only@*/ char *
otrng_xstrndup(/*@notnull@*/ const char *s, const size_t s_len);

INTERNAL /*@notnull@*/ /*@only@*/ char *
otrng_xstrdup(/*@notnull@*/ const char *s);

INTERNAL /*@notnull@*/ /*@only@*/ char *
otrng_stpcpy(/*@notnull@*/ char *dst,
             /*@notnull@*/ const char *src) /*@modifies dst@*/;

INTERNAL /*@notnull@*/ /*@only@*/ char *
otrng_stpncpy(/*@notnull@*/ char *dst, /*@notnull@*/ const char *src,
              const size_t n) /*@modifies dst@*/;

INTERNAL size_t otrng_strnlen(/*@notnull@*/ const char *s, const size_t maxlen);

INTERNAL size_t otrng_strlen_ns(/*@null@*/ const char *s);

#ifdef OTRNG_STR_PRIVATE
#endif

#endif
