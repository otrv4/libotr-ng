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

#ifndef OTRNG_ALLOC_H
#define OTRNG_ALLOC_H

#include <stddef.h>

#include "shared.h"

API void otrng_register_out_of_memory_handler(/*@null@*/ void (*handler)(void));

INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_xmalloc_(size_t size, const char *file, int line, const char *fn);
INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_xmalloc_z_(size_t size, const char *file, int line, const char *fn);

INTERNAL /*@only@*/ /*@notnull@*/ void *
otrng_xrealloc(/*@only@*/ /*@null@*/ void *ptr, size_t size);

INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_secure_allocx(size_t size);
INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_secure_alloc_(size_t size, const char *file, int line, const char *fn);
INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_secure_alloc_array(size_t count,
                                                                 size_t size);

INTERNAL void otrng_free_(/*@notnull@*/ /*@only@*/ void *ptr, const char *file, int line, const char *fn);

INTERNAL void otrng_secure_free_(/*@notnull@*/ /*@only@*/ void *ptr, const char *file, int line, const char *fn);

#define otrng_free(p) otrng_free_(p, __FILE__, __LINE__, __func__)

#define otrng_secure_free(p) otrng_secure_free_(p, __FILE__, __LINE__, __func__)

#define otrng_xmalloc(sz) otrng_xmalloc_(sz, __FILE__, __LINE__, __func__)
#define otrng_xmalloc_z(sz) otrng_xmalloc_z_(sz, __FILE__, __LINE__, __func__)
#define otrng_secure_alloc(sz) otrng_secure_alloc_(sz, __FILE__, __LINE__, __func__)

INTERNAL void otrng_secure_wipe(/*@notnull@*/ /*@only@*/ void *p,
                                size_t size) /*@modifies p@*/;

#endif // OTRNG_ALLOC_H
