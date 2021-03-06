/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
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

/**
 * @brief The function given to this function will be called if there is no
 * memory left.
 *
 * It will be called before xmalloc exits the process.
 * This function is not thread safe, and if you call it
 * concurrently from more than one thread with different
 * arguments, there is no guarantee which function will be
 * the final out of memory handler.
 */
API void otrng_register_out_of_memory_handler(
    /*@null@*/ void (*handler)(void)) /*@modifies internalState @*/;

INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_xmalloc(size_t size);
INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_xmalloc_z(size_t size);

INTERNAL /*@only@*/ /*@notnull@*/ void *
otrng_xrealloc(/*@only@*/ /*@null@*/ void *ptr, size_t size);

INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_secure_alloc(size_t size);
INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_secure_alloc_array(size_t count,
                                                                 size_t size);

INTERNAL void otrng_free(/*@notnull@*/ /*@only@*/ void *ptr);

INTERNAL void otrng_secure_free(/*@notnull@*/ /*@only@*/ void *ptr);

INTERNAL void otrng_secure_wipe(/*@notnull@*/ /*@only@*/ void *p,
                                size_t size) /*@modifies p@*/;

#endif // OTRNG_ALLOC_H
