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

#ifndef OTRNG_UTIL_H
#define OTRNG_UTIL_H

#include <stddef.h>

#include "error.h"
#include "shared.h"

/* This function tests whether the array is empty. It is NOT constant time. */
INTERNAL otrng_bool otrng_is_empty_array(const uint8_t *buf,
                                         const size_t buf_len);

#ifdef OTRNG_UTIL_PRIVATE
#endif

#endif
