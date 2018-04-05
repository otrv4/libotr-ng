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

#ifndef OTRNG_RANDOM_H
#define OTRNG_RANDOM_H

#include <gcrypt.h>

#include "ed448.h"
#include "shared.h"

static inline void random_bytes(void *const buf, const size_t size) {
  gcry_randomize(buf, size, GCRY_STRONG_RANDOM);
}

static inline void ed448_random_scalar(goldilocks_448_scalar_t priv) {
  uint8_t sym[ED448_PRIVATE_BYTES];
  random_bytes(sym, ED448_PRIVATE_BYTES);
  otrng_ec_scalar_derive_from_secret(priv, sym);
}

#endif
