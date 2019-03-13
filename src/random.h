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

#ifndef OTRNG_RANDOM_H
#define OTRNG_RANDOM_H

#ifndef S_SPLINT_S
#include <gcrypt.h>
#endif

#include "alloc.h"
#include "ed448.h"
#include "shared.h"

typedef void *(*random_generator)(size_t);

static inline void random_bytes(void *buffer, const size_t size) {
  gcry_randomize(buffer, size, GCRY_STRONG_RANDOM);
}

static inline void ed448_random_scalar(goldilocks_448_scalar_p priv) {
  uint8_t *sym = otrng_secure_alloc(ED448_PRIVATE_BYTES);
  random_bytes(sym, ED448_PRIVATE_BYTES);

  otrng_ec_scalar_derive_from_secret(priv, sym);
  otrng_secure_free(sym);
}

/**
 * @brief Creates a random keypair, where priv is in Z_q. Nothing special is
 * done with the symmetric key.
 *
 * @param [pub] The public key.
 * @param [priv] The private key.
 *
 * @warning TODO: @refactoring Is this safe?
 */
/*@unused@*/ static inline void
otrng_zq_keypair_generate(goldilocks_448_point_p pub,
                          goldilocks_448_scalar_p priv) {
  ed448_random_scalar(priv);
  goldilocks_448_point_scalarmul(pub, goldilocks_448_point_base, priv);
}

#endif
