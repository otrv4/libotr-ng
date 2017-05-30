#include <gcrypt.h>
#include "ed448.h"

#ifndef RANDOM_H
#define RANDOM_H

static inline void random_bytes(void *const buf, const size_t size)
{
	gcry_randomize(buf, size, GCRY_STRONG_RANDOM);
}

static inline void ed448_random_scalar(decaf_448_scalar_t priv)
{
	uint8_t sym[ED448_PRIVATE_BYTES];
	random_bytes(sym, ED448_PRIVATE_BYTES);
	ec_scalar_derive_from_secret(priv, sym);
}

#endif
