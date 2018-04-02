#ifndef OTRV4_RANDOM_H
#define OTRV4_RANDOM_H

#include <gcrypt.h>

#include "ed448.h"
#include "shared.h"

static inline void random_bytes(void *const buf, const size_t size) {
  gcry_randomize(buf, size, GCRY_STRONG_RANDOM);
}

static inline void ed448_random_scalar(goldilocks_448_scalar_t priv) {
  uint8_t sym[ED448_PRIVATE_BYTES];
  random_bytes(sym, ED448_PRIVATE_BYTES);
  otrv4_ec_scalar_derive_from_secret(priv, sym);
}

#endif
