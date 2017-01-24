#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ed448.h"
#include "random.h"

void
ec_gen_keypair(ec_keypair_t keypair) {
  random_bytes(keypair->sym, DECAF_448_SYMMETRIC_KEY_BYTES);
  decaf_448_derive_private_key(keypair, keypair->sym);
}

void
ec_keypair_destroy(ec_keypair_t keypair) {
  decaf_448_destroy_private_key(keypair);
}

int
ecdh_shared_secret(
    uint8_t *shared,
    size_t shared_bytes,
    const ec_keypair_t our_priv,
    const ec_public_key_t their_pub
) {
  if (!decaf_448_shared_secret(shared, shared_bytes, our_priv, their_pub)) {
    return -1;
  }

  return 0;
}


void
ec_public_key_serialize(uint8_t *dst, size_t dst_bytes, const ec_public_key_t pub) {
    memcpy(dst, pub, dst_bytes);
}

void
ec_public_key_copy(ec_public_key_t dst, const ec_public_key_t src) {
  memcpy(dst, src, sizeof(ec_public_key_t));
}

void
ec_point_serialize(uint8_t *dst, size_t dst_len, const ec_point_t point) {
  decaf_448_point_encode(dst, point);
}

int
ec_point_deserialize(ec_point_t point, const uint8_t *serialized) {
  if (!decaf_448_point_decode (point, serialized, DECAF_FALSE)) {
    return 1;
  }
  
  return 0;
}
