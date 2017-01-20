#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "ed448.h"

void
ec_gen_keypair(ec_keypair_t keypair) {
  randombytes_buf(keypair->sym, DECAF_448_SYMMETRIC_KEY_BYTES);
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

ed448_point_t *
ed448_point_new() {
  ed448_point_t *p = malloc(sizeof(ed448_point_t));
  if (p == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }

  memset(p->data, 0, 56);

  return p;
}

void
ed448_point_free(ed448_point_t *point) {
  free(point);
}
