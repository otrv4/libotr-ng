#include <cramershoup.h>

#include "cramer_shoup.h"

void
cs_generate_keypair(cs_keypair_t key_pair) {
  cramershoup_448_derive_keys(key_pair->priv, key_pair->pub);
}

void
cs_public_key_copy(cs_public_key_t *dst, const cs_public_key_t *src) {
  ec_point_copy(dst->c, src->c);
  ec_point_copy(dst->d, src->d);
  ec_point_copy(dst->h, src->h);
}

