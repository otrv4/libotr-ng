#include <cramershoup.h>

#include "cramer_shoup.h"

void
cs_generate_keypair(cs_keypair_t key_pair) {
  cramershoup_448_derive_keys(key_pair->priv, key_pair->pub);
}
