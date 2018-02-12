#include <assert.h>
#include <stdlib.h>
#include <libotr/b64.h>

#define OTRV4_KEYS_PRIVATE

#include "keys.h"
#include "random.h"

INTERNAL otrv4_keypair_t *otrv4_keypair_new(void) {
  otrv4_keypair_t *ret = malloc(sizeof(otrv4_keypair_t));
  if (!ret)
    return NULL;

  ec_bzero(ret->priv, ED448_SCALAR_BYTES);
  ec_bzero(ret->pub, ED448_POINT_BYTES);

  return ret;
}

INTERNAL void otrv4_keypair_generate(otrv4_keypair_t *keypair,
                            const uint8_t sym[ED448_PRIVATE_BYTES]) {
  memcpy(keypair->sym, sym, ED448_PRIVATE_BYTES);
  ec_scalar_derive_from_secret(keypair->priv, keypair->sym);

  uint8_t pub[ED448_POINT_BYTES];
  ec_derive_public_key(pub, keypair->sym);
  ec_point_deserialize(keypair->pub, pub);

  decaf_bzero(pub, ED448_POINT_BYTES);
}

tstatic void otrv4_keypair_destroy(otrv4_keypair_t *keypair) {
  decaf_bzero(keypair->sym, ED448_PRIVATE_BYTES);
  ec_scalar_destroy(keypair->priv);
  ec_point_destroy(keypair->pub);
}

INTERNAL void otrv4_keypair_free(otrv4_keypair_t *keypair) {
  if (!keypair)
    return;

  otrv4_keypair_destroy(keypair);
  free(keypair);
  keypair = NULL;
}

INTERNAL otrv4_err_t otrv4_symmetric_key_serialize(char **buffer, size_t *buffer_size,
                                          uint8_t sym[ED448_PRIVATE_BYTES]) {
  *buffer = malloc((ED448_PRIVATE_BYTES + 2) / 3 * 4);
  if (!*buffer)
    return ERROR;

  *buffer_size = otrl_base64_encode(*buffer, sym, ED448_PRIVATE_BYTES);
  return SUCCESS;
}

INTERNAL otrv4_shared_prekey_pair_t *otrv4_shared_prekey_pair_new(void) {
  otrv4_shared_prekey_pair_t *ret = malloc(sizeof(otrv4_shared_prekey_pair_t));
  if (!ret)
    return NULL;

  ec_bzero(ret->priv, ED448_SCALAR_BYTES);
  ec_bzero(ret->pub, ED448_POINT_BYTES);

  return ret;
}

INTERNAL void otrv4_shared_prekey_pair_generate(otrv4_shared_prekey_pair_t *prekey_pair,
                                       const uint8_t sym[ED448_PRIVATE_BYTES]) {
  memcpy(prekey_pair->sym, sym, ED448_PRIVATE_BYTES);
  ec_scalar_derive_from_secret(prekey_pair->priv, prekey_pair->sym);

  uint8_t pub[ED448_POINT_BYTES];
  ec_derive_public_key(pub, sym);
  ec_point_deserialize(prekey_pair->pub, pub);

  decaf_bzero(pub, ED448_POINT_BYTES);
}

tstatic void otrv4_shared_prekey_pair_destroy(otrv4_shared_prekey_pair_t *prekey_pair) {
  decaf_bzero(prekey_pair->sym, ED448_PRIVATE_BYTES);
  ec_scalar_destroy(prekey_pair->priv);
  ec_point_destroy(prekey_pair->pub);
}

INTERNAL void otrv4_shared_prekey_pair_free(otrv4_shared_prekey_pair_t *prekey_pair) {
  if (!prekey_pair)
    return;

  otrv4_shared_prekey_pair_destroy(prekey_pair);
  free(prekey_pair);
  prekey_pair = NULL;
}
