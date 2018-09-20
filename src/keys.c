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

#include <assert.h>

#ifndef S_SPLINT_S
#include <libotr/b64.h>
#endif

#include <stdlib.h>

#define OTRNG_KEYS_PRIVATE

#include "keys.h"
#include "random.h"
#include "shake.h"

INTERNAL otrng_keypair_s *otrng_keypair_new(void) {
  otrng_keypair_s *ret = malloc(sizeof(otrng_keypair_s));
  if (!ret) {
    return NULL;
  }

  otrng_ec_bzero(ret->priv, ED448_SCALAR_BYTES);
  otrng_ec_bzero(ret->pub, ED448_POINT_BYTES);

  return ret;
}

INTERNAL void otrng_keypair_generate(otrng_keypair_s *keypair,
                                     const uint8_t sym[ED448_PRIVATE_BYTES]) {
  uint8_t pub[ED448_POINT_BYTES];

  memcpy(keypair->sym, sym, ED448_PRIVATE_BYTES);
  otrng_ec_scalar_derive_from_secret(keypair->priv, keypair->sym);

  otrng_ec_derive_public_key(pub, keypair->sym);
  otrng_ec_point_decode(keypair->pub, pub);

  goldilocks_bzero(pub, ED448_POINT_BYTES);
}

tstatic void keypair_destroy(otrng_keypair_s *keypair) {
  goldilocks_bzero(keypair->sym, ED448_PRIVATE_BYTES);
  otrng_ec_scalar_destroy(keypair->priv);
  otrng_ec_point_destroy(keypair->pub);
}

INTERNAL void otrng_keypair_free(otrng_keypair_s *keypair) {
  if (!keypair) {
    return;
  }

  keypair_destroy(keypair);
  free(keypair);
}

INTERNAL otrng_result otrng_symmetric_key_serialize(
    char **buffer, size_t *written, const uint8_t sym[ED448_PRIVATE_BYTES]) {
  *buffer = malloc((ED448_PRIVATE_BYTES + 2) / 3 * 4);
  if (!*buffer) {
    return OTRNG_ERROR;
  }

  *written = otrl_base64_encode(*buffer, sym, ED448_PRIVATE_BYTES);
  return OTRNG_SUCCESS;
}

INTERNAL otrng_shared_prekey_pair_s *otrng_shared_prekey_pair_new(void) {
  otrng_shared_prekey_pair_s *ret = malloc(sizeof(otrng_shared_prekey_pair_s));
  if (!ret) {
    return NULL;
  }

  otrng_ec_bzero(ret->priv, ED448_SCALAR_BYTES);
  otrng_ec_bzero(ret->pub, ED448_POINT_BYTES);

  return ret;
}

INTERNAL void
otrng_shared_prekey_pair_generate(otrng_shared_prekey_pair_s *prekey_pair,
                                  const uint8_t sym[ED448_PRIVATE_BYTES]) {
  uint8_t pub[ED448_POINT_BYTES];

  memcpy(prekey_pair->sym, sym, ED448_PRIVATE_BYTES);
  otrng_ec_scalar_derive_from_secret(prekey_pair->priv, prekey_pair->sym);

  otrng_ec_derive_public_key(pub, sym);
  otrng_ec_point_decode(prekey_pair->pub, pub);

  goldilocks_bzero(pub, ED448_POINT_BYTES);
}

INTERNAL otrng_result otrng_generate_ephemeral_keys(ecdh_keypair_p ecdh,
                                                    dh_keypair_p dh) {
  uint8_t sym[ED448_PRIVATE_BYTES];
  random_bytes(sym, ED448_PRIVATE_BYTES);

  otrng_ecdh_keypair_generate(ecdh, sym);
  goldilocks_bzero(sym, ED448_PRIVATE_BYTES);

  return otrng_dh_keypair_generate(dh);
}

tstatic void
shared_prekey_pair_destroy(otrng_shared_prekey_pair_s *prekey_pair) {
  goldilocks_bzero(prekey_pair->sym, ED448_PRIVATE_BYTES);
  otrng_ec_scalar_destroy(prekey_pair->priv);
  otrng_ec_point_destroy(prekey_pair->pub);
}

INTERNAL void
otrng_shared_prekey_pair_free(otrng_shared_prekey_pair_s *prekey_pair) {
  if (!prekey_pair) {
    return;
  }

  shared_prekey_pair_destroy(prekey_pair);
  free(prekey_pair);
}

INTERNAL uint8_t *otrng_derive_key_from_extra_symm_key(
    uint8_t usage, const unsigned char *use_data, size_t use_data_len,
    const unsigned char *extra_symm_key) {
  goldilocks_shake256_ctx_p hd;
  uint8_t *derived_key = malloc(EXTRA_SYMMETRIC_KEY_BYTES);
  if (!derived_key) {
    return NULL;
  }

  hash_init_with_usage(hd, usage);
  hash_update(hd, use_data, use_data_len);
  hash_update(hd, extra_symm_key, EXTRA_SYMMETRIC_KEY_BYTES);

  hash_final(hd, derived_key, EXTRA_SYMMETRIC_KEY_BYTES);
  hash_destroy(hd);

  return derived_key;
}

#ifdef DEBUG_API

#include "debug.h"

API void otrng_keypair_debug_print(FILE *f, int indent, otrng_keypair_s *k) {
  if (otrng_debug_print_should_ignore("keypair")) {
    return;
  }

  otrng_print_indent(f, indent);
  fprintf(f, "keypair {\n");

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("keypair->sym")) {
    fprintf(f, "sym = IGNORED\n");
  } else {
    fprintf(f, "sym = ");
    otrng_debug_print_data(f, k->sym, ED448_PRIVATE_BYTES);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("keypair->pub")) {
    fprintf(f, "pub = IGNORED\n");
  } else {
    fprintf(f, "pub = ");
    otrng_public_key_debug_print(f, k->pub);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("keypair->priv")) {
    fprintf(f, "priv = IGNORED\n");
  } else {
    fprintf(f, "priv = ");
    otrng_private_key_debug_print(f, k->priv);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent);
  fprintf(f, "} // keypair\n");
}

API void otrng_shared_prekey_pair_debug_print(FILE *f, int indent,
                                              otrng_shared_prekey_pair_s *k) {
  if (otrng_debug_print_should_ignore("shared_prekey_pair")) {
    return;
  }

  otrng_print_indent(f, indent);
  fprintf(f, "shared_prekey_pair {\n");

  if (otrng_debug_print_should_ignore("shared_prekey_pair->sym")) {
    otrng_print_indent(f, indent + 2);
    fprintf(f, "sym = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    fprintf(f, "sym = ");
    otrng_debug_print_data(f, k->sym, ED448_PRIVATE_BYTES);
    fprintf(f, "\n");
  }

  if (otrng_debug_print_should_ignore("shared_prekey_pair->pub")) {
    otrng_print_indent(f, indent + 2);
    fprintf(f, "pub = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    fprintf(f, "pub = ");
    otrng_shared_prekey_pub_debug_print(f, k->pub);
    fprintf(f, "\n");
  }

  if (otrng_debug_print_should_ignore("shared_prekey_pair->priv")) {
    otrng_print_indent(f, indent + 2);
    fprintf(f, "priv = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    fprintf(f, "priv = ");
    otrng_shared_prekey_priv_debug_print(f, k->priv);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent);
  fprintf(f, "} // shared_prekey_pair\n");
}

API void otrng_public_key_debug_print(FILE *f, otrng_public_key_p k) {
  if (otrng_debug_print_should_ignore("public_key")) {
    return;
  }

  uint8_t *r = malloc(ED448_POINT_BYTES);
  if (!r) {
    fprintf(f, "ERROR!!");
    return;
  }
  if (!otrng_ec_point_encode(r, ED448_POINT_BYTES, k)) {
    free(r);
    fprintf(f, "ERROR!!");
    return;
  }

  otrng_debug_print_data(f, r, ED448_POINT_BYTES);
  free(r);
}

API void otrng_private_key_debug_print(FILE *f, otrng_private_key_p k) {
  if (otrng_debug_print_should_ignore("private_key")) {
    return;
  }

  uint8_t *r = malloc(ED448_SCALAR_BYTES);
  if (!r) {
    fprintf(f, "ERROR!!");
    return;
  }

  otrng_ec_scalar_encode(r, k);

  otrng_debug_print_data(f, r, ED448_SCALAR_BYTES);
  free(r);
}

API void otrng_shared_prekey_pub_debug_print(FILE *f,
                                             otrng_shared_prekey_pub_p k) {
  if (otrng_debug_print_should_ignore("shared_prekey_pub")) {
    return;
  }

  uint8_t *r = malloc(ED448_POINT_BYTES);
  if (!r) {
    fprintf(f, "ERROR!!");
    return;
  }
  if (!otrng_ec_point_encode(r, ED448_POINT_BYTES, k)) {
    free(r);
    fprintf(f, "ERROR!!");
    return;
  }

  otrng_debug_print_data(f, r, ED448_POINT_BYTES);
  free(r);
}

API void otrng_shared_prekey_priv_debug_print(FILE *f,
                                              otrng_shared_prekey_priv_p k) {
  if (otrng_debug_print_should_ignore("shared_prekey_priv")) {
    return;
  }

  uint8_t *r = malloc(ED448_SCALAR_BYTES);
  if (!r) {
    fprintf(f, "ERROR!!");
    return;
  }
  otrng_ec_scalar_encode(r, k);

  otrng_debug_print_data(f, r, ED448_SCALAR_BYTES);
  free(r);
}

#endif /* DEBUG */
