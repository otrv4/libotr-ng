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
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <libotr/b64.h>
#pragma clang diagnostic pop
#endif

#include <stdlib.h>

#define OTRNG_KEYS_PRIVATE

#include "alloc.h"
#include "keys.h"
#include "random.h"
#include "shake.h"

INTERNAL otrng_keypair_s *otrng_keypair_new(void) {
  otrng_keypair_s *ret = otrng_secure_alloc(sizeof(otrng_keypair_s));

  return ret;
}

INTERNAL otrng_result otrng_keypair_generate(
    otrng_keypair_s *keypair, const uint8_t sym[ED448_PRIVATE_BYTES]) {
  uint8_t pub[ED448_POINT_BYTES];

  memcpy(keypair->sym, sym, ED448_PRIVATE_BYTES);
  otrng_ec_scalar_derive_from_secret(keypair->priv, keypair->sym);

  otrng_ec_derive_public_key(pub, keypair->sym);
  if (!otrng_ec_point_decode(keypair->pub, pub)) {
    return OTRNG_ERROR;
  }

  otrng_secure_wipe(pub, ED448_POINT_BYTES);

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_keypair_free(otrng_keypair_s *keypair) {
  if (!keypair) {
    return;
  }

  otrng_secure_wipe(keypair->sym, ED448_PRIVATE_BYTES);
  otrng_ec_scalar_destroy(keypair->priv);
  otrng_ec_point_destroy(keypair->pub);
  otrng_secure_free(keypair);
}

INTERNAL otrng_result otrng_symmetric_key_serialize(
    char **buffer, size_t *written, const uint8_t sym[ED448_PRIVATE_BYTES]) {
  *buffer = otrng_secure_alloc((ED448_PRIVATE_BYTES + 2) / 3 * 4);
  *written = otrl_base64_encode(*buffer, sym, ED448_PRIVATE_BYTES);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_shared_prekey_pair_s *otrng_shared_prekey_pair_new(void) {
  otrng_shared_prekey_pair_s *ret =
      otrng_secure_alloc(sizeof(otrng_shared_prekey_pair_s));

  return ret;
}

INTERNAL otrng_result
otrng_shared_prekey_pair_generate(otrng_shared_prekey_pair_s *prekey_pair,
                                  const uint8_t sym[ED448_PRIVATE_BYTES]) {
  uint8_t pub[ED448_POINT_BYTES];

  if (sym !=
      prekey_pair->sym) { /* Make it possible to use the same sym instance */
    memcpy(prekey_pair->sym, sym, ED448_PRIVATE_BYTES);
  }

  otrng_ec_scalar_derive_from_secret(prekey_pair->priv, prekey_pair->sym);

  otrng_ec_derive_public_key(pub, sym);
  if (!otrng_ec_point_decode(prekey_pair->pub, pub)) {
    otrng_secure_wipe(pub, ED448_POINT_BYTES);
    return OTRNG_ERROR;
  }

  otrng_secure_wipe(pub, ED448_POINT_BYTES);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_generate_ephemeral_keys(ecdh_keypair_s *ecdh,
                                                    dh_keypair_s *dh) {
  uint8_t *sym = otrng_secure_alloc(ED448_PRIVATE_BYTES);
  random_bytes(sym, ED448_PRIVATE_BYTES);

  if (!otrng_ecdh_keypair_generate(ecdh, sym)) {
    otrng_secure_free(sym);
    return OTRNG_ERROR;
  }

  otrng_secure_free(sym);

  return otrng_dh_keypair_generate(dh);
}

tstatic void
shared_prekey_pair_destroy(otrng_shared_prekey_pair_s *prekey_pair) {
  otrng_secure_wipe(prekey_pair->sym, ED448_PRIVATE_BYTES);
  otrng_ec_scalar_destroy(prekey_pair->priv);
  otrng_ec_point_destroy(prekey_pair->pub);
}

INTERNAL void
otrng_shared_prekey_pair_free(otrng_shared_prekey_pair_s *prekey_pair) {
  if (!prekey_pair) {
    return;
  }

  shared_prekey_pair_destroy(prekey_pair);
  otrng_secure_free(prekey_pair);
}

INTERNAL uint8_t *otrng_derive_key_from_extra_symm_key(
    uint8_t usage, const unsigned char *use_data, size_t use_data_len,
    const unsigned char *extra_symm_key) {
  goldilocks_shake256_ctx_p hd;
  uint8_t *derived_key = otrng_secure_alloc(EXTRA_SYMMETRIC_KEY_BYTES);

  if (!hash_init_with_usage(hd, usage)) {
    otrng_secure_free(derived_key);
    return NULL;
  }

  if (hash_update(hd, use_data, use_data_len) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    otrng_secure_free(derived_key);
    return NULL;
  }

  if (hash_update(hd, extra_symm_key, EXTRA_SYMMETRIC_KEY_BYTES) ==
      GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    otrng_secure_free(derived_key);
    return NULL;
  }

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
  debug_api_print(f, "keypair {\n");

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("keypair->sym")) {
    debug_api_print(f, "sym = IGNORED\n");
  } else {
    debug_api_print(f, "sym = ");
    otrng_debug_print_data(f, k->sym, ED448_PRIVATE_BYTES);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("keypair->pub")) {
    debug_api_print(f, "pub = IGNORED\n");
  } else {
    debug_api_print(f, "pub = ");
    otrng_public_key_debug_print(f, k->pub);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("keypair->priv")) {
    debug_api_print(f, "priv = IGNORED\n");
  } else {
    debug_api_print(f, "priv = ");
    otrng_private_key_debug_print(f, k->priv);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "} // keypair\n");
}

API void otrng_shared_prekey_pair_debug_print(FILE *f, int indent,
                                              otrng_shared_prekey_pair_s *k) {
  if (otrng_debug_print_should_ignore("shared_prekey_pair")) {
    return;
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "shared_prekey_pair {\n");

  if (otrng_debug_print_should_ignore("shared_prekey_pair->sym")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "sym = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "sym = ");
    otrng_debug_print_data(f, k->sym, ED448_PRIVATE_BYTES);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore("shared_prekey_pair->pub")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "pub = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "pub = ");
    otrng_shared_prekey_pub_debug_print(f, k->pub);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore("shared_prekey_pair->priv")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "priv = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "priv = ");
    otrng_shared_prekey_priv_debug_print(f, k->priv);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "} // shared_prekey_pair\n");
}

API void otrng_public_key_debug_print(FILE *f, otrng_public_key k) {
  if (otrng_debug_print_should_ignore("public_key")) {
    return;
  }

  uint8_t *r = otrng_xmalloc_z(ED448_POINT_BYTES);
  if (!otrng_ec_point_encode(r, ED448_POINT_BYTES, k)) {
    otrng_free(r);
    debug_api_print(f, "ERROR!!");
    return;
  }

  otrng_debug_print_data(f, r, ED448_POINT_BYTES);
  otrng_free(r);
}

API void otrng_private_key_debug_print(FILE *f, otrng_private_key k) {
  if (otrng_debug_print_should_ignore("private_key")) {
    return;
  }

  uint8_t *r = otrng_xmalloc_z(ED448_SCALAR_BYTES);

  otrng_ec_scalar_encode(r, k);

  otrng_debug_print_data(f, r, ED448_SCALAR_BYTES);
  otrng_free(r);
}

API void otrng_shared_prekey_pub_debug_print(FILE *f,
                                             otrng_shared_prekey_pub k) {
  if (otrng_debug_print_should_ignore("shared_prekey_pub")) {
    return;
  }

  uint8_t *r = otrng_xmalloc_z(ED448_POINT_BYTES);
  if (!otrng_ec_point_encode(r, ED448_POINT_BYTES, k)) {
    otrng_free(r);
    debug_api_print(f, "ERROR!!");
    return;
  }

  otrng_debug_print_data(f, r, ED448_POINT_BYTES);
  otrng_free(r);
}

API void otrng_shared_prekey_priv_debug_print(FILE *f,
                                              otrng_shared_prekey_priv k) {
  if (otrng_debug_print_should_ignore("shared_prekey_priv")) {
    return;
  }

  uint8_t *r = otrng_xmalloc_z(ED448_SCALAR_BYTES);
  otrng_ec_scalar_encode(r, k);

  otrng_debug_print_data(f, r, ED448_SCALAR_BYTES);
  otrng_free(r);
}

#endif /* DEBUG */
