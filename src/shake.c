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

#include <string.h>

#include "shake.h"

tstatic otrng_result hash_init_with_dom(goldilocks_shake256_ctx_p hd) {
  const char *domain = "OTRv4";

  hash_init(hd);
  if (hash_update(hd, (const unsigned char *)domain, strlen(domain)) ==
      GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

otrng_result
hash_init_with_usage_and_domain_separation(goldilocks_shake256_ctx_p hd,
                                           uint8_t usage, const char *domain) {
  hash_init(hd);
  if (hash_update(hd, (const uint8_t *)domain, strlen(domain)) ==
      GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, &usage, 1) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

static otrng_result
hash_init_with_usage_prekey_server(goldilocks_shake256_ctx_p hash,
                                   uint8_t usage) {
  const char *domain = "OTR-Prekey-Server";
  if (!hash_init_with_usage_and_domain_separation(hash, usage, domain)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

otrng_result hash_init_with_usage(goldilocks_shake256_ctx_p hd, uint8_t usage) {
  if (!hash_init_with_dom(hd)) {
    return OTRNG_ERROR;
  }

  if (hash_update(hd, &usage, 1) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

otrng_result shake_kkdf(uint8_t *dst, size_t dst_len, const uint8_t *key,
                        size_t key_len, const uint8_t *secret,
                        size_t secret_len) {
  goldilocks_shake256_ctx_p hd;

  if (!hash_init_with_dom(hd)) {
    return OTRNG_ERROR;
  }

  if (hash_update(hd, key, key_len) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, secret, secret_len) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  hash_final(hd, dst, dst_len);
  hash_destroy(hd);

  return OTRNG_SUCCESS;
}

otrng_result shake_256_kdf1(uint8_t *dst, size_t dst_len, uint8_t usage,
                            const uint8_t *values, size_t values_len) {
  goldilocks_shake256_ctx_p hd;

  if (!hash_init_with_usage(hd, usage)) {
    return OTRNG_ERROR;
  }

  if (hash_update(hd, values, values_len) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  hash_final(hd, dst, dst_len);
  hash_destroy(hd);

  return OTRNG_SUCCESS;
}

otrng_result shake_256_prekey_server_kdf(uint8_t *dst, size_t dst_len,
                                         uint8_t usage, const uint8_t *values,
                                         size_t values_len) {
  goldilocks_shake256_ctx_p hd;
  if (!hash_init_with_usage_prekey_server(hd, usage)) {
    return OTRNG_ERROR;
  }

  if (hash_update(hd, values, values_len) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  hash_final(hd, dst, dst_len);
  hash_destroy(hd);

  return OTRNG_SUCCESS;
}

otrng_result shake_256_hash(uint8_t *dst, size_t dst_len, const uint8_t *secret,
                            size_t secret_len) {
  goldilocks_shake256_ctx_p hd;

  if (!hash_init_with_dom(hd)) {
    return OTRNG_ERROR;
  }

  if (hash_update(hd, secret, secret_len) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  hash_final(hd, dst, dst_len);
  hash_destroy(hd);

  return OTRNG_SUCCESS;
}
