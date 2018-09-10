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

void hash_init_with_dom(goldilocks_shake256_ctx_p hash) {
  hash_init(hash);

  const char *domain = "OTRv4";
  hash_update(hash, (const unsigned char *)domain, strlen(domain));
}

void hash_init_with_usage_and_domain_separation(goldilocks_shake256_ctx_p hash,
                                                uint8_t usage,
                                                const char *domain) {
  hash_init(hash);
  // TODO: why we cast here?
  hash_update(hash, (const unsigned char *)domain, strlen(domain));
  hash_update(hash, &usage, 1);
}

void hash_init_with_usage_prekey_server(goldilocks_shake256_ctx_p hash,
                                        uint8_t usage) {
  const char *domain = "OTR-Prekey-Server";
  hash_init_with_usage_and_domain_separation(hash, usage, domain);
}

void hash_init_with_usage(goldilocks_shake256_ctx_p hash, uint8_t usage) {
  hash_init_with_dom(hash);
  hash_update(hash, &usage, 1);
}

void shake_kkdf(uint8_t *dst, size_t dstlen, const uint8_t *key, size_t keylen,
                const uint8_t *secret, size_t secretlen) {
  goldilocks_shake256_ctx_p hd;

  hash_init_with_dom(hd);
  hash_update(hd, key, keylen);
  hash_update(hd, secret, secretlen);

  hash_final(hd, dst, dstlen);
  hash_destroy(hd);
}

void shake_256_kdf1(uint8_t *dst, size_t dstlen, uint8_t usage,
                    const uint8_t *values, size_t valueslen) {
  goldilocks_shake256_ctx_p hd;
  hash_init_with_usage(hd, usage);

  hash_update(hd, values, valueslen);
  hash_final(hd, dst, dstlen);
  hash_destroy(hd);
}

void shake_256_prekey_server_kdf(uint8_t *dst, size_t dstlen, uint8_t usage,
                                 const uint8_t *values, size_t valueslen) {
  goldilocks_shake256_ctx_p hd;
  hash_init_with_usage_prekey_server(hd, usage);

  hash_update(hd, values, valueslen);
  hash_final(hd, dst, dstlen);
  hash_destroy(hd);
}

void shake_256_hash(uint8_t *dst, size_t dstlen, const uint8_t *secret,
                    size_t secretlen) {
  goldilocks_shake256_ctx_p hd;

  hash_init_with_dom(hd);
  hash_update(hd, secret, secretlen);

  hash_final(hd, dst, dstlen);
  hash_destroy(hd);
}
