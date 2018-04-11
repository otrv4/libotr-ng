/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
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

#ifndef OTRNG_SHAKE_H
#define OTRNG_SHAKE_H

#include "goldilocks/shake.h"
#include "shared.h"

#define hash_init goldilocks_shake256_init
#define hash_update goldilocks_shake256_update
#define hash_final goldilocks_shake256_final
#define hash_destroy goldilocks_shake256_destroy
#define hash_hash goldilocks_shake256_hash

static void hash_init_with_dom(goldilocks_shake256_ctx_t hash) {
  hash_init(hash);

  // TODO: This should be "OTRv4", per spec.
  const char *dom_s = "OTR4";
  hash_update(hash, (const unsigned char *)dom_s, strlen(dom_s));
}

static inline void hash_init_with_usage(goldilocks_shake256_ctx_t hash,
                                        uint8_t usage) {
  uint8_t buff[1] = {0};
  *buff = usage;

  hash_init_with_dom(hash);
  hash_update(hash, buff, 1);
}

static void shake_kkdf(uint8_t *dst, size_t dstlen, const uint8_t *key,
                       size_t keylen, const uint8_t *secret, size_t secretlen) {
  goldilocks_shake256_ctx_t hd;

  hash_init_with_dom(hd);
  hash_update(hd, key, keylen);
  hash_update(hd, secret, secretlen);

  hash_final(hd, dst, dstlen);
  hash_destroy(hd);
}

static inline void shake_256_mac(uint8_t *dst, size_t dstlen,
                                 const uint8_t *key, size_t keylen,
                                 const uint8_t *msg, size_t msglen) {
  shake_kkdf(dst, dstlen, key, keylen, msg, msglen);
}

static inline void shake_256_kdf(uint8_t *key, size_t keylen,
                                 const uint8_t magic[1], const uint8_t *secret,
                                 size_t secretlen) {
  shake_kkdf(key, keylen, magic, 1, secret, secretlen);
}

static inline void shake_256_hash(uint8_t *dst, size_t dstlen,
                                  const uint8_t *secret, size_t secretlen) {
  goldilocks_shake256_ctx_t hd;

  hash_init_with_dom(hd);
  hash_update(hd, secret, secretlen);

  hash_final(hd, dst, dstlen);
  hash_destroy(hd);
}

#endif
