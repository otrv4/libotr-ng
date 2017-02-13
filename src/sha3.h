#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stdbool.h>

#include <gcrypt.h>

static inline bool
sha3_256(uint8_t *dst, size_t dst_len, const uint8_t *src, size_t src_len) {
  if (gcry_md_get_algo_dlen(GCRY_MD_SHA3_256) != dst_len) {
    return false;
  }

  gcry_md_hash_buffer(GCRY_MD_SHA3_256, dst, src, src_len);
  return true;
}

#endif
