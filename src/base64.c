#include "base64.h"

char *otrng_base64_encode(uint8_t *src, size_t src_len) {
  size_t l;
  char *dst = malloc(OTRNG_BASE64_ENCODE_LEN(src_len) + 1);
  if (!dst) {
    return NULL;
  }

  l = otrl_base64_encode(dst, src, src_len);
  dst[l] = '\0';

  return dst;
}
