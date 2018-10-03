#include "base64.h"
#include "alloc.h"

INTERNAL char *otrng_base64_encode(uint8_t *src, size_t src_len) {
  size_t l;
  char *destination = otrng_xmalloc_z(OTRNG_BASE64_ENCODE_LEN(src_len) + 1);

  l = otrl_base64_encode(destination, src, src_len);
  destination[l] = '\0';

  return destination;
}
