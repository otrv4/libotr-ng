#include "base64.h"
#include "alloc.h"

INTERNAL char *otrng_base64_encode(uint8_t *source, size_t source_len) {
  size_t l;
  char *destination = otrng_xmalloc_z(OTRNG_BASE64_ENCODE_LEN(source_len) + 1);

  l = otrl_base64_encode(destination, source, source_len);
  destination[l] = '\0';

  return destination;
}
