
#ifndef OTRNG_B64_H
#define OTRNG_B64_H

#define OTRNG_BASE64_ENCODE_LEN(x) (((x + 2) / 3) * 4)

#include <libotr/b64.h>
#include <stdint.h>

char *otrng_base64_encode(uint8_t *src, size_t src_len);

#endif
