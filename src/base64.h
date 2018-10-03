
#ifndef OTRNG_B64_H
#define OTRNG_B64_H

#define OTRNG_BASE64_ENCODE_LEN(x) (((x + 2) / 3) * 4)
#define OTRNG_BASE64_DECODE_LEN(x) (((x + 3) / 4) * 3)

#ifndef S_SPLINT_S
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <libotr/b64.h>
#pragma clang diagnostic pop
#endif

#include <stdint.h>

#include "shared.h"

INTERNAL char *otrng_base64_encode(uint8_t *source, size_t source_len);

#endif
