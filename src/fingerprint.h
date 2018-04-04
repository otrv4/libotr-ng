#ifndef OTRNG_FINGERPRINT_H
#define OTRNG_FINGERPRINT_H

#include <stdint.h>
#include <stdio.h>

#include "keys.h"
#include "shared.h"

#define FPRINT_LEN_BYTES 56
#define FPRINT_HUMAN_LEN 126 // 56 / 4 * 9

typedef uint8_t otrng_fingerprint_t[FPRINT_LEN_BYTES];
typedef uint8_t v3_fingerprint_t[20];

API void
otrng_fingerprint_hash_to_human(char human[FPRINT_HUMAN_LEN],
                                const unsigned char hash[FPRINT_LEN_BYTES]);

INTERNAL int otrng_serialize_fingerprint(otrng_fingerprint_t fp,
                                         const otrng_public_key_t pub);

#ifdef OTRNG_FINGERPRINT_PRIVATE
#endif

#endif
