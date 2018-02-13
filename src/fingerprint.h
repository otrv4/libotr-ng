#ifndef OTRV4_FINGERPRINT_H
#define OTRV4_FINGERPRINT_H

#include <stdint.h>
#include <stdio.h>

#include "keys.h"
#include "shared.h"

#define FPRINT_LEN_BYTES 56
#define FPRINT_HUMAN_LEN 126 // 56 / 4 * 9

typedef uint8_t otrv4_fingerprint_t[FPRINT_LEN_BYTES];
typedef uint8_t otrv3_fingerprint_t[20];

API void
otrv4_fingerprint_hash_to_human(char human[FPRINT_HUMAN_LEN],
                                const unsigned char hash[FPRINT_LEN_BYTES]);

INTERNAL int otrv4_serialize_fingerprint(otrv4_fingerprint_t fp,
                                         const otrv4_public_key_t pub);

#ifdef OTRV4_FINGERPRINT_PRIVATE
#endif

#endif
