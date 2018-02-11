#ifndef OTRV4_FINGERPRINT_H
#define OTRV4_FINGERPRINT_H

#include <stdint.h>
#include <stdio.h>

#include "keys.h"

#define OTR4_FPRINT_LEN_BYTES 56
#define OTR4_FPRINT_HUMAN_LEN 126 // 56 / 4 * 9

typedef uint8_t otrv4_fingerprint_t[OTR4_FPRINT_LEN_BYTES];
typedef uint8_t otrv3_fingerprint_t[20];

void otr4_fingerprint_hash_to_human(
    char human[OTR4_FPRINT_HUMAN_LEN],
    const unsigned char hash[OTR4_FPRINT_LEN_BYTES]);

int otr4_serialize_fingerprint(otrv4_fingerprint_t fp,
                               const otrv4_public_key_t pub);

#endif
