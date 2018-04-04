#define OTRNG_FINGERPRINT_PRIVATE

#include "fingerprint.h"
#include "serialize.h"
#include "shake.h"

/* Convert a 56-byte hash value to a 126-byte human-readable value */
API void
otrng_fingerprint_hash_to_human(char human[FPRINT_HUMAN_LEN],
                                const unsigned char hash[FPRINT_LEN_BYTES]) {
  int word, byte;
  char *p = human;

  for (word = 0; word < 14; ++word) {
    for (byte = 0; byte < 4; ++byte) {
      sprintf(p, "%02X", hash[word * 4 + byte]);
      p += 2;
    }
    *(p++) = ' ';
  }

  /* Change that last ' ' to a '\0' */
  --p;
  *p = '\0';
}

INTERNAL int otrng_serialize_fingerprint(otrng_fingerprint_t fp,
                                         const otrng_public_key_t pub) {
  uint8_t serialized[ED448_PUBKEY_BYTES] = {0};

  if (!fp)
    return 1;

  otrng_serialize_otrng_public_key(serialized, pub);

  hash_hash(fp, sizeof(otrng_fingerprint_t), serialized, sizeof serialized);

  return 0;
}
