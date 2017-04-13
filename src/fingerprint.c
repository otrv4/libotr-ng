#include "fingerprint.h"
#include "serialize.h"
#include "sha3.h"

/* Convert a 64-byte hash value to a 145-byte human-readable value */
void
otr4_fingerprint_hash_to_human(char human[OTR4_FPRINT_HUMAN_LEN],
			       const unsigned char hash[OTR4_FPRINT_LEN_BYTES])
{
	int word, byte;
	char *p = human;

	for (word = 0; word < 16; ++word) {
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

int otr4_serialize_fingerprint(otrv4_fingerprint_t fp,
			       const otrv4_public_key_t pub)
{
	uint8_t serialized[ED448_PUBKEY_BYTES] = { 0 };

	if (!fp)
		return 1;

	serialize_otrv4_public_key(serialized, pub);

	return !sha3_512(fp, sizeof(otrv4_fingerprint_t), serialized,
			 sizeof(serialized));
}
