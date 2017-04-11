#ifndef SMP_H
#define SMP_H

#include "fingerprint.h"
#include "str.h"
#include "tlv.h"

#define SMP_VERSION 0x01
#define SMP_MIN_SECRET_BYTES (1+64*2+8)

typedef enum {
	SMPSTATE_EXPECT1,
	SMPSTATE_EXPECT2,
	SMPSTATE_EXPECT3
} smp_state_t;

typedef struct {
	smp_state_t state;
	unsigned char *x;
} smp_context_t[1];

void smp_destroy(smp_context_t smp);

void generate_smp_secret(smp_context_t smp, otrv4_fingerprint_t our_fp,
			otrv4_fingerprint_t their_fp, uint8_t * ssid,
			string_t answer);

tlv_t *generate_smp_msg_1(smp_context_t smp, string_t answer);
tlv_t *generate_smp_msg_2(void);

#endif
