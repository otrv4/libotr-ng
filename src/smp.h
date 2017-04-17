#ifndef SMP_H
#define SMP_H

#include "fingerprint.h"
#include "str.h" //TODO: The question is an optional DATA. So it can be any array of bytes.
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
	decaf_448_scalar_t a2;
	decaf_448_scalar_t a3;
} smp_context_t[1];

typedef struct
{
	char * question;
	decaf_448_point_t G2a;
	decaf_448_scalar_t c2;
	decaf_448_scalar_t d2;
	decaf_448_point_t G3a;
	decaf_448_scalar_t c3;
	decaf_448_scalar_t d3;

} smp_msg_1_t[1];

void smp_destroy(smp_context_t smp);

void generate_smp_secret(smp_context_t smp, otrv4_fingerprint_t our_fp,
			otrv4_fingerprint_t their_fp, uint8_t * ssid,
			string_t answer);

int generate_smp_msg_1(smp_msg_1_t dst, smp_context_t smp);
int smp_msg_1_aprint(uint8_t ** dst, size_t * len, const smp_msg_1_t msg);

tlv_t *generate_smp_msg_2(void);

#endif
