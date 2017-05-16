#ifndef SMP_H
#define SMP_H

#include "fingerprint.h"
#include "str.h"		//TODO: The question is an optional DATA. So it can be any array of bytes.
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
	unsigned char *y;
	ec_scalar_t a2;
	ec_scalar_t a3;
	ec_scalar_t b3;
	ec_point_t G2;
	ec_point_t G3;
	ec_point_t G3a;
	ec_point_t Pb;
	ec_point_t Qb;
} smp_context_t[1];

typedef struct {
	char *question;
	ec_point_t G2a;
	ec_scalar_t c2;
	ec_scalar_t d2;
	ec_point_t G3a;
	ec_scalar_t c3;
	ec_scalar_t d3;
} smp_msg_1_t[1];

typedef struct {
	ec_point_t G2b;
	ec_scalar_t c2;
	ec_scalar_t d2;
	ec_point_t G3b;
	ec_scalar_t c3;
	ec_scalar_t d3;
	ec_point_t Pb;
	ec_point_t Qb;
	ec_scalar_t cp;
	ec_scalar_t d5;
	ec_scalar_t d6;
} smp_msg_2_t[1];

void smp_destroy(smp_context_t smp);

void generate_smp_secret(unsigned char **secret, otrv4_fingerprint_t our_fp,
			 otrv4_fingerprint_t their_fp, uint8_t * ssid,
			 string_t answer);

int generate_smp_msg_1(smp_msg_1_t dst, smp_context_t smp);

int smp_msg_1_aprint(uint8_t ** dst, size_t * len, const smp_msg_1_t msg);

int generate_smp_msg_2(smp_msg_2_t dst, const smp_msg_1_t msg_1,
			smp_context_t smp);

#endif
