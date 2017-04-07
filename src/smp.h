#ifndef SMP_H
#define SMP_H

#include "str.h"
#include "tlv.h"

typedef enum {
	SMPSTATE_EXPECT1,
	SMPSTATE_EXPECT2,
	SMPSTATE_EXPECT3
} smp_state_t;

typedef struct {
	smp_state_t state;
} smp_context_t[1];

tlv_t *generate_smp_msg_1(smp_context_t smp, string_t answer);
tlv_t *generate_smp_msg_2(void);

#endif
