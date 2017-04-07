#include "../otrv4.h"
#include "../smp.h"
#include "../tlv.h"

void test_smp_state_machine(void)
{
	cs_keypair_t keypair;
	cs_keypair_generate(keypair);
	otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V4};
	otrv4_t *alice_otr = otrv4_new(keypair, policy);
	otrv4_t *bob_otr = otrv4_new(keypair, policy);

	g_assert_cmpint(alice_otr->smp->state, ==, SMPSTATE_EXPECT1);

	tlv_t *smp_msg_1 = otrv4_smp_initiate(alice_otr, "");
	otrv4_assert(!smp_msg_1);

	//Should be in ecrypted state before perform SMP
	//Do DAKE
	alice_otr->state = OTRV4_STATE_ENCRYPTED_MESSAGES;

	smp_msg_1 = otrv4_smp_initiate(alice_otr, "answer");
	otrv4_assert(smp_msg_1);
	g_assert_cmpint(alice_otr->smp->state, ==, SMPSTATE_EXPECT2);

	//If Bob receives SMP msg when he's in not encrypted state,
	//his SMP state should be expecting msg1
	bob_otr->state = OTRV4_STATE_FINISHED;
	bob_otr->smp->state = SMPSTATE_EXPECT2;

	tlv_t * smp_msg_2 = otrv4_process_smp(bob_otr, smp_msg_1);
	g_assert_cmpint(bob_otr->smp->state, ==, SMPSTATE_EXPECT1);
	otrv4_assert(!smp_msg_2);

	bob_otr->state = OTRV4_STATE_ENCRYPTED_MESSAGES;
	smp_msg_2 = otrv4_process_smp(bob_otr, smp_msg_1);
	otrv4_assert(smp_msg_2);
	g_assert_cmpint(smp_msg_2->type, ==, OTRV4_TLV_SMP_MSG_2);
	g_assert_cmpint(bob_otr->smp->state, ==, SMPSTATE_EXPECT3);
};
