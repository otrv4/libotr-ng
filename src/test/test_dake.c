#include <glib.h>
#include <string.h>

#include "../auth.h"
#include "../dake.h"
#include "../serialize.h"

void test_snizkpk_auth() {
  snizkpk_proof_t dst[1];
  snizkpk_keypair_t pair1[1], pair2[1], pair3[1];
  const char *msg = "hi";

  otrv4_snizkpk_keypair_generate(pair1);
  otrv4_snizkpk_keypair_generate(pair2);
  otrv4_snizkpk_keypair_generate(pair3);

  otrv4_snizkpk_authenticate(dst, pair1, pair2->pub, pair3->pub, (unsigned char *)msg,
                       strlen(msg));

  otrv4_assert(otrv4_snizkpk_verify(dst, pair1->pub, pair2->pub, pair3->pub,
                              (unsigned char *)msg,
                              strlen(msg)) == SUCCESS);

  // Serialize and deserialize things.
  otrv4_keypair_t p1[1], p2[1], p3[1];
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1}, sym2[ED448_PRIVATE_BYTES] = {2},
          sym3[ED448_PRIVATE_BYTES] = {3};

  otrv4_keypair_generate(p1, sym1);
  otrv4_keypair_generate(p2, sym2);
  otrv4_keypair_generate(p3, sym3);

  snizkpk_proof_t dst2[1];
  otrv4_snizkpk_authenticate(dst2, p1, p2->pub, p3->pub, (unsigned char *)msg,
                       strlen(msg));

  otrv4_assert(otrv4_snizkpk_verify(dst2, p1->pub, p2->pub, p3->pub,
                              (unsigned char *)msg,
                              strlen(msg)) == SUCCESS);
}
