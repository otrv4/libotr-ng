/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <glib.h>
#include <string.h>

#include "../auth.h"
#include "../dake.h"
#include "../serialize.h"

// TODO: include somewhere else or remove
void test_snizkpk_auth() {
  snizkpk_proof_t dst[1];
  snizkpk_keypair_t pair1[1], pair2[1], pair3[1];
  const char *msg = "hi";

  otrng_snizkpk_keypair_generate(pair1);
  otrng_snizkpk_keypair_generate(pair2);
  otrng_snizkpk_keypair_generate(pair3);

  otrng_snizkpk_authenticate(dst, pair1, pair2->pub, pair3->pub,
                             (unsigned char *)msg, strlen(msg));

  otrng_assert(otrng_snizkpk_verify(dst, pair1->pub, pair2->pub, pair3->pub,
                                    (unsigned char *)msg,
                                    strlen(msg)) == SUCCESS);

  // Serialize and deserialize things.
  otrng_keypair_t p1[1], p2[1], p3[1];
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1}, sym2[ED448_PRIVATE_BYTES] = {2},
          sym3[ED448_PRIVATE_BYTES] = {3};

  otrng_keypair_generate(p1, sym1);
  otrng_keypair_generate(p2, sym2);
  otrng_keypair_generate(p3, sym3);

  snizkpk_proof_t dst2[1];
  otrng_snizkpk_authenticate(dst2, p1, p2->pub, p3->pub, (unsigned char *)msg,
                             strlen(msg));

  otrng_assert(otrng_snizkpk_verify(dst2, p1->pub, p2->pub, p3->pub,
                                    (unsigned char *)msg,
                                    strlen(msg)) == SUCCESS);
}
