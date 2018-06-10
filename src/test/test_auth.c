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

void test_rsig_calculate_c() {
  const char *msg = "hey";
  uint8_t expected_c[ED448_SCALAR_BYTES] = {
      0xd1, 0x87, 0xa3, 0x94, 0x08, 0x15, 0xc5, 0xbd, 0xee, 0xc3, 0x8b, 0x7e,
      0xe3, 0xcd, 0xdd, 0xe9, 0x4f, 0x5f, 0xff, 0x4a, 0x3e, 0xd4, 0xa4, 0x91,
      0x57, 0x9d, 0xf9, 0x3a, 0x74, 0x75, 0xc3, 0x13, 0x3b, 0xbd, 0x7d, 0xe3,
      0xa7, 0x08, 0x00, 0x88, 0xfc, 0x5c, 0x87, 0x1c, 0x16, 0x52, 0x5c, 0xd8,
      0x1d, 0x90, 0x51, 0x5b, 0xef, 0x09, 0xc8, 0x37,
  };

  otrng_keypair_p a1, a2, a3, t1, t2, t3;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1}, sym2[ED448_PRIVATE_BYTES] = {2},
          sym3[ED448_PRIVATE_BYTES] = {3}, sym4[ED448_PRIVATE_BYTES] = {4},
          sym5[ED448_PRIVATE_BYTES] = {5}, sym6[ED448_PRIVATE_BYTES] = {6};

  otrng_keypair_generate(a1, sym1);
  otrng_keypair_generate(a2, sym2);
  otrng_keypair_generate(a3, sym3);
  otrng_keypair_generate(t1, sym4);
  otrng_keypair_generate(t2, sym5);
  otrng_keypair_generate(t3, sym6);

  goldilocks_448_scalar_p c;
  otrng_rsig_calculate_c(c, a1->pub, a2->pub, a3->pub, t1->pub, t2->pub,
                         t3->pub, (const uint8_t *)msg, strlen(msg));

  uint8_t serialized_c[ED448_SCALAR_BYTES] = {0};
  goldilocks_448_scalar_encode(serialized_c, c);
  otrng_assert_cmpmem(expected_c, serialized_c, ED448_SCALAR_BYTES);
}

void test_rsig_auth() {
  const char *msg = "hi";

  otrng_keypair_p p1, p2, p3;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {}, sym2[ED448_PRIVATE_BYTES] = {},
          sym3[ED448_PRIVATE_BYTES] = {};

  random_bytes(sym1, ED448_PRIVATE_BYTES);
  random_bytes(sym2, ED448_PRIVATE_BYTES);
  random_bytes(sym3, ED448_PRIVATE_BYTES);

  otrng_keypair_generate(p1, sym1);
  otrng_keypair_generate(p2, sym2);
  otrng_keypair_generate(p3, sym3);

  ring_sig_p dst;
  otrng_assert(otrng_rsig_authenticate(dst, p1->priv, p1->pub, p2->pub, p3->pub,
                                       p2->pub, (unsigned char *)msg,
                                       strlen(msg)) == ERROR);

  otrng_assert(otrng_rsig_authenticate(dst, p1->priv, p1->pub, p1->pub, p3->pub,
                                       p1->pub, (unsigned char *)msg,
                                       strlen(msg)) == ERROR);

  otrng_assert(otrng_rsig_authenticate(dst, p1->priv, p1->pub, p1->pub, p2->pub,
                                       p3->pub, (unsigned char *)msg,
                                       strlen(msg)) == SUCCESS);

  otrng_assert(otrng_rsig_verify(dst, p1->pub, p2->pub, p3->pub,
                                 (unsigned char *)msg, strlen(msg)) == SUCCESS);

  otrng_assert(otrng_rsig_authenticate(dst, p1->priv, p1->pub, p3->pub, p1->pub,
                                       p2->pub, (unsigned char *)msg,
                                       strlen(msg)) == SUCCESS);

  otrng_assert(otrng_rsig_verify(dst, p3->pub, p1->pub, p2->pub,
                                 (unsigned char *)msg, strlen(msg)) == SUCCESS);
}
