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
      0xc5, 0x42, 0x02, 0x79, 0x30, 0x67, 0x14, 0xce, 0x99, 0x89, 0xfa, 0xab,
      0x10, 0x24, 0x4e, 0x1d, 0x51, 0x86, 0x3f, 0x36, 0x59, 0xa7, 0x90, 0x8e,
      0x3c, 0x65, 0x1c, 0x0a, 0x1e, 0x4d, 0x16, 0x22, 0x9c, 0x0a, 0xa7, 0x61,
      0x31, 0x62, 0xcc, 0x82, 0x2a, 0x7e, 0x31, 0x07, 0x4d, 0x5a, 0x60, 0xff,
      0x84, 0x87, 0x6b, 0x00, 0xc9, 0xaa, 0x01, 0x2f,
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
  otrng_assert(!otrng_rsig_authenticate(dst, p1->priv, p1->pub, p2->pub,
                                        p3->pub, p2->pub, (unsigned char *)msg,
                                        strlen(msg)));

  otrng_assert(!otrng_rsig_authenticate(dst, p1->priv, p1->pub, p1->pub,
                                        p3->pub, p1->pub, (unsigned char *)msg,
                                        strlen(msg)));

  otrng_assert(otrng_rsig_authenticate(dst, p1->priv, p1->pub, p1->pub, p2->pub,
                                       p3->pub, (unsigned char *)msg,
                                       strlen(msg)));

  otrng_assert_is_success(otrng_rsig_verify(dst, p1->pub, p2->pub, p3->pub,
                                            (unsigned char *)msg, strlen(msg)));

  otrng_assert(otrng_rsig_authenticate(dst, p1->priv, p1->pub, p3->pub, p1->pub,
                                       p2->pub, (unsigned char *)msg,
                                       strlen(msg)));

  otrng_assert(otrng_rsig_verify(dst, p3->pub, p1->pub, p2->pub,
                                 (unsigned char *)msg, strlen(msg)));
}
