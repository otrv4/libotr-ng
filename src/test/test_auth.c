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

void test_rsig_auth() {
  const char *msg = "hi";

  otrng_keypair_p p1, p2, p3;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1}, sym2[ED448_PRIVATE_BYTES] = {2},
          sym3[ED448_PRIVATE_BYTES] = {3};

  otrng_keypair_generate(p1, sym1);
  otrng_keypair_generate(p2, sym2);
  otrng_keypair_generate(p3, sym3);

  ring_sig_p dst2;
  otrng_rsig_authenticate(dst2, p1, p2->pub, p3->pub, (unsigned char *)msg,
                          strlen(msg));

  otrng_assert(otrng_rsig_verify(dst2, p1->pub, p2->pub, p3->pub,
                                 (unsigned char *)msg, strlen(msg)) == SUCCESS);
}

void test_rsig_auth_generic() {
  const char *msg = "hi";

  otrng_keypair_p p1, p2, p3;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1}, sym2[ED448_PRIVATE_BYTES] = {2},
          sym3[ED448_PRIVATE_BYTES] = {3};

  otrng_keypair_generate(p1, sym1);
  otrng_keypair_generate(p2, sym2);
  otrng_keypair_generate(p3, sym3);

  ring_sig_p dst;
  otrng_err ok = otrng_rsig_authenticate_generic(
      dst, p1->priv, p1->pub, p2->pub, p3->pub, p2->pub, (unsigned char *)msg,
      strlen(msg));

  otrng_assert(ok == ERROR);

  ok = otrng_rsig_authenticate_generic(dst, p1->priv, p1->pub, p1->pub, p3->pub,
                                       p1->pub, (unsigned char *)msg,
                                       strlen(msg));

  otrng_assert(ok == ERROR);

  ok = otrng_rsig_authenticate_generic(dst, p1->priv, p1->pub, p1->pub, p2->pub,
                                       p3->pub, (unsigned char *)msg,
                                       strlen(msg));

  otrng_assert(ok == SUCCESS);

  ok = otrng_rsig_verify(dst, p1->pub, p2->pub, p3->pub, (unsigned char *)msg,
                         strlen(msg));
  otrng_assert(ok == SUCCESS);

  ok = otrng_rsig_authenticate_generic(dst, p1->priv, p1->pub, p3->pub, p1->pub,
                                       p2->pub, (unsigned char *)msg,
                                       strlen(msg));

  otrng_assert(ok == SUCCESS);

  ok = otrng_rsig_verify(dst, p3->pub, p1->pub, p2->pub, (unsigned char *)msg,
                         strlen(msg));
  otrng_assert(ok == SUCCESS);
}
