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

#define OTRNG_AUTH_PRIVATE

#include "auth.h"
#include "constants.h"
#include "deserialize.h"
#include "random.h"
#include "shake.h"

static const unsigned char base_point_bytes_dup[ED448_POINT_BYTES] = {
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x00,
};

/* in big endian */
static const unsigned char prime_order_bytes_dup[ED448_SCALAR_BYTES] = {
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x7c, 0xca, 0x23, 0xe9, 0xc4, 0x4e, 0xdb, 0x49,
    0xae, 0xd6, 0x36, 0x90, 0x21, 0x6c, 0xc2, 0x72, 0x8d, 0xc5, 0x8f, 0x55,
    0x23, 0x78, 0xc2, 0x92, 0xab, 0x58, 0x44, 0xf3,
};

// TODO: export this function when it replaces the old one.
// TODO: reduce the dependency on the rest of libotr-ng so it can be easily
// turned into a standalone library.
INTERNAL otrng_err otrng_rsig_authenticate_generic(
    ring_sig_s *dst, const rsig_privkey_p a, const rsig_pubkey_p pub,
    const rsig_pubkey_p A1, const rsig_pubkey_p A2, const rsig_pubkey_p A3,
    const uint8_t *msg, size_t msglen) {

  // TODO: It may be possible to optimize this by reusing the same
  // ec_scalar for multiple operations (and reduce memory usage).

  goldilocks_shake256_ctx_p hd;
  uint8_t hash[HASH_BYTES];
  unsigned char point_buff[ED448_POINT_BYTES];

  goldilocks_bool_t isA1 = goldilocks_448_point_eq(pub, A1);
  goldilocks_bool_t isA2 = goldilocks_448_point_eq(pub, A2);
  goldilocks_bool_t isA3 = goldilocks_448_point_eq(pub, A3);

  // One of A1, A2, A3 is the public counterpart of secret.
  if (!(isA1 | isA2 | isA3)) {
    return ERROR;
  }

  // And only one of them is.
  if (!(isA1 ^ isA2 ^ isA3)) {
    return ERROR;
  }

  ec_scalar_p t1, t2, t3;
  ec_point_p T1, T2, T3;
  otrng_zq_keypair_generate(T1, t1);
  otrng_zq_keypair_generate(T2, t2);
  otrng_zq_keypair_generate(T3, t3);

  ec_scalar_p r1, r2, r3;
  ec_point_p R1, R2, R3;
  otrng_zq_keypair_generate(R1, r1);
  otrng_zq_keypair_generate(R2, r2);
  otrng_zq_keypair_generate(R3, r3);

  ec_scalar_p c1, c2, c3;
  ed448_random_scalar(c1);
  ed448_random_scalar(c2);
  ed448_random_scalar(c3);

  // serT1 = secretIs1 ? T1 : R1 + A1 * c1
  // serT2 = secretIs2 ? T2 : R2 + A2 * c2
  // serT3 = secretIs3 ? T3 : R3 + A3 * c3

  ec_point_p RAc1, RAc2, RAc3;
  goldilocks_448_point_scalarmul(RAc1, A1, c1);
  goldilocks_448_point_add(RAc1, R1, RAc1);

  goldilocks_448_point_scalarmul(RAc2, A2, c2);
  goldilocks_448_point_add(RAc2, R2, RAc2);

  goldilocks_448_point_scalarmul(RAc3, A3, c3);
  goldilocks_448_point_add(RAc3, R3, RAc3);

  goldilocks_448_point_p T1_chosen, T2_chosen, T3_chosen;
  goldilocks_448_point_cond_sel(T1_chosen, RAc1, T1, isA1);
  goldilocks_448_point_cond_sel(T2_chosen, RAc2, T2, isA2);
  goldilocks_448_point_cond_sel(T3_chosen, RAc3, T3, isA3);

  uint8_t serT1[ED448_POINT_BYTES];
  uint8_t serT2[ED448_POINT_BYTES];
  uint8_t serT3[ED448_POINT_BYTES];
  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(serT1, T1_chosen);
  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(serT2, T2_chosen);
  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(serT3, T3_chosen);

  // TODO: zero RAci from the stack?
  // TODO: zero Ti_chosen from the stack?

  hash_init_with_dom(hd);
  hash_update(hd, base_point_bytes_dup, ED448_POINT_BYTES);
  hash_update(hd, prime_order_bytes_dup, ED448_SCALAR_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A1);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  hash_update(hd, serT1, ED448_POINT_BYTES);
  hash_update(hd, serT2, ED448_POINT_BYTES);
  hash_update(hd, serT3, ED448_POINT_BYTES);
  hash_update(hd, msg, msglen);
  hash_final(hd, hash, sizeof(hash));
  hash_destroy(hd);

  rsig_privkey_p c;
  goldilocks_448_scalar_decode_long(c, hash, sizeof(hash));

  ec_scalar_p c1_secret, c2_secret, c3_secret;
  goldilocks_448_scalar_sub(c1_secret, c, c2);
  goldilocks_448_scalar_sub(c1_secret, c1_secret, c3);

  goldilocks_448_scalar_sub(c2_secret, c, c3);
  goldilocks_448_scalar_sub(c2_secret, c2_secret, c1);

  goldilocks_448_scalar_sub(c3_secret, c, c2);
  goldilocks_448_scalar_sub(c3_secret, c3_secret, c1);

  // TODO: Ideally we want:
  // dst->c1 = (goldilocks_448_scalar_s*) otrng_constant_time_select(isA1 & 1,
  // c1_secret, c1).
  //
  // But we can't. Instead, we rely on:
  //
  // (i)   isA1 is 1 if pub == A1; 0 otherwise;
  // (ii)  dst->c1 = c1_secret if isA1;
  // (iii) dst->c1 = c1 if not isA1;
  //
  //  That is:
  //  dst->c1 = (c1_secret * isA1) + (c1 * (1-isA1));
  //  or:
  //  dst->c1 = (c1_secret * isA1) + c1 - (c1 * isA1);

  ec_scalar_p is_a1_scalar, is_a2_scalar, is_a3_scalar;
  goldilocks_448_scalar_set_unsigned(is_a1_scalar, isA1 & 1);
  goldilocks_448_scalar_set_unsigned(is_a2_scalar, isA2 & 1);
  goldilocks_448_scalar_set_unsigned(is_a3_scalar, isA3 & 1);

  ec_scalar_p tmp;
  goldilocks_448_scalar_mul(tmp, c1_secret, is_a1_scalar);
  goldilocks_448_scalar_add(dst->c1, c1, tmp);
  goldilocks_448_scalar_mul(tmp, c1, is_a1_scalar);
  goldilocks_448_scalar_sub(dst->c1, dst->c1, tmp);

  goldilocks_448_scalar_mul(tmp, c2_secret, is_a2_scalar);
  goldilocks_448_scalar_add(dst->c2, c2, tmp);
  goldilocks_448_scalar_mul(tmp, c2, is_a2_scalar);
  goldilocks_448_scalar_sub(dst->c2, dst->c2, tmp);

  goldilocks_448_scalar_mul(tmp, c3_secret, is_a3_scalar);
  goldilocks_448_scalar_add(dst->c3, c3, tmp);
  goldilocks_448_scalar_mul(tmp, c3, is_a3_scalar);
  goldilocks_448_scalar_sub(dst->c3, dst->c3, tmp);

  // This is analogous to how we calculate dst->c1, dst->c2, dst->c3
  ec_scalar_p r1_secret, r2_secret, r3_secret;
  goldilocks_448_scalar_mul(r1_secret, dst->c1, a);
  goldilocks_448_scalar_sub(r1_secret, t1, r1_secret);

  goldilocks_448_scalar_mul(r2_secret, dst->c2, a);
  goldilocks_448_scalar_sub(r2_secret, t2, r2_secret);

  goldilocks_448_scalar_mul(r3_secret, dst->c3, a);
  goldilocks_448_scalar_sub(r3_secret, t3, r3_secret);

  goldilocks_448_scalar_mul(tmp, r1_secret, is_a1_scalar);
  goldilocks_448_scalar_add(dst->r1, r1, tmp);
  goldilocks_448_scalar_mul(tmp, r1, is_a1_scalar);
  goldilocks_448_scalar_sub(dst->r1, dst->r1, tmp);

  goldilocks_448_scalar_mul(tmp, r2_secret, is_a2_scalar);
  goldilocks_448_scalar_add(dst->r2, r2, tmp);
  goldilocks_448_scalar_mul(tmp, r2, is_a2_scalar);
  goldilocks_448_scalar_sub(dst->r2, dst->r2, tmp);

  goldilocks_448_scalar_mul(tmp, r3_secret, is_a3_scalar);
  goldilocks_448_scalar_add(dst->r3, r3, tmp);
  goldilocks_448_scalar_mul(tmp, r3, is_a3_scalar);
  goldilocks_448_scalar_sub(dst->r3, dst->r3, tmp);

  // TODO: zero all secret scalars

  return SUCCESS;
}

// TODO: replace this function by the generic version.
INTERNAL void otrng_rsig_authenticate(ring_sig_s *dst,
                                      const rsig_keypair_s *keypair,
                                      const rsig_pubkey_p A2,
                                      const rsig_pubkey_p A3,
                                      const unsigned char *msg, size_t msglen) {

  otrng_rsig_authenticate_generic(dst, keypair->priv, keypair->pub,
                                  keypair->pub, A2, A3, msg, msglen);
}

INTERNAL otrng_bool otrng_rsig_verify(const ring_sig_s *src,
                                      const rsig_pubkey_p A1,
                                      const rsig_pubkey_p A2,
                                      const rsig_pubkey_p A3,
                                      const unsigned char *msg, size_t msglen) {
  goldilocks_shake256_ctx_p hd;
  uint8_t hash[HASH_BYTES];
  unsigned char point_buff[ED448_POINT_BYTES];

  rsig_pubkey_p gr1, gr2, gr3, A1c1, A2c2, A3c3;

  goldilocks_448_point_scalarmul(gr1, goldilocks_448_point_base, src->r1);
  goldilocks_448_point_scalarmul(gr2, goldilocks_448_point_base, src->r2);
  goldilocks_448_point_scalarmul(gr3, goldilocks_448_point_base, src->r3);

  goldilocks_448_point_scalarmul(A1c1, A1, src->c1);
  goldilocks_448_point_scalarmul(A2c2, A2, src->c2);
  goldilocks_448_point_scalarmul(A3c3, A3, src->c3);

  goldilocks_448_point_add(A1c1, A1c1, gr1);
  goldilocks_448_point_add(A2c2, A2c2, gr2);
  goldilocks_448_point_add(A3c3, A3c3, gr3);

  hash_init_with_dom(hd);
  hash_update(hd, base_point_bytes_dup, ED448_POINT_BYTES);
  hash_update(hd, prime_order_bytes_dup, ED448_SCALAR_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A1);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A1c1);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A2c2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A3c3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  hash_update(hd, msg, msglen);

  hash_final(hd, hash, sizeof(hash));
  hash_destroy(hd);

  rsig_privkey_p c, c1c2c3;
  goldilocks_448_scalar_decode_long(c, hash, sizeof(hash));

  goldilocks_448_scalar_add(c1c2c3, src->c1, src->c2);
  goldilocks_448_scalar_add(c1c2c3, c1c2c3, src->c3);

  if (GOLDILOCKS_TRUE == goldilocks_448_scalar_eq(c, c1c2c3))
    return otrng_true;

  return otrng_false;
}

INTERNAL void otrng_ring_sig_destroy(ring_sig_s *src) {
  otrng_ec_scalar_destroy(src->c1);
  otrng_ec_scalar_destroy(src->r1);
  otrng_ec_scalar_destroy(src->c2);
  otrng_ec_scalar_destroy(src->r2);
  otrng_ec_scalar_destroy(src->c3);
  otrng_ec_scalar_destroy(src->r3);
}
