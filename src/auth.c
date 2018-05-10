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

static void choose_T(goldilocks_448_point_p chosen,
                     const goldilocks_448_point_p Ai, uint8_t is_secret,
                     const goldilocks_448_point_p Ri,
                     const goldilocks_448_point_p Ti,
                     const goldilocks_448_scalar_p ci) {
  // Ti = is_secret_i ? Ti : Ri + Ai * ci
  goldilocks_448_point_scalarmul(chosen, Ai, ci);
  goldilocks_448_point_add(chosen, Ri, chosen);

  goldilocks_448_point_cond_sel(chosen, chosen, Ti, is_secret);
}

static void scalar_select(goldilocks_448_scalar_p dst,
                          const goldilocks_448_scalar_p a,
                          const goldilocks_448_scalar_p b, uint8_t select_b) {
  // TODO: Ideally we want:
  // goldilocks_448_scalar_cond_sel but it segfaults on some gcc (see build for:
  // 75493e1a9ab9ebde445f68b3981950aca6c6443b).
  goldilocks_448_scalar_p select_b_scalar, tmp;
  goldilocks_448_scalar_set_unsigned(select_b_scalar, select_b & 1);

  // do the constant time select between a and b;
  // ci = (b * select_b) + (a * (1-select_b));
  goldilocks_448_scalar_mul(tmp, b, select_b_scalar);
  goldilocks_448_scalar_add(dst, tmp, a);
  goldilocks_448_scalar_mul(tmp, a, select_b_scalar);
  goldilocks_448_scalar_sub(dst, dst, tmp);

  goldilocks_448_scalar_destroy(tmp);
  goldilocks_448_scalar_destroy(select_b_scalar);
}

static void calculate_ci(goldilocks_448_scalar_p dst,
                         const goldilocks_448_scalar_p c,
                         const goldilocks_448_scalar_p ci, uint8_t is_secret,
                         const goldilocks_448_scalar_p cj,
                         const goldilocks_448_scalar_p ck) {
  // if_secret = c - c2 - c3 or c - c1 - c3 or c - c1 - c2
  goldilocks_448_scalar_p if_secret;

  goldilocks_448_scalar_sub(if_secret, c, cj);
  goldilocks_448_scalar_sub(if_secret, if_secret, ck);
  scalar_select(dst, ci, if_secret, is_secret & 1);

  goldilocks_448_scalar_destroy(if_secret);
}

static void calculate_ri(goldilocks_448_scalar_p dst,
                         const goldilocks_448_scalar_p secret,
                         const goldilocks_448_scalar_p ri, uint8_t is_secret,
                         const goldilocks_448_scalar_p ci,
                         const goldilocks_448_scalar_p ti) {
  // if_secret = t1 - c1 * secret OR t2 - c2 * secret OR t3 - c3 * secret
  goldilocks_448_scalar_p if_secret;
  goldilocks_448_scalar_mul(if_secret, ci, secret);
  goldilocks_448_scalar_sub(if_secret, ti, if_secret);

  scalar_select(dst, ri, if_secret, is_secret & 1);

  goldilocks_448_scalar_destroy(if_secret);
}

void otrng_rsig_calculate_c(
    goldilocks_448_scalar_p dst, const goldilocks_448_point_p A1,
    const goldilocks_448_point_p A2, const goldilocks_448_point_p A3,
    const goldilocks_448_point_p T1, const goldilocks_448_point_p T2,
    const goldilocks_448_point_p T3, const uint8_t *msg, size_t msglen) {
  goldilocks_shake256_ctx_p hd;
  uint8_t hash[HASH_BYTES];
  uint8_t point_buff[ED448_POINT_BYTES];

  hash_init_with_dom(hd);
  hash_update(hd, base_point_bytes_dup, ED448_POINT_BYTES);
  hash_update(hd, prime_order_bytes_dup, ED448_SCALAR_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A1);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, T1);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, T2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, T3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  hash_update(hd, msg, msglen);

  hash_final(hd, hash, sizeof(hash));
  hash_destroy(hd);

  goldilocks_448_scalar_decode_long(dst, hash, sizeof(hash));
}

INTERNAL otrng_err otrng_rsig_authenticate(
    ring_sig_s *dst, const rsig_privkey_p secret, const rsig_pubkey_p pub,
    const rsig_pubkey_p A1, const rsig_pubkey_p A2, const rsig_pubkey_p A3,
    const uint8_t *msg, size_t msglen) {
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

  goldilocks_448_scalar_p t1, t2, t3;
  goldilocks_448_point_p T1, T2, T3;
  otrng_zq_keypair_generate(T1, t1);
  otrng_zq_keypair_generate(T2, t2);
  otrng_zq_keypair_generate(T3, t3);

  goldilocks_448_scalar_p r1, r2, r3;
  goldilocks_448_point_p R1, R2, R3;
  otrng_zq_keypair_generate(R1, r1);
  otrng_zq_keypair_generate(R2, r2);
  otrng_zq_keypair_generate(R3, r3);

  goldilocks_448_scalar_p c1, c2, c3;
  ed448_random_scalar(c1);
  ed448_random_scalar(c2);
  ed448_random_scalar(c3);

  // chosenT1 = secretIs1 ? T1 : R1 + A1 * c1
  // chosenT2 = secretIs2 ? T2 : R2 + A2 * c2
  // chosenT3 = secretIs3 ? T3 : R3 + A3 * c3

  goldilocks_448_point_p chosenT1, chosenT2, chosenT3;
  choose_T(chosenT1, A1, isA1, R1, T1, c1);
  choose_T(chosenT2, A2, isA2, R2, T2, c2);
  choose_T(chosenT3, A3, isA3, R3, T3, c3);

  goldilocks_448_point_destroy(T1);
  goldilocks_448_point_destroy(T2);
  goldilocks_448_point_destroy(T3);
  goldilocks_448_point_destroy(R1);
  goldilocks_448_point_destroy(R2);
  goldilocks_448_point_destroy(R3);

  goldilocks_448_scalar_p c;
  otrng_rsig_calculate_c(c, A1, A2, A3, chosenT1, chosenT2, chosenT3, msg,
                         msglen);

  goldilocks_448_point_destroy(chosenT1);
  goldilocks_448_point_destroy(chosenT2);
  goldilocks_448_point_destroy(chosenT3);

  // c1 = secretIs1 ? c - c2 - c3 : c1
  // c2 = secretIs2 ? c - c1 - c3 : c2
  // c3 = secretIs3 ? c - c1 - c2 : c3
  calculate_ci(dst->c1, c, c1, isA1, c2, c3);
  calculate_ci(dst->c2, c, c2, isA2, c1, c3);
  calculate_ci(dst->c3, c, c3, isA3, c1, c2);

  goldilocks_448_scalar_destroy(c);
  goldilocks_448_scalar_destroy(c1);
  goldilocks_448_scalar_destroy(c2);
  goldilocks_448_scalar_destroy(c3);

  // t1 = secretIs1 ? t1 - c1 * secret : t1
  // t2 = secretIs2 ? t2 - c2 * secret : t2
  // t3 = secretIs3 ? t3 - c3 * secret : t3
  calculate_ri(dst->r1, secret, r1, isA1, dst->c1, t1);
  calculate_ri(dst->r2, secret, r2, isA2, dst->c2, t2);
  calculate_ri(dst->r3, secret, r3, isA3, dst->c3, t3);

  goldilocks_448_scalar_destroy(t1);
  goldilocks_448_scalar_destroy(t2);
  goldilocks_448_scalar_destroy(t3);
  goldilocks_448_scalar_destroy(r1);
  goldilocks_448_scalar_destroy(r2);
  goldilocks_448_scalar_destroy(r3);

  return SUCCESS;
}

void otrng_rsig_calculate_c_from_sigma(goldilocks_448_scalar_p c,
                                       const ring_sig_s *src,
                                       const rsig_pubkey_p A1,
                                       const rsig_pubkey_p A2,
                                       const rsig_pubkey_p A3,
                                       const uint8_t *msg, size_t msglen) {
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

  otrng_rsig_calculate_c(c, A1, A2, A3, A1c1, A2c2, A3c3, msg, msglen);
}

INTERNAL otrng_bool otrng_rsig_verify(const ring_sig_s *src,
                                      const rsig_pubkey_p A1,
                                      const rsig_pubkey_p A2,
                                      const rsig_pubkey_p A3,
                                      const uint8_t *msg, size_t msglen) {
  goldilocks_448_scalar_p c;
  otrng_rsig_calculate_c_from_sigma(c, src, A1, A2, A3, msg, msglen);

  rsig_privkey_p c1c2c3;
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
