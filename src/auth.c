/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
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

// TODO: @ed448 Change this. Mike sent it ;)
static const uint8_t base_point_bytes_dup[ED448_POINT_BYTES] = {
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x00,
};

/* in big endian */
static const uint8_t prime_order_bytes_dup[ED448_SCALAR_BYTES] = {
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

static void calculate_ci(goldilocks_448_scalar_p dst,
                         const goldilocks_448_scalar_p c,
                         const goldilocks_448_scalar_p ci,
                         goldilocks_bool_t is_secret,
                         const goldilocks_448_scalar_p cj,
                         const goldilocks_448_scalar_p ck) {
  // if_secret = c - c2 - c3 or c - c1 - c3 or c - c1 - c2
  goldilocks_448_scalar_p if_secret;

  goldilocks_448_scalar_sub(if_secret, c, cj);
  goldilocks_448_scalar_sub(if_secret, if_secret, ck);
  goldilocks_448_scalar_cond_sel(dst, ci, if_secret, is_secret);

  goldilocks_448_scalar_destroy(if_secret);
}

static void calculate_ri(goldilocks_448_scalar_p dst,
                         const goldilocks_448_scalar_p secret,
                         const goldilocks_448_scalar_p ri,
                         goldilocks_bool_t is_secret,
                         const goldilocks_448_scalar_p ci,
                         const goldilocks_448_scalar_p ti) {
  // if_secret = t1 - c1 * secret OR t2 - c2 * secret OR t3 - c3 * secret
  goldilocks_448_scalar_p if_secret;
  goldilocks_448_scalar_mul(if_secret, ci, secret);
  goldilocks_448_scalar_sub(if_secret, ti, if_secret);

  goldilocks_448_scalar_cond_sel(dst, ri, if_secret, is_secret);

  goldilocks_448_scalar_destroy(if_secret);
}

tstatic void otrng_rsig_calculate_c_with_usage_and_domain(
    uint8_t usage_auth, const char *domain_sep, goldilocks_448_scalar_p dst,
    const goldilocks_448_point_p A1, const goldilocks_448_point_p A2,
    const goldilocks_448_point_p A3, const goldilocks_448_point_p T1,
    const goldilocks_448_point_p T2, const goldilocks_448_point_p T3,
    const uint8_t *message, size_t message_len) {
  goldilocks_shake256_ctx_p hd;
  uint8_t hash[HASH_BYTES];
  uint8_t point_buff[ED448_POINT_BYTES];

  hash_init_with_usage_and_domain_separation(hd, usage_auth, domain_sep);
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

  hash_update(hd, message, message_len);

  hash_final(hd, hash, sizeof(hash));
  hash_destroy(hd);

  goldilocks_448_scalar_decode_long(dst, hash, sizeof(hash));
}

static void otrng_rsig_calculate_c_from_sigma_with_usage_and_domain(
    uint8_t usage, const char *domain_sep, goldilocks_448_scalar_p c,
    const ring_sig_p src, const otrng_public_key_p A1,
    const otrng_public_key_p A2, const otrng_public_key_p A3,
    const uint8_t *message, size_t message_len) {
  otrng_public_key_p gr1, gr2, gr3, A1c1, A2c2, A3c3;

  goldilocks_448_point_scalarmul(gr1, goldilocks_448_point_base, src->r1);
  goldilocks_448_point_scalarmul(gr2, goldilocks_448_point_base, src->r2);
  goldilocks_448_point_scalarmul(gr3, goldilocks_448_point_base, src->r3);

  goldilocks_448_point_scalarmul(A1c1, A1, src->c1);
  goldilocks_448_point_scalarmul(A2c2, A2, src->c2);
  goldilocks_448_point_scalarmul(A3c3, A3, src->c3);

  goldilocks_448_point_add(A1c1, A1c1, gr1);
  goldilocks_448_point_add(A2c2, A2c2, gr2);
  goldilocks_448_point_add(A3c3, A3c3, gr3);

  otrng_rsig_calculate_c_with_usage_and_domain(
      usage, domain_sep, c, A1, A2, A3, A1c1, A2c2, A3c3, message, message_len);
}

INTERNAL otrng_result otrng_rsig_authenticate(
    ring_sig_p dst, const otrng_private_key_p secret,
    const otrng_public_key_p pub, const otrng_public_key_p A1,
    const otrng_public_key_p A2, const otrng_public_key_p A3,
    const uint8_t *message, size_t message_len) {
  return otrng_rsig_authenticate_with_usage_and_domain(
      OTRNG_PROTOCOL_USAGE_AUTH, OTRNG_PROTOCOL_DOMAIN_SEPARATION, dst, secret,
      pub, A1, A2, A3, message, message_len);
}

INTERNAL otrng_result otrng_rsig_authenticate_with_usage_and_domain(
    uint8_t usage, const char *domain_sep, ring_sig_p dst,
    const otrng_private_key_p secret, const otrng_public_key_p pub,
    const otrng_public_key_p A1, const otrng_public_key_p A2,
    const otrng_public_key_p A3, const uint8_t *message, size_t message_len) {
  goldilocks_bool_t is_A1 = goldilocks_448_point_eq(pub, A1);
  goldilocks_bool_t is_A2 = goldilocks_448_point_eq(pub, A2);
  goldilocks_bool_t is_A3 = goldilocks_448_point_eq(pub, A3);
  goldilocks_448_scalar_p t1, t2, t3;
  goldilocks_448_point_p T1, T2, T3;
  goldilocks_448_scalar_p r1, r2, r3;
  goldilocks_448_point_p R1, R2, R3;
  goldilocks_448_scalar_p c1, c2, c3;
  goldilocks_448_point_p chosen_T1, chosen_T2, chosen_T3;
  goldilocks_448_scalar_p tmp_c1, tmp_c2, tmp_c3;
  goldilocks_448_scalar_p tmp_r1, tmp_r2, tmp_r3;
  goldilocks_448_scalar_p c;

  // One of A1, A2, A3 is the public counterpart of secret.
  if (!(is_A1 | is_A2 | is_A3)) {
    return OTRNG_ERROR;
  }

  // And only one of them is.
  if (!(is_A1 ^ is_A2 ^ is_A3)) {
    return OTRNG_ERROR;
  }

  otrng_zq_keypair_generate(T1, t1);
  otrng_zq_keypair_generate(T2, t2);
  otrng_zq_keypair_generate(T3, t3);

  otrng_zq_keypair_generate(R1, r1);
  otrng_zq_keypair_generate(R2, r2);
  otrng_zq_keypair_generate(R3, r3);

  ed448_random_scalar(c1);
  ed448_random_scalar(c2);
  ed448_random_scalar(c3);

  // chosen_T1 = is_A1 ? T1 : R1 + A1 * c1
  // chosen_T2 = is_A2 ? T2 : R2 + A2 * c2
  // chosen_T3 = is_A3 ? T3 : R3 + A3 * c3
  choose_T(chosen_T1, A1, is_A1, R1, T1, c1);
  choose_T(chosen_T2, A2, is_A2, R2, T2, c2);
  choose_T(chosen_T3, A3, is_A3, R3, T3, c3);

  goldilocks_448_point_destroy(T1);
  goldilocks_448_point_destroy(T2);
  goldilocks_448_point_destroy(T3);
  goldilocks_448_point_destroy(R1);
  goldilocks_448_point_destroy(R2);
  goldilocks_448_point_destroy(R3);

  otrng_rsig_calculate_c_with_usage_and_domain(usage, domain_sep, c, A1, A2, A3,
                                               chosen_T1, chosen_T2, chosen_T3,
                                               message, message_len);

  goldilocks_448_point_destroy(chosen_T1);
  goldilocks_448_point_destroy(chosen_T2);
  goldilocks_448_point_destroy(chosen_T3);

  // c1 = is_A1 ? c - c2 - c3 : c1
  // c2 = is_A2 ? c - c1 - c3 : c2
  // c3 = is_A3 ? c - c1 - c2 : c3

  calculate_ci(tmp_c1, c, c1, is_A1, c2, c3);
  calculate_ci(tmp_c2, c, c2, is_A2, c1, c3);
  calculate_ci(tmp_c3, c, c3, is_A3, c1, c2);

  goldilocks_448_scalar_copy(dst->c1, tmp_c1);
  goldilocks_448_scalar_copy(dst->c2, tmp_c2);
  goldilocks_448_scalar_copy(dst->c3, tmp_c3);

  goldilocks_448_scalar_destroy(c);
  goldilocks_448_scalar_destroy(c1);
  goldilocks_448_scalar_destroy(c2);
  goldilocks_448_scalar_destroy(c3);
  goldilocks_448_scalar_destroy(tmp_c1);
  goldilocks_448_scalar_destroy(tmp_c2);
  goldilocks_448_scalar_destroy(tmp_c3);

  // t1 = secretIs1 ? t1 - c1 * secret : t1
  // t2 = secretIs2 ? t2 - c2 * secret : t2
  // t3 = secretIs3 ? t3 - c3 * secret : t3

  calculate_ri(tmp_r1, secret, r1, is_A1, dst->c1, t1);
  calculate_ri(tmp_r2, secret, r2, is_A2, dst->c2, t2);
  calculate_ri(tmp_r3, secret, r3, is_A3, dst->c3, t3);

  goldilocks_448_scalar_copy(dst->r1, tmp_r1);
  goldilocks_448_scalar_copy(dst->r2, tmp_r2);
  goldilocks_448_scalar_copy(dst->r3, tmp_r3);

  goldilocks_448_scalar_destroy(t1);
  goldilocks_448_scalar_destroy(t2);
  goldilocks_448_scalar_destroy(t3);
  goldilocks_448_scalar_destroy(r1);
  goldilocks_448_scalar_destroy(r2);
  goldilocks_448_scalar_destroy(r3);
  goldilocks_448_scalar_destroy(tmp_r1);
  goldilocks_448_scalar_destroy(tmp_r2);
  goldilocks_448_scalar_destroy(tmp_r3);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_bool otrng_rsig_verify(const ring_sig_p src,
                                      const otrng_public_key_p A1,
                                      const otrng_public_key_p A2,
                                      const otrng_public_key_p A3,
                                      const uint8_t *message,
                                      size_t message_len) {
  return otrng_rsig_verify_with_usage_and_domain(
      OTRNG_PROTOCOL_USAGE_AUTH, OTRNG_PROTOCOL_DOMAIN_SEPARATION, src, A1, A2,
      A3, message, message_len);
}

INTERNAL otrng_bool otrng_rsig_verify_with_usage_and_domain(
    uint8_t usage, const char *domain_sep, const ring_sig_p src,
    const otrng_public_key_p A1, const otrng_public_key_p A2,
    const otrng_public_key_p A3, const uint8_t *message, size_t message_len) {
  goldilocks_448_scalar_p c;
  otrng_private_key_p c1c2c3;

  otrng_rsig_calculate_c_from_sigma_with_usage_and_domain(
      usage, domain_sep, c, src, A1, A2, A3, message, message_len);

  goldilocks_448_scalar_add(c1c2c3, src->c1, src->c2);
  goldilocks_448_scalar_add(c1c2c3, c1c2c3, src->c3);

  if (goldilocks_succeed_if(goldilocks_448_scalar_eq(c, c1c2c3))) {
    return otrng_true;
  }

  return otrng_false;
}

INTERNAL void otrng_ring_sig_destroy(ring_sig_p src) {
  otrng_ec_scalar_destroy(src->c1);
  otrng_ec_scalar_destroy(src->r1);
  otrng_ec_scalar_destroy(src->c2);
  otrng_ec_scalar_destroy(src->r2);
  otrng_ec_scalar_destroy(src->c3);
  otrng_ec_scalar_destroy(src->r3);
}
