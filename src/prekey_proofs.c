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

#define OTRNG_PREKEY_PROOFS_PRIVATE

#include "prekey_proofs.h"
#include "alloc.h"
#include "random.h"
#include "shake.h"

#define PREKEY_PROOF_LAMBDA 44 // 352 / 8

static const uint8_t usage_proof_c_lambda = 0x17;

INTERNAL otrng_result ecdh_proof_generate(ecdh_proof_p dst,
                                          const ec_scalar_p *values_priv,
                                          const ec_point_p *values_pub,
                                          const size_t values_len,
                                          const uint8_t *m,
                                          const uint8_t usage) {
  size_t i;
  goldilocks_448_scalar_p r;
  goldilocks_448_point_p a;
  uint8_t *cbuf;
  uint8_t *curr;
  uint8_t *p;
  size_t cbuf_len = ((values_len + 1) * ED448_POINT_BYTES) + 64;
  size_t p_len = PREKEY_PROOF_LAMBDA * values_len;

  otrng_zq_keypair_generate(a, r);

  cbuf = otrng_xmalloc(cbuf_len * sizeof(uint8_t));
  curr = cbuf;

  if (!otrng_ec_point_encode(curr, ED448_POINT_BYTES, a)) {
    free(cbuf);
    goldilocks_448_point_destroy(a);
    goldilocks_448_scalar_destroy(r);
    return OTRNG_ERROR;
  }
  goldilocks_448_point_destroy(a);

  curr += ED448_POINT_BYTES;

  for (i = 0; i < values_len; i++) {
    if (!otrng_ec_point_encode(curr, ED448_POINT_BYTES, values_pub[i])) {
      free(cbuf);
      goldilocks_448_scalar_destroy(r);
      return OTRNG_ERROR;
    }
    curr += ED448_POINT_BYTES;
  }

  memcpy(curr, m, 64);

  shake_256_prekey_server_kdf(dst->c, PROOF_C_SIZE, usage, cbuf, cbuf_len);
  free(cbuf);

  p = otrng_xmalloc(p_len * sizeof(uint8_t));
  shake_256_prekey_server_kdf(p, p_len, usage_proof_c_lambda, dst->c,
                              PROOF_C_SIZE);

  goldilocks_448_scalar_copy(dst->v, r);
  goldilocks_448_scalar_destroy(r);
  for (i = 0; i < values_len; i++) {
    goldilocks_448_scalar_p t;
    goldilocks_448_scalar_decode_long(t, p + i * PREKEY_PROOF_LAMBDA,
                                      PREKEY_PROOF_LAMBDA);
    goldilocks_448_scalar_mul(t, t, values_priv[i]);
    goldilocks_448_scalar_add(dst->v, dst->v, t);
    goldilocks_448_scalar_destroy(t);
  }

  free(p);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_bool ecdh_proof_verify(ecdh_proof_p px,
                                      const ec_point_p *values_pub,
                                      const size_t values_len, const uint8_t *m,
                                      const uint8_t usage) {
  size_t i;
  uint8_t *p;
  goldilocks_448_point_p a;
  goldilocks_448_point_p curr;
  size_t p_len = PREKEY_PROOF_LAMBDA * values_len;
  uint8_t *cbuf;
  uint8_t *cbuf_curr;
  size_t cbuf_len = ((values_len + 1) * ED448_POINT_BYTES) + 64;
  uint8_t c2[PROOF_C_SIZE];

  p = otrng_xmalloc(p_len * sizeof(uint8_t));
  shake_256_prekey_server_kdf(p, p_len, usage_proof_c_lambda, px->c,
                              PROOF_C_SIZE);
  goldilocks_448_precomputed_scalarmul(a, goldilocks_448_precomputed_base,
                                       px->v);

  goldilocks_448_point_copy(curr, goldilocks_448_point_identity);

  for (i = 0; i + 1 < values_len; i += 2) {
    goldilocks_448_scalar_p t1, t2;
    goldilocks_448_point_p res;

    goldilocks_448_scalar_decode_long(t1, p + i * PREKEY_PROOF_LAMBDA,
                                      PREKEY_PROOF_LAMBDA);
    goldilocks_448_scalar_decode_long(t2, p + (i + 1) * PREKEY_PROOF_LAMBDA,
                                      PREKEY_PROOF_LAMBDA);

    goldilocks_448_point_double_scalarmul(res, values_pub[i], t1,
                                          values_pub[i + 1], t2);
    goldilocks_448_point_add(curr, curr, res);

    goldilocks_448_scalar_destroy(t1);
    goldilocks_448_scalar_destroy(t2);
    goldilocks_448_point_destroy(res);
  }

  if (i < values_len) {
    goldilocks_448_scalar_p t;
    goldilocks_448_point_p res;

    goldilocks_448_scalar_decode_long(t, p + i * PREKEY_PROOF_LAMBDA,
                                      PREKEY_PROOF_LAMBDA);
    goldilocks_448_point_scalarmul(res, values_pub[i], t);
    goldilocks_448_point_add(curr, curr, res);

    goldilocks_448_scalar_destroy(t);
    goldilocks_448_point_destroy(res);
  }

  free(p);

  goldilocks_448_point_sub(a, a, curr);
  goldilocks_448_point_destroy(curr);

  cbuf = otrng_xmalloc(cbuf_len * sizeof(uint8_t));
  cbuf_curr = cbuf;

  if (!otrng_ec_point_encode(cbuf_curr, ED448_POINT_BYTES, a)) {
    free(cbuf);
    goldilocks_448_point_destroy(a);
    return OTRNG_ERROR;
  }
  goldilocks_448_point_destroy(a);

  cbuf_curr += ED448_POINT_BYTES;

  for (i = 0; i < values_len; i++) {
    if (!otrng_ec_point_encode(cbuf_curr, ED448_POINT_BYTES, values_pub[i])) {
      free(cbuf);
      return OTRNG_ERROR;
    }
    cbuf_curr += ED448_POINT_BYTES;
  }

  memcpy(cbuf_curr, m, 64);
  shake_256_prekey_server_kdf(c2, PROOF_C_SIZE, usage, cbuf, cbuf_len);
  free(cbuf);

  if (goldilocks_memeq(px->c, c2, PROOF_C_SIZE)) {
    return otrng_true;
  }

  return otrng_false;
}

/* func generateDhProof(wr gotrax.WithRandom, valuesPrivate []*big.Int,
 * valuesPublic []*big.Int, m []byte, usageID uint8) (*dhProof, error) { */
/* func (px *dhProof) verify(values []*big.Int, m []byte, usageID uint8) bool {
 */
