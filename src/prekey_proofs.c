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
    return otrng_false;
  }
  goldilocks_448_point_destroy(a);

  cbuf_curr += ED448_POINT_BYTES;

  for (i = 0; i < values_len; i++) {
    if (!otrng_ec_point_encode(cbuf_curr, ED448_POINT_BYTES, values_pub[i])) {
      free(cbuf);
      return otrng_false;
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

INTERNAL otrng_result dh_proof_generate(dh_proof_p dst,
                                        const dh_mpi_p *values_priv,
                                        const dh_mpi_p *values_pub,
                                        const size_t values_len,
                                        const uint8_t *m, const uint8_t usage) {
  uint8_t *p;
  uint8_t rhash[DH_KEY_SIZE] = {0};
  uint8_t *rbuf;
  gcry_error_t err;
  gcry_mpi_t r, a, q;
  size_t i;
  uint8_t *cbuf;
  uint8_t *cbuf_curr;
  uint8_t *p_curr;
  size_t w;
  size_t total = 0;
  size_t cbuf_len = ((values_len + 1) * DH3072_MOD_LEN_BYTES) + 64;
  size_t p_len = PREKEY_PROOF_LAMBDA * values_len;

  q = otrng_dh_modulus_q();

  rbuf = gcry_random_bytes_secure(DH_KEY_SIZE, GCRY_STRONG_RANDOM);
  shake_256_hash(rhash, sizeof(rhash), rbuf, DH_KEY_SIZE);
  err = gcry_mpi_scan(&r, GCRYMPI_FMT_USG, rhash, DH_KEY_SIZE, NULL);
  gcry_free(rbuf);

  if (err) {
    otrng_dh_mpi_release(r);
    return OTRNG_ERROR;
  }

  a = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  otrng_dh_calculate_public_key(a, r);

  cbuf = otrng_xmalloc(cbuf_len * sizeof(uint8_t));
  cbuf_curr = cbuf;
  if (otrng_failed(
          otrng_dh_mpi_serialize(cbuf_curr, DH3072_MOD_LEN_BYTES, &w, a))) {
    free(cbuf);
    otrng_dh_mpi_release(r);
    otrng_dh_mpi_release(a);
    return OTRNG_ERROR;
  }
  otrng_dh_mpi_release(a);
  cbuf_curr += w;
  total += w;

  for (i = 0; i < values_len; i++) {
    if (otrng_failed(otrng_dh_mpi_serialize(cbuf_curr, DH3072_MOD_LEN_BYTES, &w,
                                            values_pub[i]))) {
      free(cbuf);
      otrng_dh_mpi_release(r);
      return OTRNG_ERROR;
    }
    cbuf_curr += w;
    total += w;
  }

  memcpy(cbuf_curr, m, 64);
  total += 64;
  shake_256_prekey_server_kdf(dst->c, PROOF_C_SIZE, usage, cbuf, cbuf_len);
  free(cbuf);

  p = otrng_xmalloc(p_len * sizeof(uint8_t));
  shake_256_prekey_server_kdf(p, p_len, usage_proof_c_lambda, dst->c,
                              PROOF_C_SIZE);

  dst->v = otrng_dh_mpi_copy(r);
  otrng_dh_mpi_release(r);
  p_curr = p;
  for (i = 0; i < values_len; i++) {
    gcry_mpi_t t = NULL;
    if (!otrng_dh_mpi_deserialize(&t, p_curr, PREKEY_PROOF_LAMBDA, &w)) {
      free(p);
      return OTRNG_ERROR;
    }
    p_curr += w;
    gcry_mpi_mulm(t, t, values_priv[i], q);
    gcry_mpi_addm(dst->v, dst->v, t, q);
    otrng_dh_mpi_release(t);
  }
  free(p);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_bool dh_proof_verify(dh_proof_p px, const dh_mpi_p *values_pub,
                                    const size_t values_len, const uint8_t *m,
                                    const uint8_t usage) {
  uint8_t *p;
  gcry_mpi_t a, mod, curr;
  size_t i;
  uint8_t *cbuf;
  uint8_t *cbuf_curr;
  uint8_t *p_curr;
  size_t w;
  size_t total = 0;
  size_t cbuf_len = ((values_len + 1) * DH3072_MOD_LEN_BYTES) + 64;
  size_t p_len = PREKEY_PROOF_LAMBDA * values_len;
  uint8_t c2[PROOF_C_SIZE];

  p = otrng_xmalloc(p_len * sizeof(uint8_t));
  shake_256_prekey_server_kdf(p, p_len, usage_proof_c_lambda, px->c,
                              PROOF_C_SIZE);

  a = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  otrng_dh_calculate_public_key(a, px->v);

  mod = otrng_dh_modulus_p();

  curr = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  gcry_mpi_set_ui(curr, 1);

  p_curr = p;
  for (i = 0; i < values_len; i++) {
    gcry_mpi_t t;
    if (!otrng_dh_mpi_deserialize(&t, p_curr, PREKEY_PROOF_LAMBDA, &w)) {
      free(p);
      return otrng_false;
    }
    p_curr += w;

    gcry_mpi_powm(t, values_pub[i], t, mod);
    gcry_mpi_mulm(curr, curr, t, mod);
    otrng_dh_mpi_release(t);
  }
  free(p);
  gcry_mpi_invm(curr, curr, mod);
  gcry_mpi_mulm(a, a, curr, mod);
  otrng_dh_mpi_release(curr);

  cbuf = otrng_xmalloc(cbuf_len * sizeof(uint8_t));
  cbuf_curr = cbuf;
  if (otrng_failed(
          otrng_dh_mpi_serialize(cbuf_curr, DH3072_MOD_LEN_BYTES, &w, a))) {
    free(cbuf);
    gcry_mpi_release(a);
    return otrng_false;
  }

  gcry_mpi_release(a);

  cbuf_curr += w;
  total += w;

  for (i = 0; i < values_len; i++) {
    if (otrng_failed(otrng_dh_mpi_serialize(cbuf_curr, DH3072_MOD_LEN_BYTES, &w,
                                            values_pub[i]))) {
      free(cbuf);
      return otrng_false;
    }
    cbuf_curr += w;
    total += w;
  }

  memcpy(cbuf_curr, m, 64);
  total += 64;
  shake_256_prekey_server_kdf(c2, PROOF_C_SIZE, usage, cbuf, cbuf_len);
  free(cbuf);

  if (goldilocks_memeq(px->c, c2, PROOF_C_SIZE)) {
    return otrng_true;
  }

  return otrng_false;
}
