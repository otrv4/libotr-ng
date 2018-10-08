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
#include "deserialize.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"

#define PREKEY_PROOF_LAMBDA 44 // 352 / 8

static const uint8_t usage_proof_c_lambda = 0x17;

INTERNAL otrng_result otrng_ecdh_proof_generate(
    ecdh_proof_s *dst, const ec_scalar *values_priv, const ec_point *values_pub,
    const size_t values_len, const uint8_t *m, const uint8_t usage) {
  size_t i;
  goldilocks_448_scalar_p r;
  goldilocks_448_point_p a;
  uint8_t *cbuf;
  uint8_t *curr;
  uint8_t *p;
  size_t cbuf_len = ((values_len + 1) * ED448_POINT_BYTES) + HASH_BYTES;
  size_t p_len = PREKEY_PROOF_LAMBDA * values_len;

  otrng_zq_keypair_generate(a, r);

  cbuf = otrng_xmalloc_z(cbuf_len * sizeof(uint8_t));
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

  memcpy(curr, m, HASH_BYTES);

  shake_256_prekey_server_kdf(dst->c, PROOF_C_SIZE, usage, cbuf, cbuf_len);
  free(cbuf);

  p = otrng_xmalloc_z(p_len * sizeof(uint8_t));
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

INTERNAL otrng_bool otrng_ecdh_proof_verify(ecdh_proof_s *px,
                                            const ec_point *values_pub,
                                            const size_t values_len,
                                            const uint8_t *m,
                                            const uint8_t usage) {
  size_t i;
  uint8_t *p;
  goldilocks_448_point_p a;
  goldilocks_448_point_p curr;
  size_t p_len = PREKEY_PROOF_LAMBDA * values_len;
  uint8_t *cbuf;
  uint8_t *cbuf_curr;
  size_t cbuf_len = ((values_len + 1) * ED448_POINT_BYTES) + HASH_BYTES;
  uint8_t c2[PROOF_C_SIZE];

  p = otrng_xmalloc_z(p_len * sizeof(uint8_t));
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

  cbuf = otrng_xmalloc_z(cbuf_len * sizeof(uint8_t));
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

  memcpy(cbuf_curr, m, HASH_BYTES);
  shake_256_prekey_server_kdf(c2, PROOF_C_SIZE, usage, cbuf, cbuf_len);
  free(cbuf);

  if (goldilocks_memeq(px->c, c2, PROOF_C_SIZE)) {
    return otrng_true;
  }

  return otrng_false;
}

tstatic void *gen_random_data(size_t n, random_generator gen) {
  if (gen == NULL) {
    void *rhash, *rbuf;
    rbuf = gcry_random_bytes_secure(n, GCRY_STRONG_RANDOM);
    rhash = otrng_secure_alloc(n * sizeof(uint8_t));
    shake_256_hash(rhash, n * sizeof(uint8_t), rbuf, n);
    otrng_secure_wipe(rbuf, n);
    gcry_free(rbuf);
    return rhash;
  }
  return gen(n);
}

INTERNAL otrng_result otrng_dh_proof_generate(
    dh_proof_s *dst, const dh_mpi *values_priv, const dh_mpi *values_pub,
    const size_t values_len, const uint8_t *m, const uint8_t usage,
    random_generator gen) {
  uint8_t *p;
  uint8_t *rbuf;
  gcry_error_t err;
  dh_mpi q, a, r = NULL;
  size_t i;
  uint8_t *cbuf;
  uint8_t *cbuf_curr;
  uint8_t *p_curr;
  size_t w = 0;
  size_t cbuf_len = ((values_len + 1) * DH_MPI_MAX_BYTES) + HASH_BYTES;
  size_t p_len = PREKEY_PROOF_LAMBDA * values_len;

  q = otrng_dh_modulus_q();

  rbuf = gen_random_data(DH_KEY_SIZE, gen);
  err = gcry_mpi_scan(&r, GCRYMPI_FMT_USG, rbuf, DH_KEY_SIZE, NULL);
  otrng_secure_wipe(rbuf, DH_KEY_SIZE);
  free(rbuf);

  if (err) {
    otrng_dh_mpi_release(r);
    return OTRNG_ERROR;
  }

  a = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  otrng_dh_calculate_public_key(a, r);

  cbuf = otrng_xmalloc_z(cbuf_len * sizeof(uint8_t));
  cbuf_curr = cbuf;
  if (otrng_failed(
          otrng_serialize_dh_mpi_otr(cbuf_curr, DH_MPI_MAX_BYTES, &w, a))) {
    free(cbuf);
    otrng_dh_mpi_release(r);
    otrng_dh_mpi_release(a);
    return OTRNG_ERROR;
  }
  otrng_dh_mpi_release(a);
  cbuf_curr += w;

  for (i = 0; i < values_len; i++) {
    if (otrng_failed(otrng_serialize_dh_mpi_otr(cbuf_curr, DH_MPI_MAX_BYTES, &w,
                                                values_pub[i]))) {
      free(cbuf);
      otrng_dh_mpi_release(r);
      return OTRNG_ERROR;
    }
    cbuf_curr += w;
  }

  memcpy(cbuf_curr, m, HASH_BYTES);
  cbuf_curr += HASH_BYTES;

  shake_256_prekey_server_kdf(dst->c, PROOF_C_SIZE, usage, cbuf,
                              cbuf_curr - cbuf);
  free(cbuf);

  p = otrng_xmalloc_z(p_len * sizeof(uint8_t));
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

INTERNAL otrng_bool otrng_dh_proof_verify(dh_proof_s *px,
                                          const dh_mpi *values_pub,
                                          const size_t values_len,
                                          const uint8_t *m,
                                          const uint8_t usage) {
  uint8_t *p;
  dh_mpi mod, a, curr;
  size_t i;
  uint8_t *cbuf;
  uint8_t *cbuf_curr;
  uint8_t *p_curr;
  size_t w = 0;
  size_t cbuf_len = ((values_len + 1) * DH_MPI_MAX_BYTES) + HASH_BYTES;
  size_t p_len = PREKEY_PROOF_LAMBDA * values_len;
  uint8_t c2[PROOF_C_SIZE];

  p = otrng_xmalloc_z(p_len * sizeof(uint8_t));
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

  cbuf = otrng_xmalloc_z(cbuf_len * sizeof(uint8_t));
  cbuf_curr = cbuf;
  if (otrng_failed(
          otrng_serialize_dh_mpi_otr(cbuf_curr, DH_MPI_MAX_BYTES, &w, a))) {
    free(cbuf);
    gcry_mpi_release(a);
    return otrng_false;
  }

  gcry_mpi_release(a);

  cbuf_curr += w;

  for (i = 0; i < values_len; i++) {
    if (otrng_failed(otrng_serialize_dh_mpi_otr(cbuf_curr, DH_MPI_MAX_BYTES, &w,
                                                values_pub[i]))) {
      free(cbuf);
      return otrng_false;
    }
    cbuf_curr += w;
  }

  memcpy(cbuf_curr, m, HASH_BYTES);
  cbuf_curr += HASH_BYTES;

  shake_256_prekey_server_kdf(c2, PROOF_C_SIZE, usage, cbuf, cbuf_curr - cbuf);
  free(cbuf);

  if (goldilocks_memeq(px->c, c2, PROOF_C_SIZE)) {
    return otrng_true;
  }

  return otrng_false;
}

INTERNAL size_t otrng_ecdh_proof_serialize(uint8_t *dst,
                                           const ecdh_proof_s *px) {
  uint8_t *cursor = dst;

  cursor += otrng_serialize_bytes_array(cursor, px->c, PROOF_C_SIZE);
  cursor += otrng_serialize_ec_scalar(cursor, px->v);

  return cursor - dst;
}

INTERNAL size_t otrng_dh_proof_serialize(uint8_t *dst, const dh_proof_s *px) {
  uint8_t *cursor = dst;
  size_t len = 0;

  cursor += otrng_serialize_bytes_array(cursor, px->c, PROOF_C_SIZE);
  otrng_serialize_dh_mpi_otr(cursor, DH_MPI_MAX_BYTES, &len, px->v);
  cursor += len;

  return cursor - dst;
}

INTERNAL otrng_result otrng_ecdh_proof_deserialize(ecdh_proof_s *px,
                                                   const uint8_t *ser,
                                                   size_t ser_len,
                                                   size_t *read) {
  const uint8_t *cursor = ser;
  if (ser_len < PROOF_C_SIZE + ED448_SCALAR_BYTES) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_bytes_array(px->c, PROOF_C_SIZE, cursor, ser_len)) {
    return OTRNG_ERROR;
  }
  cursor += PROOF_C_SIZE;
  ser_len -= PROOF_C_SIZE;

  if (!otrng_deserialize_ec_scalar(px->v, cursor, ser_len)) {
    return OTRNG_ERROR;
  }

  if (read) {
    *read = PROOF_C_SIZE + ED448_SCALAR_BYTES;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_dh_proof_deserialize(dh_proof_s *px,
                                                 const uint8_t *ser,
                                                 size_t ser_len, size_t *read) {
  const uint8_t *cursor = ser;
  size_t n = 0;

  if (ser_len < PROOF_C_SIZE) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_bytes_array(px->c, PROOF_C_SIZE, cursor, ser_len)) {
    return OTRNG_ERROR;
  }
  cursor += PROOF_C_SIZE;
  ser_len -= PROOF_C_SIZE;

  if (!otrng_deserialize_dh_mpi_otr(&px->v, cursor, ser_len, &n)) {
    return OTRNG_ERROR;
  }

  if (read) {
    *read = PROOF_C_SIZE + n;
  }

  return OTRNG_SUCCESS;
}
