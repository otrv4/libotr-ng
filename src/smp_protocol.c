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

#define OTRNG_SMP_PROTOCOL_PRIVATE

#include <sodium.h>

#include "auth.h"
#include "constants.h"
#include "deserialize.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"
#include "smp_protocol.h"
#include "tlv.h"

#include "debug.h"

INTERNAL void otrng_smp_protocol_init(smp_protocol_s *smp) {
  memset(smp, 0, sizeof(smp_protocol_s));
  smp->state_expect = SMP_STATE_EXPECT_1;
  smp->progress = SMP_ZERO_PROGRESS;
}

INTERNAL void otrng_smp_destroy(smp_protocol_s *smp) {
  free(smp->secret);
  smp->secret = NULL;

  otrng_smp_message_1_destroy(smp->message1);
  free(smp->message1);
  smp->message1 = NULL;

  otrng_ec_scalar_destroy(smp->a2);
  otrng_ec_scalar_destroy(smp->a3);
  otrng_ec_scalar_destroy(smp->b3);

  otrng_ec_point_destroy(smp->g2);
  otrng_ec_point_destroy(smp->g3);
  otrng_ec_point_destroy(smp->g3a);
  otrng_ec_point_destroy(smp->g3b);
  otrng_ec_point_destroy(smp->pb);
  otrng_ec_point_destroy(smp->qb);
  otrng_ec_point_destroy(smp->pa_pb);
  otrng_ec_point_destroy(smp->qa_qb);
}

INTERNAL otrng_result otrng_generate_smp_secret(unsigned char **secret,
                                                otrng_fingerprint our_fp,
                                                otrng_fingerprint their_fp,
                                                uint8_t *ssid,
                                                const uint8_t *answer,
                                                size_t answer_len) {
  uint8_t *hash = otrng_secure_alloc(HASH_BYTES);
  uint8_t version[1] = {0x01};
  uint8_t usage_smp_secret = 0x1B;
  goldilocks_shake256_ctx_p hd;

  hash_init_with_usage(hd, usage_smp_secret);

  if (hash_update(hd, version, 1) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, our_fp, FPRINT_LEN_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, their_fp, FPRINT_LEN_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, ssid, SSID_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, answer, answer_len) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  hash_final(hd, hash, HASH_BYTES);
  hash_destroy(hd);

  *secret = otrng_secure_alloc(HASH_BYTES);

  memcpy(*secret, hash, HASH_BYTES);
  otrng_secure_wipe(hash, HASH_BYTES);
  free(hash);

  return OTRNG_SUCCESS;
}

tstatic otrng_result hash_to_scalar(ec_scalar dst, uint8_t *ser_p,
                                    size_t ser_p_len, const uint8_t usage_smp) {
  goldilocks_shake256_ctx_p hd;
  uint8_t *hash = otrng_secure_alloc(HASH_BYTES);

  hash_init_with_usage(hd, usage_smp);

  if (hash_update(hd, ser_p, ser_p_len) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  hash_final(hd, hash, HASH_BYTES);
  hash_destroy(hd);

  if (!otrng_deserialize_ec_scalar(dst, hash, ED448_SCALAR_BYTES)) {
    otrng_secure_wipe(hash, HASH_BYTES);
    free(hash);
    return OTRNG_ERROR;
  }
  otrng_secure_wipe(ser_p, ED448_POINT_BYTES);

  otrng_secure_wipe(hash, HASH_BYTES);
  free(hash);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_generate_smp_message_1(smp_message_1_s *dst,
                                                   smp_protocol_s *smp) {
  ecdh_keypair_s pair_r2, pair_r3;
  ec_scalar a3c3, a2c2;
  uint8_t ser_point_1[ED448_POINT_BYTES];
  uint8_t usage_smp_1 = 0x01;
  uint8_t ser_point_2[ED448_POINT_BYTES];
  uint8_t usage_smp_2 = 0x02;

  dst->q_len = 0;
  dst->question = NULL;

  /* G2a = G * a2 * and G3a = G * a3 */
  otrng_zq_keypair_generate(dst->g2a, smp->a2);
  otrng_zq_keypair_generate(dst->g3a, smp->a3);

  otrng_zq_keypair_generate(pair_r2.pub, pair_r2.priv);
  otrng_zq_keypair_generate(pair_r3.pub, pair_r3.priv);

  if (otrng_serialize_ec_point(ser_point_1, pair_r2.pub) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  /* c2 = hash_to_scalar(0x01 || G * r2) */
  if (!hash_to_scalar(dst->c2, ser_point_1, ED448_POINT_BYTES, usage_smp_1)) {
    return OTRNG_ERROR;
  }

  /* d2 = r2 - a2 * c2 mod q */
  goldilocks_448_scalar_mul(a2c2, smp->a2, dst->c2);
  goldilocks_448_scalar_sub(dst->d2, pair_r2.priv, a2c2);

  if (otrng_serialize_ec_point(ser_point_2, pair_r3.pub) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  /* c3 = hash_to_scalar(0x02 || G * r3) */
  if (!hash_to_scalar(dst->c3, ser_point_2, ED448_POINT_BYTES, usage_smp_2)) {
    return OTRNG_ERROR;
  }

  /* d3 = r3 - a3 * c3 mod q */
  goldilocks_448_scalar_mul(a3c3, smp->a3, dst->c3);
  goldilocks_448_scalar_sub(dst->d3, pair_r3.priv, a3c3);

  return OTRNG_SUCCESS;
}

tstatic void smp_message_1_copy(smp_message_1_s *dst,
                                const smp_message_1_s *src) {
  dst->q_len = src->q_len;
  if (src->question != NULL) {
    dst->question = otrng_xmemdup(src->question, src->q_len);
  } else {
    dst->question = NULL;
  }

  otrng_ec_point_copy(dst->g2a, src->g2a);
  otrng_ec_scalar_copy(dst->c2, src->c2);
  otrng_ec_scalar_copy(dst->d2, src->d2);
  otrng_ec_point_copy(dst->g3a, src->g3a);
  otrng_ec_scalar_copy(dst->c3, src->c3);
  otrng_ec_scalar_copy(dst->d3, src->d3);
}

INTERNAL otrng_result otrng_smp_message_1_serialize(
    uint8_t **dst, size_t *len, const smp_message_1_s *msg) {
  size_t size = 0;
  uint8_t *cursor;
  size = 4 + msg->q_len + (2 * ED448_POINT_BYTES) + (4 * ED448_SCALAR_BYTES);

  *dst = otrng_xmalloc_z(size);

  cursor = *dst;

  cursor += otrng_serialize_data(cursor, msg->question, msg->q_len);
  cursor += otrng_serialize_ec_point(cursor, msg->g2a);
  cursor += otrng_serialize_ec_scalar(cursor, msg->c2);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d2);
  cursor += otrng_serialize_ec_point(cursor, msg->g3a);
  cursor += otrng_serialize_ec_scalar(cursor, msg->c3);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d3);

  if (len) {
    *len = (cursor - *dst);
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_1_deserialize(smp_message_1_s *msg,
                                               const tlv_s *tlv) {
  const uint8_t *cursor = tlv->data;
  uint16_t len = tlv->len;
  size_t read = 0;

  msg->question = NULL;
  if (!otrng_deserialize_data(&msg->question, &msg->q_len, cursor, len,
                              &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_ec_point(msg->g2a, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(msg->c2, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(msg->d2, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_point(msg->g3a, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(msg->c3, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(msg->d3, cursor, len)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_bool smp_message_1_valid_points(smp_message_1_s *msg) {
  return otrng_ec_point_valid(msg->g2a) && otrng_ec_point_valid(msg->g3a);
}

tstatic otrng_bool smp_message_1_valid_zkp(smp_message_1_s *msg) {
  ec_scalar temp_scalar;
  ec_point ga_c, g_d;
  uint8_t ser_point_3[ED448_POINT_BYTES];
  uint8_t usage_zkp_smp_1 = 0x01;
  uint8_t usage_zkp_smp_2 = 0x02;
  uint8_t ser_point_4[ED448_POINT_BYTES];

  /* Check that c2 = hash_to_scalar(1 || G * d2 + G2a * c2). */
  goldilocks_448_point_scalarmul(ga_c, msg->g2a, msg->c2);
  goldilocks_448_point_scalarmul(g_d, goldilocks_448_point_base, msg->d2);
  goldilocks_448_point_add(g_d, g_d, ga_c);

  if (otrng_serialize_ec_point(ser_point_3, g_d) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  if (!hash_to_scalar(temp_scalar, ser_point_3, ED448_POINT_BYTES,
                      usage_zkp_smp_1)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, msg->c2)) {
    otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);
    return otrng_false;
  }
  otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);

  /* Check that c3 = hash_to_scalar(2 || G * d3 + G3a * c3). */
  goldilocks_448_point_scalarmul(ga_c, msg->g3a, msg->c3);
  goldilocks_448_point_scalarmul(g_d, goldilocks_448_point_base, msg->d3);
  goldilocks_448_point_add(g_d, g_d, ga_c);

  if (otrng_serialize_ec_point(ser_point_4, g_d) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  if (!hash_to_scalar(temp_scalar, ser_point_4, ED448_POINT_BYTES,
                      usage_zkp_smp_2)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, msg->c3)) {
    otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);
    return otrng_false;
  }

  otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);

  return otrng_true;
}

INTERNAL void otrng_smp_message_1_destroy(smp_message_1_s *msg) {
  if (!msg) {
    return;
  }

  free(msg->question);
  msg->question = NULL;
  msg->q_len = 0;

  otrng_ec_point_destroy(msg->g2a);
  otrng_ec_point_destroy(msg->g3a);

  otrng_ec_scalar_destroy(msg->c2);
  otrng_ec_scalar_destroy(msg->c3);
  otrng_ec_scalar_destroy(msg->d2);
  otrng_ec_scalar_destroy(msg->d3);
}

tstatic otrng_result generate_smp_message_2(smp_message_2_s *dst,
                                            const smp_message_1_s *msg_1,
                                            smp_protocol_s *smp) {
  ec_scalar b2, r6;
  ec_scalar temp_scalar;
  ecdh_keypair_s pair_r2, pair_r3, pair_r4, pair_r5;
  ec_point temp_point;
  uint8_t ser_point_1[ED448_POINT_BYTES];
  uint8_t usage_smp_3 = 0x03;
  uint8_t ser_point_2[ED448_POINT_BYTES];
  uint8_t usage_smp_4 = 0x04;
  ec_scalar secret_as_scalar;
  uint8_t ser_point_3[ED448_POINT_BYTES];
  uint8_t ser_point_4[ED448_POINT_BYTES];
  uint8_t hash[HASH_BYTES];
  goldilocks_shake256_ctx_p hd_2;
  uint8_t usage_smp_5 = 0x05;

  /* G2b = G * b2 and G3b = G * b3 */
  otrng_zq_keypair_generate(dst->g2b, b2);
  otrng_zq_keypair_generate(dst->g3b, smp->b3);

  otrng_zq_keypair_generate(pair_r2.pub, pair_r2.priv);
  otrng_zq_keypair_generate(pair_r3.pub, pair_r3.priv);
  otrng_zq_keypair_generate(pair_r4.pub, pair_r4.priv);
  otrng_zq_keypair_generate(pair_r5.pub, pair_r5.priv);

  ed448_random_scalar(r6);

  if (otrng_serialize_ec_point(ser_point_1, pair_r2.pub) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  /* c2 = HashToScalar(3 || G * r2) */
  if (!hash_to_scalar(dst->c2, ser_point_1, ED448_POINT_BYTES, usage_smp_3)) {
    return OTRNG_ERROR;
  }

  /* d2 = (r2 - b2 * c2 mod q). */
  goldilocks_448_scalar_mul(temp_scalar, b2, dst->c2);
  goldilocks_448_scalar_sub(dst->d2, pair_r2.priv, temp_scalar);

  if (otrng_serialize_ec_point(ser_point_2, pair_r3.pub) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  /* c3 = HashToScalar(4 || G * r3) */
  if (!hash_to_scalar(dst->c3, ser_point_2, ED448_POINT_BYTES, usage_smp_4)) {
    return OTRNG_ERROR;
  }

  /* d3 = (r3 - b3 * c3 mod q). */
  goldilocks_448_scalar_mul(temp_scalar, smp->b3, dst->c3);
  goldilocks_448_scalar_sub(dst->d3, pair_r3.priv, temp_scalar);

  /* Compute G2 = (G2a * b2). */
  goldilocks_448_point_scalarmul(smp->g2, msg_1->g2a, b2);

  /* Compute G3 = (G3a * b3). */
  goldilocks_448_point_scalarmul(smp->g3, msg_1->g3a, smp->b3);
  otrng_ec_point_copy(smp->g3a, msg_1->g3a);

  /* Compute Pb = (G3 * r4). */
  goldilocks_448_point_scalarmul(dst->pb, smp->g3, pair_r4.priv);
  otrng_ec_point_copy(smp->pb, dst->pb);

  /* Compute Qb = (G * r4 + G2 * (y mod q)). */

  if (!otrng_deserialize_ec_scalar(secret_as_scalar, smp->secret, HASH_BYTES)) {
    return OTRNG_ERROR;
  }

  goldilocks_448_point_scalarmul(dst->qb, smp->g2, secret_as_scalar);
  goldilocks_448_point_add(dst->qb, pair_r4.pub, dst->qb);
  otrng_ec_point_copy(smp->qb, dst->qb);

  /* cp = HashToScalar(5 || G3 * r5 || G * r5 + G2 * r6) */
  goldilocks_448_point_scalarmul(temp_point, smp->g3, pair_r5.priv);
  if (otrng_serialize_ec_point(ser_point_3, temp_point) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  goldilocks_448_point_scalarmul(temp_point, smp->g2, r6);
  goldilocks_448_point_add(temp_point, pair_r5.pub, temp_point);

  if (otrng_serialize_ec_point(ser_point_4, temp_point) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  hash_init(hd_2);

  if (hash_update(hd_2, ser_point_3, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd_2);
    return OTRNG_ERROR;
  }

  if (hash_update(hd_2, ser_point_4, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd_2);
    return OTRNG_ERROR;
  }

  hash_final(hd_2, hash, HASH_BYTES);
  hash_destroy(hd_2);

  otrng_secure_wipe(ser_point_3, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_4, ED448_POINT_BYTES);

  if (!hash_to_scalar(dst->cp, hash, HASH_BYTES, usage_smp_5)) {
    return OTRNG_ERROR;
  }

  /* d5 = (r5 - r4 * cp mod q). */
  goldilocks_448_scalar_mul(dst->d5, pair_r4.priv, dst->cp);
  goldilocks_448_scalar_sub(dst->d5, pair_r5.priv, dst->d5);

  /* d6 = (r6 - (y mod q) * cp) mod q. */
  goldilocks_448_scalar_mul(dst->d6, secret_as_scalar, dst->cp);
  goldilocks_448_scalar_sub(dst->d6, r6, dst->d6);

  otrng_secure_wipe(secret_as_scalar, ED448_SCALAR_BYTES);

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_2_serialize(uint8_t **dst, size_t *len,
                                             const smp_message_2_s *msg) {
  size_t size = 0;
  uint8_t *cursor;
  size += (4 * ED448_POINT_BYTES) + (7 * ED448_SCALAR_BYTES);

  *dst = otrng_xmalloc_z(size);

  cursor = *dst;

  cursor += otrng_serialize_ec_point(cursor, msg->g2b);
  cursor += otrng_serialize_ec_scalar(cursor, msg->c2);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d2);
  cursor += otrng_serialize_ec_point(cursor, msg->g3b);
  cursor += otrng_serialize_ec_scalar(cursor, msg->c3);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d3);
  cursor += otrng_serialize_ec_point(cursor, msg->pb);
  cursor += otrng_serialize_ec_point(cursor, msg->qb);
  cursor += otrng_serialize_ec_scalar(cursor, msg->cp);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d5);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d6);

  if (len) {
    *len = (cursor - *dst);
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_2_deserialize(smp_message_2_s *msg,
                                               const tlv_s *tlv) {
  const uint8_t *cursor = tlv->data;
  uint16_t len = tlv->len;

  if (!otrng_deserialize_ec_point(msg->g2b, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(msg->c2, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(msg->d2, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_point(msg->g3b, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(msg->c3, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(msg->d3, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_point(msg->pb, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_point(msg->qb, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(msg->cp, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(msg->d5, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(msg->d6, cursor, len)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_bool smp_message_2_valid_points(smp_message_2_s *msg) {
  return otrng_ec_point_valid(msg->g2b) && otrng_ec_point_valid(msg->g3b) &&
         otrng_ec_point_valid(msg->pb) && otrng_ec_point_valid(msg->qb);
}

tstatic otrng_bool smp_message_2_valid_zkp(smp_message_2_s *msg,
                                           const smp_protocol_s *smp) {
  ec_scalar temp_scalar;
  ec_point gb_c, g_d, point_cp;
  uint8_t ser_point_1[ED448_POINT_BYTES];
  uint8_t usage_zkp_smp_3 = 0x03;
  uint8_t ser_point_2[ED448_POINT_BYTES];
  uint8_t usage_smp_zkp_4 = 0x04;
  uint8_t ser_point_3[ED448_POINT_BYTES];
  uint8_t ser_point_4[ED448_POINT_BYTES];
  uint8_t hash[HASH_BYTES];
  goldilocks_shake256_ctx_p hd;
  uint8_t usage_zkp_smp_5 = 0x05;

  /* Check that c2 = HashToScalar(3 || G * d2 + G2b * c2). */
  goldilocks_448_point_scalarmul(gb_c, msg->g2b, msg->c2);
  goldilocks_448_point_scalarmul(g_d, goldilocks_448_point_base, msg->d2);
  goldilocks_448_point_add(g_d, g_d, gb_c);

  if (otrng_serialize_ec_point(ser_point_1, g_d) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  if (!hash_to_scalar(temp_scalar, ser_point_1, ED448_POINT_BYTES,
                      usage_zkp_smp_3)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, msg->c2)) {
    otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);
    return otrng_false;
  }
  otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);

  /* c3 = HashToScalar(4 || G * d3 + G3b * c3). */
  goldilocks_448_point_scalarmul(gb_c, msg->g3b, msg->c3);
  goldilocks_448_point_scalarmul(g_d, goldilocks_448_point_base, msg->d3);
  goldilocks_448_point_add(g_d, g_d, gb_c);

  if (otrng_serialize_ec_point(ser_point_2, g_d) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  if (!hash_to_scalar(temp_scalar, ser_point_2, ED448_POINT_BYTES,
                      usage_smp_zkp_4)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, msg->c3)) {
    otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);
    return otrng_false;
  }
  otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);

  /* cp = HashToScalar(5 || G3 * d5 + Pb * cp || G * d5 + G2 * d6 +
   Qb * cp) */
  goldilocks_448_point_scalarmul(point_cp, msg->pb, msg->cp);
  goldilocks_448_point_scalarmul(g_d, smp->g3, msg->d5);
  goldilocks_448_point_add(g_d, g_d, point_cp);

  if (otrng_serialize_ec_point(ser_point_3, g_d) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  goldilocks_448_point_scalarmul(point_cp, msg->qb, msg->cp);
  goldilocks_448_point_scalarmul(g_d, smp->g2, msg->d6);
  goldilocks_448_point_add(g_d, g_d, point_cp);
  goldilocks_448_point_scalarmul(point_cp, goldilocks_448_point_base, msg->d5);
  goldilocks_448_point_add(g_d, g_d, point_cp);

  if (otrng_serialize_ec_point(ser_point_4, g_d) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  hash_init(hd);

  if (hash_update(hd, ser_point_3, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return otrng_false;
  }

  if (hash_update(hd, ser_point_4, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return otrng_false;
  }

  hash_final(hd, hash, HASH_BYTES);
  hash_destroy(hd);

  otrng_secure_wipe(ser_point_3, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_4, ED448_POINT_BYTES);

  if (!hash_to_scalar(temp_scalar, hash, HASH_BYTES, usage_zkp_smp_5)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, msg->cp)) {
    return otrng_false;
  }

  return otrng_true;
}

tstatic void smp_message_2_destroy(smp_message_2_s *msg) {
  otrng_ec_point_destroy(msg->g2b);
  otrng_ec_point_destroy(msg->g3b);
  otrng_ec_point_destroy(msg->pb);
  otrng_ec_point_destroy(msg->qb);
  otrng_ec_scalar_destroy(msg->c3);
  otrng_ec_scalar_destroy(msg->d3);
  otrng_ec_scalar_destroy(msg->c2);
  otrng_ec_scalar_destroy(msg->d2);
  otrng_ec_scalar_destroy(msg->cp);
  otrng_ec_scalar_destroy(msg->d5);
  otrng_ec_scalar_destroy(msg->d6);
}

tstatic otrng_result generate_smp_message_3(smp_message_3_s *dst,
                                            const smp_message_2_s *msg_2,
                                            smp_protocol_s *smp) {
  ecdh_keypair_s pair_r4, pair_r5, pair_r7;
  ec_scalar r6;
  ec_point temp_point;
  ec_scalar secret_as_scalar;
  uint8_t ser_point_1[ED448_POINT_BYTES];
  uint8_t ser_point_2[ED448_POINT_BYTES];
  uint8_t hash_1[HASH_BYTES];
  goldilocks_shake256_ctx_p hd_2;
  uint8_t usage_smp_6 = 0x06;
  uint8_t ser_point_3[ED448_POINT_BYTES];
  uint8_t ser_point_4[ED448_POINT_BYTES];
  uint8_t hash_2[HASH_BYTES];
  goldilocks_shake256_ctx_p hd_3;
  uint8_t usage_smp_7 = 0x07;

  ed448_random_scalar(r6);

  otrng_zq_keypair_generate(pair_r4.pub, pair_r4.priv);
  otrng_zq_keypair_generate(pair_r5.pub, pair_r5.priv);
  otrng_zq_keypair_generate(pair_r7.pub, pair_r7.priv);

  otrng_ec_point_copy(smp->g3b, msg_2->g3b);

  /* Pa = (G3 * r4) */
  goldilocks_448_point_scalarmul(dst->pa, smp->g3, pair_r4.priv);
  goldilocks_448_point_sub(smp->pa_pb, dst->pa, msg_2->pb);

  /* Qa = G * r4 + G2 * (x mod q)) */
  if (!otrng_deserialize_ec_scalar(secret_as_scalar, smp->secret, HASH_BYTES)) {
    return OTRNG_ERROR;
  }

  goldilocks_448_point_scalarmul(dst->qa, smp->g2, secret_as_scalar);
  goldilocks_448_point_add(dst->qa, pair_r4.pub, dst->qa);

  /* cp = HashToScalar(6 || G3 * r5 || G * r5 + G2 * r6) */
  goldilocks_448_point_scalarmul(temp_point, smp->g3, pair_r5.priv);

  if (otrng_serialize_ec_point(ser_point_1, temp_point) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  goldilocks_448_point_scalarmul(temp_point, smp->g2, r6);
  goldilocks_448_point_add(temp_point, pair_r5.pub, temp_point);

  if (otrng_serialize_ec_point(ser_point_2, temp_point) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  hash_init(hd_2);

  if (hash_update(hd_2, ser_point_1, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd_2);
    return OTRNG_ERROR;
  }

  if (hash_update(hd_2, ser_point_2, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd_2);
    return OTRNG_ERROR;
  }

  hash_final(hd_2, hash_1, HASH_BYTES);
  hash_destroy(hd_2);

  otrng_secure_wipe(ser_point_1, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_2, ED448_POINT_BYTES);

  if (!hash_to_scalar(dst->cp, hash_1, HASH_BYTES, usage_smp_6)) {
    return OTRNG_ERROR;
  }

  /* d5 = (r5 - r4 * cp mod q). */
  goldilocks_448_scalar_mul(dst->d5, pair_r4.priv, dst->cp);
  goldilocks_448_scalar_sub(dst->d5, pair_r5.priv, dst->d5);

  /* d6 = (r6 - (x mod q) * cp) mod q. */
  goldilocks_448_scalar_mul(dst->d6, secret_as_scalar, dst->cp);
  goldilocks_448_scalar_sub(dst->d6, r6, dst->d6);

  /* Ra = ((Qa - Qb) * a3) */
  goldilocks_448_point_sub(smp->qa_qb, dst->qa, msg_2->qb);
  goldilocks_448_point_scalarmul(dst->ra, smp->qa_qb, smp->a3);

  /* cr = HashToScalar(7 || G * r7 || (Qa - Qb) * r7) */
  if (otrng_serialize_ec_point(ser_point_3, pair_r7.pub) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  goldilocks_448_point_scalarmul(temp_point, smp->qa_qb, pair_r7.priv);
  if (otrng_serialize_ec_point(ser_point_4, temp_point) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  hash_init(hd_3);

  if (hash_update(hd_3, ser_point_3, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd_3);
    return OTRNG_ERROR;
  }

  if (hash_update(hd_3, ser_point_4, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd_3);
    return OTRNG_ERROR;
  }

  hash_final(hd_3, hash_2, HASH_BYTES);
  hash_destroy(hd_3);

  otrng_secure_wipe(ser_point_3, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_4, ED448_POINT_BYTES);

  if (!hash_to_scalar(dst->cr, hash_2, HASH_BYTES, usage_smp_7)) {
    return OTRNG_ERROR;
  }

  /* d7 = (r7 - a3 * cr mod q). */
  goldilocks_448_scalar_mul(dst->d7, smp->a3, dst->cr);
  goldilocks_448_scalar_sub(dst->d7, pair_r7.priv, dst->d7);

  otrng_secure_wipe(secret_as_scalar, ED448_SCALAR_BYTES);

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_3_serialize(uint8_t **dst, size_t *len,
                                             const smp_message_3_s *msg) {
  size_t size = 0;
  uint8_t *cursor;
  size += (3 * ED448_POINT_BYTES) + (5 * ED448_SCALAR_BYTES);

  *dst = otrng_xmalloc_z(size);

  cursor = *dst;

  cursor += otrng_serialize_ec_point(cursor, msg->pa);
  cursor += otrng_serialize_ec_point(cursor, msg->qa);
  cursor += otrng_serialize_ec_scalar(cursor, msg->cp);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d5);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d6);
  cursor += otrng_serialize_ec_point(cursor, msg->ra);
  cursor += otrng_serialize_ec_scalar(cursor, msg->cr);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d7);

  if (len) {
    *len = (cursor - *dst);
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_3_deserialize(smp_message_3_s *dst,
                                               const tlv_s *tlv) {
  const uint8_t *cursor = tlv->data;
  uint16_t len = tlv->len;

  if (!otrng_deserialize_ec_point(dst->pa, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_point(dst->qa, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(dst->cp, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(dst->d5, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(dst->d6, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_point(dst->ra, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(dst->cr, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(dst->d7, cursor, len)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_bool smp_message_3_validate_points(smp_message_3_s *msg) {
  return otrng_ec_point_valid(msg->pa) && otrng_ec_point_valid(msg->qa) &&
         otrng_ec_point_valid(msg->ra);
}

tstatic otrng_bool smp_message_3_validate_zkp(smp_message_3_s *msg,
                                              const smp_protocol_s *smp) {
  ec_point temp_point, temp_point_2;
  ec_scalar temp_scalar;
  uint8_t ser_point_1[ED448_POINT_BYTES];
  uint8_t ser_point_2[ED448_POINT_BYTES];
  uint8_t hash_1[HASH_BYTES];
  goldilocks_shake256_ctx_p hd_1;
  uint8_t usage_zkp_smp_6 = 0x06;
  uint8_t ser_point_3[ED448_POINT_BYTES];
  uint8_t ser_point_4[ED448_POINT_BYTES];
  uint8_t hash_2[HASH_BYTES];
  goldilocks_shake256_ctx_p hd_2;
  uint8_t usage_zkp_smp_7 = 0x07;

  /* cp = HashToScalar(6 || G3 * d5 + Pa * cp || G * d5 + G2 * d6 + Qa * cp) */
  goldilocks_448_point_scalarmul(temp_point, msg->pa, msg->cp);
  goldilocks_448_point_scalarmul(temp_point_2, smp->g3, msg->d5);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  if (otrng_serialize_ec_point(ser_point_1, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  goldilocks_448_point_scalarmul(temp_point, msg->qa, msg->cp);
  goldilocks_448_point_scalarmul(temp_point_2, smp->g2, msg->d6);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);
  goldilocks_448_point_scalarmul(temp_point_2, goldilocks_448_point_base,
                                 msg->d5);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  if (otrng_serialize_ec_point(ser_point_2, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  hash_init(hd_1);

  if (hash_update(hd_1, ser_point_1, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd_1);
    return otrng_false;
  }

  if (hash_update(hd_1, ser_point_2, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd_1);
    return otrng_false;
  }

  hash_final(hd_1, hash_1, HASH_BYTES);
  hash_destroy(hd_1);

  otrng_secure_wipe(ser_point_1, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_2, ED448_POINT_BYTES);

  if (!hash_to_scalar(temp_scalar, hash_1, HASH_BYTES, usage_zkp_smp_6)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, msg->cp)) {
    return otrng_false;
  }

  /* cr = Hash_to_scalar(7 || G * d7 + G3a * cr || (Qa - Qb) * d7 + Ra * cr) */
  goldilocks_448_point_scalarmul(temp_point, smp->g3a, msg->cr);
  goldilocks_448_point_scalarmul(temp_point_2, goldilocks_448_point_base,
                                 msg->d7);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  if (otrng_serialize_ec_point(ser_point_3, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  goldilocks_448_point_scalarmul(temp_point, msg->ra, msg->cr);
  goldilocks_448_point_sub(temp_point_2, msg->qa, smp->qb);
  goldilocks_448_point_scalarmul(temp_point_2, temp_point_2, msg->d7);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  if (otrng_serialize_ec_point(ser_point_4, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  hash_init(hd_2);

  if (hash_update(hd_2, ser_point_3, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd_2);
    return otrng_false;
  }

  if (hash_update(hd_2, ser_point_4, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd_2);
    return otrng_false;
  }

  hash_final(hd_2, hash_2, HASH_BYTES);
  hash_destroy(hd_2);

  otrng_secure_wipe(ser_point_3, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_4, ED448_POINT_BYTES);

  if (!hash_to_scalar(temp_scalar, hash_2, HASH_BYTES, usage_zkp_smp_7)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, msg->cr)) {
    return otrng_false;
  }

  return otrng_true;
}

tstatic void smp_message_3_destroy(smp_message_3_s *msg) {
  otrng_ec_point_destroy(msg->pa);
  otrng_ec_point_destroy(msg->qa);
  otrng_ec_point_destroy(msg->ra);
  otrng_ec_scalar_destroy(msg->cp);
  otrng_ec_scalar_destroy(msg->d5);
  otrng_ec_scalar_destroy(msg->d6);
  otrng_ec_scalar_destroy(msg->cr);
  otrng_ec_scalar_destroy(msg->d7);
}

tstatic otrng_result generate_smp_message_4(smp_message_4_s *dst,
                                            const smp_message_3_s *msg_3,
                                            smp_protocol_s *smp) {
  ec_point qa_qb;
  ecdh_keypair_s pair_r7;
  uint8_t ser_point_1[ED448_POINT_BYTES];
  uint8_t ser_point_2[ED448_POINT_BYTES];
  uint8_t hash[HASH_BYTES];
  goldilocks_shake256_ctx_p hd;
  uint8_t usage_smp_8 = 0x08;

  otrng_zq_keypair_generate(pair_r7.pub, pair_r7.priv);

  /* Rb = ((Qa - Qb) * b3) */
  goldilocks_448_point_sub(qa_qb, msg_3->qa, smp->qb);
  goldilocks_448_point_scalarmul(dst->rb, qa_qb, smp->b3);

  /* cr = HashToScalar(8 || G * r7 || (Qa - Qb) * r7) */
  if (otrng_serialize_ec_point(ser_point_1, pair_r7.pub) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  goldilocks_448_point_scalarmul(qa_qb, qa_qb, pair_r7.priv);

  if (otrng_serialize_ec_point(ser_point_2, qa_qb) != ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  hash_init(hd);

  if (hash_update(hd, ser_point_1, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, ser_point_2, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  hash_final(hd, hash, HASH_BYTES);
  hash_destroy(hd);

  otrng_secure_wipe(ser_point_1, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_2, ED448_POINT_BYTES);

  if (!hash_to_scalar(dst->cr, hash, HASH_BYTES, usage_smp_8)) {
    return OTRNG_ERROR;
  }

  /* d7 = (r7 - b3 * cr mod q). */
  goldilocks_448_scalar_mul(dst->d7, smp->b3, dst->cr);
  goldilocks_448_scalar_sub(dst->d7, pair_r7.priv, dst->d7);

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_4_serialize(uint8_t **dst, size_t *len,
                                             smp_message_4_s *msg) {
  size_t size = 0;
  uint8_t *cursor;
  size = ED448_POINT_BYTES + (2 * ED448_SCALAR_BYTES);

  *dst = otrng_xmalloc_z(size);

  cursor = *dst;

  cursor += otrng_serialize_ec_point(cursor, msg->rb);
  cursor += otrng_serialize_ec_scalar(cursor, msg->cr);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d7);

  if (len) {
    *len = (cursor - *dst);
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_4_deserialize(smp_message_4_s *dst,
                                               const tlv_s *tlv) {
  uint8_t *cursor = tlv->data;
  size_t len = tlv->len;

  if (!otrng_deserialize_ec_point(dst->rb, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(dst->cr, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(dst->d7, cursor, len)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_bool smp_message_4_validate_zkp(smp_message_4_s *msg,
                                              const smp_protocol_s *smp) {
  ec_point temp_point, temp_point_2;
  ec_scalar temp_scalar;
  uint8_t ser_point_1[ED448_POINT_BYTES];
  uint8_t ser_point_2[ED448_POINT_BYTES];
  uint8_t hash[HASH_BYTES];
  goldilocks_shake256_ctx_p hd;
  uint8_t usage_zkp_smp_8 = 0x08;

  /* cr = HashToScalar(8 || G * d7 + G3b * cr || (Qa - Qb) * d7 + Rb * cr). */
  goldilocks_448_point_scalarmul(temp_point, smp->g3b, msg->cr);
  goldilocks_448_point_scalarmul(temp_point_2, goldilocks_448_point_base,
                                 msg->d7);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  if (otrng_serialize_ec_point(ser_point_1, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  goldilocks_448_point_scalarmul(temp_point, msg->rb, msg->cr);
  goldilocks_448_point_scalarmul(temp_point_2, smp->qa_qb, msg->d7);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);
  if (otrng_serialize_ec_point(ser_point_2, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  hash_init(hd);

  if (hash_update(hd, ser_point_1, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return otrng_false;
  }

  if (hash_update(hd, ser_point_2, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return otrng_false;
  }

  hash_final(hd, hash, HASH_BYTES);
  hash_destroy(hd);

  otrng_secure_wipe(ser_point_1, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_2, ED448_POINT_BYTES);

  if (!hash_to_scalar(temp_scalar, hash, HASH_BYTES, usage_zkp_smp_8)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(msg->cr, temp_scalar)) {
    return otrng_false;
  }

  return otrng_true;
}

tstatic void smp_message_4_destroy(smp_message_4_s *msg) {
  otrng_ec_scalar_destroy(msg->cr);
  otrng_ec_scalar_destroy(msg->d7);

  otrng_ec_point_destroy(msg->rb);
}

tstatic otrng_bool smp_is_valid_for_message_3(const smp_message_3_s *msg,
                                              smp_protocol_s *smp) {
  ec_point rab, pa_pb;
  /* Compute Rab = (Ra * b3) */
  goldilocks_448_point_scalarmul(rab, msg->ra, smp->b3);
  /* Pa - Pb == Rab */
  goldilocks_448_point_sub(pa_pb, msg->pa, smp->pb);

  if (!otrng_ec_point_eq(pa_pb, rab)) {
    return otrng_false;
  }

  return otrng_true;
}

tstatic otrng_bool smp_is_valid_for_message_4(smp_message_4_s *msg,
                                              smp_protocol_s *smp) {
  ec_point rab;
  /* Compute Rab = Rb * a3. */
  goldilocks_448_point_scalarmul(rab, msg->rb, smp->a3);
  /* Pa - Pb == Rab */
  if (!otrng_ec_point_eq(smp->pa_pb, rab)) {
    return otrng_false;
  }

  return otrng_true;
}

tstatic otrng_smp_event receive_smp_message_1(const tlv_s *tlv,
                                              smp_protocol_s *smp) {
  smp_message_1_s msg_1;

  if (smp->state_expect != SMP_STATE_EXPECT_1) {
    smp->progress = SMP_ZERO_PROGRESS;
    return OTRNG_SMP_EVENT_ABORT;
  }

  do {
    if (!smp_message_1_deserialize(&msg_1, tlv)) {
      continue;
    }

    if (!smp_message_1_valid_points(&msg_1)) {
      continue;
    }

    if (!smp_message_1_valid_zkp(&msg_1)) {
      continue;
    }

    smp->message1 = otrng_xmalloc_z(sizeof(smp_message_1_s));

    smp_message_1_copy(smp->message1, &msg_1);
    otrng_smp_message_1_destroy(&msg_1);
    return OTRNG_SMP_EVENT_NONE;
  } while (0);

  otrng_smp_message_1_destroy(&msg_1);
  return OTRNG_SMP_EVENT_ERROR;
}

INTERNAL otrng_smp_event otrng_reply_with_smp_message_2(tlv_s **to_send,
                                                        smp_protocol_s *smp) {
  smp_message_2_s msg_2;
  size_t buff_len = 0;
  uint8_t *buffer = NULL;

  *to_send = NULL;

  if (!generate_smp_message_2(&msg_2, smp->message1, smp)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_2_serialize(&buffer, &buff_len, &msg_2)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  smp_message_2_destroy(&msg_2);

  *to_send = otrng_tlv_new(OTRNG_TLV_SMP_MSG_2, buff_len, buffer);

  free(buffer);

  if (!to_send) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  smp->state_expect = SMP_STATE_EXPECT_3;
  smp->progress = SMP_HALF_PROGRESS;
  return OTRNG_SMP_EVENT_NONE;
}

tstatic otrng_smp_event receive_smp_message_2(smp_message_2_s *msg_2,
                                              const tlv_s *tlv,
                                              smp_protocol_s *smp) {
  if (smp->state_expect != SMP_STATE_EXPECT_2) {
    smp->progress = SMP_ZERO_PROGRESS;
    return OTRNG_SMP_EVENT_ABORT;
  }

  if (!smp_message_2_deserialize(msg_2, tlv)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_2_valid_points(msg_2)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  goldilocks_448_point_scalarmul(smp->g2, msg_2->g2b, smp->a2);
  goldilocks_448_point_scalarmul(smp->g3, msg_2->g3b, smp->a3);

  if (!smp_message_2_valid_zkp(msg_2, smp)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  return OTRNG_SMP_EVENT_NONE;
}

tstatic otrng_smp_event reply_with_smp_message_3(tlv_s **to_send,
                                                 const smp_message_2_s *msg_2,
                                                 smp_protocol_s *smp) {
  smp_message_3_s msg_3;
  size_t buff_len = 0;
  uint8_t *buffer = NULL;

  if (!generate_smp_message_3(&msg_3, msg_2, smp)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_3_serialize(&buffer, &buff_len, &msg_3)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  smp_message_3_destroy(&msg_3);

  *to_send = otrng_tlv_new(OTRNG_TLV_SMP_MSG_3, buff_len, buffer);

  free(buffer);

  if (!*to_send) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  smp->state_expect = SMP_STATE_EXPECT_4;
  smp->progress = SMP_HALF_PROGRESS;

  return OTRNG_SMP_EVENT_NONE;
}

tstatic otrng_smp_event receive_smp_message_3(smp_message_3_s *msg_3,
                                              const tlv_s *tlv,
                                              smp_protocol_s *smp) {
  if (smp->state_expect != SMP_STATE_EXPECT_3) {
    smp->progress = SMP_ZERO_PROGRESS;
    return OTRNG_SMP_EVENT_ABORT;
  }

  if (!smp_message_3_deserialize(msg_3, tlv)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_3_validate_points(msg_3)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_3_validate_zkp(msg_3, smp)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  smp->progress = SMP_HALF_QUARTER_PROGRESS;
  return OTRNG_SMP_EVENT_NONE;
}

tstatic otrng_smp_event reply_with_smp_message_4(tlv_s **to_send,
                                                 const smp_message_3_s *msg_3,
                                                 smp_protocol_s *smp) {
  smp_message_4_s msg_4;
  size_t buff_len = 0;
  uint8_t *buffer = NULL;

  if (!generate_smp_message_4(&msg_4, msg_3, smp)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_4_serialize(&buffer, &buff_len, &msg_4)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  *to_send = otrng_tlv_new(OTRNG_TLV_SMP_MSG_4, buff_len, buffer);

  free(buffer);

  if (!*to_send) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  /* Validates SMP */
  smp->progress = SMP_TOTAL_PROGRESS;
  smp->state_expect = SMP_STATE_EXPECT_1;
  if (!smp_is_valid_for_message_3(msg_3, smp)) {
    return OTRNG_SMP_EVENT_FAILURE;
  }

  return OTRNG_SMP_EVENT_SUCCESS;
}

tstatic otrng_smp_event receive_smp_message_4(smp_message_4_s *msg_4,
                                              const tlv_s *tlv,
                                              smp_protocol_s *smp) {
  if (smp->state_expect != SMP_STATE_EXPECT_4) {
    smp->progress = SMP_ZERO_PROGRESS;
    return OTRNG_SMP_EVENT_ABORT;
  }

  if (!smp_message_4_deserialize(msg_4, tlv)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!otrng_ec_point_valid(msg_4->rb)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_4_validate_zkp(msg_4, smp)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  smp->progress = SMP_TOTAL_PROGRESS;
  smp->state_expect = SMP_STATE_EXPECT_1;
  if (!smp_is_valid_for_message_4(msg_4, smp)) {
    return OTRNG_SMP_EVENT_FAILURE;
  }

  return OTRNG_SMP_EVENT_SUCCESS;
}

INTERNAL otrng_smp_event otrng_process_smp_message1(const tlv_s *tlv,
                                                    smp_protocol_s *smp) {
  otrng_smp_event event = receive_smp_message_1(tlv, smp);

  if (!event) {
    smp->progress = SMP_QUARTER_PROGRESS;
    event = OTRNG_SMP_EVENT_ASK_FOR_ANSWER;
  }

  return event;
}

INTERNAL otrng_smp_event otrng_process_smp_message2(tlv_s **smp_reply,
                                                    const tlv_s *tlv,
                                                    smp_protocol_s *smp) {
  smp_message_2_s msg_2;
  otrng_smp_event event = receive_smp_message_2(&msg_2, tlv, smp);

  if (!event) {
    event = reply_with_smp_message_3(smp_reply, &msg_2, smp);
  }

  smp_message_2_destroy(&msg_2);
  return event;
}

INTERNAL otrng_smp_event otrng_process_smp_message3(tlv_s **smp_reply,
                                                    const tlv_s *tlv,
                                                    smp_protocol_s *smp) {
  smp_message_3_s msg_3;
  otrng_smp_event event = receive_smp_message_3(&msg_3, tlv, smp);

  if (!event) {
    event = reply_with_smp_message_4(smp_reply, &msg_3, smp);
  }

  smp_message_3_destroy(&msg_3);
  return event;
}

INTERNAL otrng_smp_event otrng_process_smp_message4(const tlv_s *tlv,
                                                    smp_protocol_s *smp) {
  smp_message_4_s msg_4;

  otrng_smp_event event = receive_smp_message_4(&msg_4, tlv, smp);

  smp_message_4_destroy(&msg_4);

  return event;
}
