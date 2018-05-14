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

#define OTRNG_SMP_PRIVATE

#include "smp.h"
#include "auth.h"
#include "constants.h"
#include "deserialize.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"
#include "tlv.h"

#include "debug.h"

INTERNAL void otrng_smp_context_init(smp_context_p smp) {
  smp->state = SMPSTATE_EXPECT1;
  smp->progress = 0;
  smp->msg1 = NULL;
  smp->secret = NULL;

  otrng_ec_bzero(smp->a2, ED448_SCALAR_BYTES);
  otrng_ec_bzero(smp->a3, ED448_SCALAR_BYTES);
  otrng_ec_bzero(smp->b3, ED448_SCALAR_BYTES);

  otrng_ec_bzero(smp->G2, ED448_POINT_BYTES);
  otrng_ec_bzero(smp->G3, ED448_POINT_BYTES);
  otrng_ec_bzero(smp->G3a, ED448_POINT_BYTES);
  otrng_ec_bzero(smp->G3b, ED448_POINT_BYTES);
  otrng_ec_bzero(smp->Pb, ED448_POINT_BYTES);
  otrng_ec_bzero(smp->Qb, ED448_POINT_BYTES);
  otrng_ec_bzero(smp->Pa_Pb, ED448_POINT_BYTES);
  otrng_ec_bzero(smp->Qa_Qb, ED448_POINT_BYTES);
}

INTERNAL void otrng_smp_destroy(smp_context_p smp) {
  free(smp->secret);
  smp->secret = NULL;

  otrng_smp_msg_1_destroy(smp->msg1);
  free(smp->msg1);
  smp->msg1 = NULL;

  otrng_ec_scalar_destroy(smp->a2);
  otrng_ec_scalar_destroy(smp->a3);
  otrng_ec_scalar_destroy(smp->b3);

  otrng_ec_point_destroy(smp->G2);
  otrng_ec_point_destroy(smp->G3);
  otrng_ec_point_destroy(smp->G3a);
  otrng_ec_point_destroy(smp->G3b);
  otrng_ec_point_destroy(smp->Pb);
  otrng_ec_point_destroy(smp->Qb);
  otrng_ec_point_destroy(smp->Pa_Pb);
  otrng_ec_point_destroy(smp->Qa_Qb);
}

INTERNAL otrng_err otrng_generate_smp_secret(unsigned char **secret,
                                             otrng_fingerprint_p our_fp,
                                             otrng_fingerprint_p their_fp,
                                             uint8_t *ssid,
                                             const uint8_t *answer,
                                             size_t answerlen) {
  uint8_t hash[HASH_BYTES];
  goldilocks_shake256_ctx_p hd;
  uint8_t version[1] = {0x01};

  hash_init_with_dom(hd);
  hash_update(hd, version, 1);
  hash_update(hd, our_fp, sizeof(otrng_fingerprint_p));
  hash_update(hd, their_fp, sizeof(otrng_fingerprint_p));
  hash_update(hd, ssid, sizeof(ssid));
  hash_update(hd, answer, answerlen);

  hash_final(hd, hash, sizeof(hash));
  hash_destroy(hd);

  *secret = malloc(HASH_BYTES);
  if (!*secret)
    return ERROR;

  memcpy(*secret, hash, HASH_BYTES);

  return SUCCESS;
}

tstatic otrng_err hash_to_scalar(const unsigned char *buff,
                                 const size_t bufflen, ec_scalar_p dst) {
  uint8_t hash[HASH_BYTES];

  shake_256_kdf1(hash, sizeof(hash), 0x1D, buff, bufflen);

  if (otrng_deserialize_ec_scalar(dst, hash, ED448_SCALAR_BYTES) == ERROR)
    return ERROR;

  return SUCCESS;
}

INTERNAL otrng_err otrng_generate_smp_msg_1(smp_msg_1_s *dst,
                                            smp_context_p smp) {
  ecdh_keypair_p pair_r2, pair_r3;
  int len = ED448_POINT_BYTES + 1;
  unsigned char hash[len];
  ec_scalar_p a3c3, a2c2;

  dst->q_len = 0;
  dst->question = NULL;

  /* G2a = G * a2 * and G3a = G * a3 */
  otrng_zq_keypair_generate(dst->G2a, smp->a2);
  otrng_zq_keypair_generate(dst->G3a, smp->a3);

  otrng_zq_keypair_generate(pair_r2->pub, pair_r2->priv);
  otrng_zq_keypair_generate(pair_r3->pub, pair_r3->priv);

  /* c2 = hash_to_scalar(1 || G * r2) */
  hash[0] = 0x01;
  otrng_serialize_ec_point(hash + 1, pair_r2->pub);

  if (hash_to_scalar(hash, sizeof(hash), dst->c2) == ERROR)
    return ERROR;

  /* d2 = r2 - a2 * c2 mod q */
  goldilocks_448_scalar_mul(a2c2, smp->a2, dst->c2);
  goldilocks_448_scalar_sub(dst->d2, pair_r2->priv, a2c2);

  /* c3 = hash_to_scalar(2 || G * r3) */
  hash[0] = 0x02;
  otrng_serialize_ec_point(hash + 1, pair_r3->pub);

  if (hash_to_scalar(hash, sizeof(hash), dst->c3) == ERROR)
    return ERROR;

  /* d3 = r3 - a3 * c3 mod q */
  goldilocks_448_scalar_mul(a3c3, smp->a3, dst->c3);
  goldilocks_448_scalar_sub(dst->d3, pair_r3->priv, a3c3);

  return SUCCESS;
}

tstatic void smp_msg_1_copy(smp_msg_1_s *dst, const smp_msg_1_s *src) {
  dst->q_len = src->q_len;
  dst->question = otrng_memdup(src->question, src->q_len);

  otrng_ec_point_copy(dst->G2a, src->G2a);
  otrng_ec_scalar_copy(dst->c2, src->c2);
  otrng_ec_scalar_copy(dst->d2, src->d2);
  otrng_ec_point_copy(dst->G3a, src->G3a);
  otrng_ec_scalar_copy(dst->c3, src->c3);
  otrng_ec_scalar_copy(dst->d3, src->d3);
}

INTERNAL otrng_err otrng_smp_msg_1_asprintf(uint8_t **dst, size_t *len,
                                            const smp_msg_1_s *msg) {
  size_t s = 0;
  s = 4 + msg->q_len + (2 * ED448_POINT_BYTES) + (4 * ED448_SCALAR_BYTES);

  *dst = malloc(s);
  if (!*dst)
    return ERROR;

  uint8_t *cursor = *dst;

  cursor += otrng_serialize_data(cursor, (uint8_t *)msg->question, msg->q_len);
  cursor += otrng_serialize_ec_point(cursor, msg->G2a);
  cursor += otrng_serialize_ec_scalar(cursor, msg->c2);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d2);
  cursor += otrng_serialize_ec_point(cursor, msg->G3a);
  cursor += otrng_serialize_ec_scalar(cursor, msg->c3);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d3);

  *len = s;

  return SUCCESS;
}

tstatic otrng_err smp_msg_1_deserialize(smp_msg_1_s *msg, const tlv_s *tlv) {
  const uint8_t *cursor = tlv->data;
  uint16_t len = tlv->len;
  size_t read = 0;

  msg->question = NULL;
  if (otrng_deserialize_data(&msg->question, cursor, len, &read) == ERROR)
    return ERROR;

  msg->q_len = read - 4;
  cursor += read;
  len -= read;

  if (otrng_deserialize_ec_point(msg->G2a, cursor) == ERROR)
    return ERROR;

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (otrng_deserialize_ec_scalar(msg->c2, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(msg->d2, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_point(msg->G3a, cursor))
    return ERROR;

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (otrng_deserialize_ec_scalar(msg->c3, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(msg->d3, cursor, len) == ERROR)
    return ERROR;

  return SUCCESS;
}

tstatic otrng_bool smp_msg_1_valid_points(smp_msg_1_s *msg) {
  return otrng_ec_point_valid(msg->G2a) && otrng_ec_point_valid(msg->G3a);
}

tstatic otrng_bool smp_msg_1_valid_zkp(smp_msg_1_s *msg) {
  ec_scalar_p temp_scalar;
  ec_point_p Ga_c, G_d;
  int len = ED448_POINT_BYTES + 1;
  uint8_t hash[len];

  /* Check that c2 = hash_to_scalar(1 || G * d2 + G2a * c2). */
  goldilocks_448_point_scalarmul(Ga_c, msg->G2a, msg->c2);
  goldilocks_448_point_scalarmul(G_d, goldilocks_448_point_base, msg->d2);
  goldilocks_448_point_add(G_d, G_d, Ga_c);

  hash[0] = 0x01;
  otrng_serialize_ec_point(hash + 1, G_d);

  if (hash_to_scalar(hash, ED448_POINT_BYTES + 1, temp_scalar) == ERROR)
    return otrng_false;

  if (otrng_ec_scalar_eq(temp_scalar, msg->c2))
    return otrng_false;

  /* Check that c3 = hash_to_scalar(2 || G * d3 + G3a * c3). */
  goldilocks_448_point_scalarmul(Ga_c, msg->G3a, msg->c3);
  goldilocks_448_point_scalarmul(G_d, goldilocks_448_point_base, msg->d3);
  goldilocks_448_point_add(G_d, G_d, Ga_c);

  hash[0] = 0x02;
  otrng_serialize_ec_point(hash + 1, G_d);

  if (hash_to_scalar(hash, ED448_POINT_BYTES + 1, temp_scalar) == ERROR)
    return otrng_false;

  if (otrng_ec_scalar_eq(temp_scalar, msg->c3))
    return otrng_false;

  return otrng_true;
}

INTERNAL void otrng_smp_msg_1_destroy(smp_msg_1_s *msg) {
  if (!msg)
    return;

  free(msg->question);
  msg->question = NULL;
  msg->q_len = 0;

  otrng_ec_point_destroy(msg->G2a);
  otrng_ec_point_destroy(msg->G3a);

  otrng_ec_scalar_destroy(msg->c2);
  otrng_ec_scalar_destroy(msg->c3);
  otrng_ec_scalar_destroy(msg->d2);
  otrng_ec_scalar_destroy(msg->d3);
}

tstatic otrng_err generate_smp_msg_2(smp_msg_2_s *dst, const smp_msg_1_s *msg_1,
                                     smp_context_p smp) {
  ec_scalar_p b2, r6;
  ec_scalar_p temp_scalar;
  ecdh_keypair_p pair_r2, pair_r3, pair_r4, pair_r5;
  ec_point_p temp_point;
  int len = ED448_POINT_BYTES + 1;
  unsigned char buff[len];

  /* G2b = G * b2 and G3b = G * b3 */
  otrng_zq_keypair_generate(dst->G2b, b2);
  otrng_zq_keypair_generate(dst->G3b, smp->b3);

  otrng_zq_keypair_generate(pair_r2->pub, pair_r2->priv);
  otrng_zq_keypair_generate(pair_r3->pub, pair_r3->priv);
  otrng_zq_keypair_generate(pair_r4->pub, pair_r4->priv);
  otrng_zq_keypair_generate(pair_r5->pub, pair_r5->priv);

  ed448_random_scalar(r6);

  /* c2 = HashToScalar(3 || G * r2) */
  buff[0] = 0x03;
  otrng_serialize_ec_point(buff + 1, pair_r2->pub);

  if (hash_to_scalar(buff, ED448_POINT_BYTES + 1, dst->c2) == ERROR)
    return ERROR;

  /* d2 = (r2 - b2 * c2 mod q). */
  goldilocks_448_scalar_mul(temp_scalar, b2, dst->c2);
  goldilocks_448_scalar_sub(dst->d2, pair_r2->priv, temp_scalar);

  /* c3 = HashToScalar(4 || G * r3) */
  buff[0] = 0x04;
  otrng_serialize_ec_point(buff + 1, pair_r3->pub);

  if (hash_to_scalar(buff, ED448_POINT_BYTES + 1, dst->c3) == ERROR)
    return ERROR;

  /* d3 = (r3 - b3 * c3 mod q). */
  goldilocks_448_scalar_mul(temp_scalar, smp->b3, dst->c3);
  goldilocks_448_scalar_sub(dst->d3, pair_r3->priv, temp_scalar);

  /* Compute G2 = (G2a * b2). */
  goldilocks_448_point_scalarmul(smp->G2, msg_1->G2a, b2);

  /* Compute G3 = (G3a * b3). */
  goldilocks_448_point_scalarmul(smp->G3, msg_1->G3a, smp->b3);
  otrng_ec_point_copy(smp->G3a, msg_1->G3a);

  /* Compute Pb = (G3 * r4). */
  goldilocks_448_point_scalarmul(dst->Pb, smp->G3, pair_r4->priv);
  otrng_ec_point_copy(smp->Pb, dst->Pb);

  /* Compute Qb = (G * r4 + G2 * hash_to_scalar(y)). */
  ec_scalar_p secret_as_scalar;
  if (hash_to_scalar(smp->secret, HASH_BYTES, secret_as_scalar) == ERROR)
    return ERROR;

  goldilocks_448_point_scalarmul(dst->Qb, smp->G2, secret_as_scalar);
  goldilocks_448_point_add(dst->Qb, pair_r4->pub, dst->Qb);
  otrng_ec_point_copy(smp->Qb, dst->Qb);

  /* cp = HashToScalar(5 || G3 * r5 || G * r5 + G2 * r6) */
  unsigned char buff_cp[ED448_POINT_BYTES * 2 + 1];
  buff_cp[0] = 0x05;
  goldilocks_448_point_scalarmul(temp_point, smp->G3, pair_r5->priv);

  otrng_serialize_ec_point(buff_cp + 1, temp_point);

  goldilocks_448_point_scalarmul(temp_point, smp->G2, r6);
  goldilocks_448_point_add(temp_point, pair_r5->pub, temp_point);

  otrng_serialize_ec_point(buff_cp + 1 + ED448_POINT_BYTES, temp_point);

  if (hash_to_scalar(buff_cp, ED448_POINT_BYTES * 2 + 1, dst->cp) == ERROR)
    return ERROR;

  /* d5 = (r5 - r4 * cp mod q). */
  goldilocks_448_scalar_mul(dst->d5, pair_r4->priv, dst->cp);
  goldilocks_448_scalar_sub(dst->d5, pair_r5->priv, dst->d5);

  /* d6 = (r6 - y * cp mod q). */
  goldilocks_448_scalar_mul(dst->d6, secret_as_scalar, dst->cp);
  goldilocks_448_scalar_sub(dst->d6, r6, dst->d6);

  return SUCCESS;
}

tstatic otrng_err smp_msg_2_asprintf(uint8_t **dst, size_t *len,
                                     const smp_msg_2_s *msg) {
  uint8_t *cursor;
  size_t s = 0;
  s += (4 * ED448_POINT_BYTES) + (7 * ED448_SCALAR_BYTES);

  *dst = malloc(s);
  if (!*dst)
    return ERROR;

  *len = s;
  cursor = *dst;

  cursor += otrng_serialize_ec_point(cursor, msg->G2b);
  cursor += otrng_serialize_ec_scalar(cursor, msg->c2);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d2);
  cursor += otrng_serialize_ec_point(cursor, msg->G3b);
  cursor += otrng_serialize_ec_scalar(cursor, msg->c3);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d3);
  cursor += otrng_serialize_ec_point(cursor, msg->Pb);
  cursor += otrng_serialize_ec_point(cursor, msg->Qb);
  cursor += otrng_serialize_ec_scalar(cursor, msg->cp);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d5);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d6);

  return SUCCESS;
}

tstatic otrng_err smp_msg_2_deserialize(smp_msg_2_s *msg, const tlv_s *tlv) {
  const uint8_t *cursor = tlv->data;
  uint16_t len = tlv->len;

  if (otrng_deserialize_ec_point(msg->G2b, cursor) == ERROR)
    return ERROR;

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (otrng_deserialize_ec_scalar(msg->c2, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(msg->d2, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_point(msg->G3b, cursor) == ERROR)
    return ERROR;

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (otrng_deserialize_ec_scalar(msg->c3, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(msg->d3, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_point(msg->Pb, cursor) == ERROR)
    return ERROR;

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (otrng_deserialize_ec_point(msg->Qb, cursor) == ERROR)
    return ERROR;

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (otrng_deserialize_ec_scalar(msg->cp, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(msg->d5, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(msg->d6, cursor, len) == ERROR)
    return ERROR;

  len -= ED448_SCALAR_BYTES;

  return SUCCESS;
}

tstatic otrng_bool smp_msg_2_valid_points(smp_msg_2_s *msg) {
  return otrng_ec_point_valid(msg->G2b) && otrng_ec_point_valid(msg->G3b) &&
         otrng_ec_point_valid(msg->Pb) && otrng_ec_point_valid(msg->Qb);
}

tstatic otrng_bool smp_msg_2_valid_zkp(smp_msg_2_s *msg,
                                       const smp_context_p smp) {
  ec_scalar_p temp_scalar;
  ec_point_p Gb_c, G_d, point_cp;
  int len = ED448_POINT_BYTES + 1;
  uint8_t hash[len];

  /* Check that c2 = HashToScalar(3 || G * d2 + G2b * c2). */
  goldilocks_448_point_scalarmul(Gb_c, msg->G2b, msg->c2);
  goldilocks_448_point_scalarmul(G_d, goldilocks_448_point_base, msg->d2);
  goldilocks_448_point_add(G_d, G_d, Gb_c);

  hash[0] = 0x03;
  otrng_serialize_ec_point(hash + 1, G_d);

  if (hash_to_scalar(hash, ED448_POINT_BYTES + 1, temp_scalar) == ERROR)
    return otrng_false;

  if (otrng_ec_scalar_eq(temp_scalar, msg->c2))
    return otrng_false;

  /* Check that c3 = HashToScalar(4 || G * d3 + G3b * c3). */
  goldilocks_448_point_scalarmul(Gb_c, msg->G3b, msg->c3);
  goldilocks_448_point_scalarmul(G_d, goldilocks_448_point_base, msg->d3);
  goldilocks_448_point_add(G_d, G_d, Gb_c);

  hash[0] = 0x04;
  otrng_serialize_ec_point(hash + 1, G_d);

  if (hash_to_scalar(hash, ED448_POINT_BYTES + 1, temp_scalar) == ERROR)
    return otrng_false;

  if (otrng_ec_scalar_eq(temp_scalar, msg->c3))
    return otrng_false;

  /* Check that cp = HashToScalar(5 || G3 * d5 + Pb * cp || G * d5 + G2 * d6 +
   Qb * cp) */
  uint8_t buff[2 * ED448_POINT_BYTES + 1];
  goldilocks_448_point_scalarmul(point_cp, msg->Pb, msg->cp);
  goldilocks_448_point_scalarmul(G_d, smp->G3, msg->d5);
  goldilocks_448_point_add(G_d, G_d, point_cp);

  buff[0] = 0x05;
  otrng_serialize_ec_point(buff + 1, G_d);

  goldilocks_448_point_scalarmul(point_cp, msg->Qb, msg->cp);
  goldilocks_448_point_scalarmul(G_d, smp->G2, msg->d6);
  goldilocks_448_point_add(G_d, G_d, point_cp);

  goldilocks_448_point_scalarmul(point_cp, goldilocks_448_point_base, msg->d5);
  goldilocks_448_point_add(G_d, G_d, point_cp);

  otrng_serialize_ec_point(buff + 1 + ED448_POINT_BYTES, G_d);

  if (hash_to_scalar(buff, sizeof(buff), temp_scalar) == ERROR)
    return otrng_false;

  if (otrng_ec_scalar_eq(temp_scalar, msg->cp))
    return otrng_false;

  return otrng_true;
}

tstatic void smp_msg_2_destroy(smp_msg_2_s *msg) {
  otrng_ec_point_destroy(msg->G2b);
  otrng_ec_point_destroy(msg->G3b);
  otrng_ec_point_destroy(msg->Pb);
  otrng_ec_point_destroy(msg->Qb);
  otrng_ec_scalar_destroy(msg->c3);
  otrng_ec_scalar_destroy(msg->d3);
  otrng_ec_scalar_destroy(msg->c2);
  otrng_ec_scalar_destroy(msg->d2);
  otrng_ec_scalar_destroy(msg->cp);
  otrng_ec_scalar_destroy(msg->d5);
  otrng_ec_scalar_destroy(msg->d6);
}

tstatic otrng_err generate_smp_msg_3(smp_msg_3_s *dst, const smp_msg_2_s *msg_2,
                                     smp_context_p smp) {
  ecdh_keypair_p pair_r4, pair_r5, pair_r7;
  ec_scalar_p r6, secret_as_scalar;
  ec_point_p temp_point;
  int len = 1 + (2 * ED448_POINT_BYTES);
  uint8_t buff[len];

  ed448_random_scalar(r6);

  otrng_zq_keypair_generate(pair_r4->pub, pair_r4->priv);
  otrng_zq_keypair_generate(pair_r5->pub, pair_r5->priv);
  otrng_zq_keypair_generate(pair_r7->pub, pair_r7->priv);

  otrng_ec_point_copy(smp->G3b, msg_2->G3b);

  /* Pa = (G3 * r4) */
  goldilocks_448_point_scalarmul(dst->Pa, smp->G3, pair_r4->priv);
  goldilocks_448_point_sub(smp->Pa_Pb, dst->Pa, msg_2->Pb);

  if (hash_to_scalar(smp->secret, HASH_BYTES, secret_as_scalar) == ERROR)
    return ERROR;

  /* Qa = (G * r4 + G2 * HashToScalar(x)) */
  goldilocks_448_point_scalarmul(dst->Qa, smp->G2, secret_as_scalar);
  goldilocks_448_point_add(dst->Qa, pair_r4->pub, dst->Qa);

  /* cp = HashToScalar(6 || G3 * r5 || G * r5 + G2 * r6) */
  goldilocks_448_point_scalarmul(temp_point, smp->G3, pair_r5->priv);

  buff[0] = 0x06;
  otrng_serialize_ec_point(buff + 1, temp_point);

  goldilocks_448_point_scalarmul(temp_point, smp->G2, r6);
  goldilocks_448_point_add(temp_point, pair_r5->pub, temp_point);

  otrng_serialize_ec_point(buff + 1 + ED448_POINT_BYTES, temp_point);

  if (hash_to_scalar(buff, sizeof(buff), dst->cp) == ERROR)
    return ERROR;

  /* d5 = (r5 - r4 * cp mod q). */
  goldilocks_448_scalar_mul(dst->d5, pair_r4->priv, dst->cp);
  goldilocks_448_scalar_sub(dst->d5, pair_r5->priv, dst->d5);

  /* d6 = (r6 - HashToScalar(x) * cp mod q.) */
  goldilocks_448_scalar_mul(dst->d6, secret_as_scalar, dst->cp);
  goldilocks_448_scalar_sub(dst->d6, r6, dst->d6);

  /* Ra = ((Qa - Qb) * a3) */
  goldilocks_448_point_sub(smp->Qa_Qb, dst->Qa, msg_2->Qb);
  goldilocks_448_point_scalarmul(dst->Ra, smp->Qa_Qb, smp->a3);

  /* cr = HashToScalar(7 || G * r7 || (Qa - Qb) * r7) */
  buff[0] = 0x07;
  otrng_serialize_ec_point(buff + 1, pair_r7->pub);

  goldilocks_448_point_scalarmul(temp_point, smp->Qa_Qb, pair_r7->priv);
  otrng_serialize_ec_point(buff + 1 + ED448_POINT_BYTES, temp_point);

  if (hash_to_scalar(buff, sizeof(buff), dst->cr) == ERROR)
    return ERROR;

  /* d7 = (r7 - a3 * cr mod q). */
  goldilocks_448_scalar_mul(dst->d7, smp->a3, dst->cr);
  goldilocks_448_scalar_sub(dst->d7, pair_r7->priv, dst->d7);

  return SUCCESS;
}

tstatic otrng_err smp_msg_3_asprintf(uint8_t **dst, size_t *len,
                                     const smp_msg_3_s *msg) {
  uint8_t *cursor;
  size_t s = 0;
  s += (3 * ED448_POINT_BYTES) + (5 * ED448_SCALAR_BYTES);

  *dst = malloc(s);
  if (!*dst)
    return ERROR;

  *len = s;
  cursor = *dst;

  cursor += otrng_serialize_ec_point(cursor, msg->Pa);
  cursor += otrng_serialize_ec_point(cursor, msg->Qa);
  cursor += otrng_serialize_ec_scalar(cursor, msg->cp);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d5);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d6);
  cursor += otrng_serialize_ec_point(cursor, msg->Ra);
  cursor += otrng_serialize_ec_scalar(cursor, msg->cr);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d7);

  return SUCCESS;
}

tstatic otrng_err smp_msg_3_deserialize(smp_msg_3_s *dst, const tlv_s *tlv) {
  const uint8_t *cursor = tlv->data;
  uint16_t len = tlv->len;

  if (otrng_deserialize_ec_point(dst->Pa, cursor) == ERROR)
    return ERROR;

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (otrng_deserialize_ec_point(dst->Qa, cursor) == ERROR)
    return ERROR;

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (otrng_deserialize_ec_scalar(dst->cp, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(dst->d5, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(dst->d6, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_point(dst->Ra, cursor) == ERROR)
    return ERROR;

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (otrng_deserialize_ec_scalar(dst->cr, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(dst->d7, cursor, len) == ERROR)
    return ERROR;

  len -= ED448_SCALAR_BYTES;

  return SUCCESS;
}

tstatic otrng_bool smp_msg_3_validate_points(smp_msg_3_s *msg) {
  return otrng_ec_point_valid(msg->Pa) && otrng_ec_point_valid(msg->Qa) &&
         otrng_ec_point_valid(msg->Ra);
}

tstatic otrng_bool smp_msg_3_validate_zkp(smp_msg_3_s *msg,
                                          const smp_context_p smp) {
  ec_point_p temp_point, temp_point_2;
  ec_scalar_p temp_scalar;
  int len = 1 + (2 * ED448_POINT_BYTES);
  uint8_t buff[len];

  /* cp = HashToScalar(6 || G3 * d5 + Pa * cp || G * d5 + G2 * d6 + Qa * cp) */
  buff[0] = 0x06;
  goldilocks_448_point_scalarmul(temp_point, msg->Pa, msg->cp);
  goldilocks_448_point_scalarmul(temp_point_2, smp->G3, msg->d5);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);
  otrng_serialize_ec_point(buff + 1, temp_point);

  goldilocks_448_point_scalarmul(temp_point, msg->Qa, msg->cp);
  goldilocks_448_point_scalarmul(temp_point_2, smp->G2, msg->d6);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);
  goldilocks_448_point_scalarmul(temp_point_2, goldilocks_448_point_base,
                                 msg->d5);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);
  otrng_serialize_ec_point(buff + 1 + ED448_POINT_BYTES, temp_point);

  if (hash_to_scalar(buff, sizeof(buff), temp_scalar) == ERROR)
    return otrng_false;

  if (otrng_ec_scalar_eq(temp_scalar, msg->cp))
    return otrng_false;

  /* cr = Hash_to_scalar(7 || G * d7 + G3a * cr || (Qa - Qb) * d7 + Ra * cr) */
  goldilocks_448_point_scalarmul(temp_point, smp->G3a, msg->cr);
  goldilocks_448_point_scalarmul(temp_point_2, goldilocks_448_point_base,
                                 msg->d7);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  buff[0] = 0x07;
  otrng_serialize_ec_point(buff + 1, temp_point);

  goldilocks_448_point_scalarmul(temp_point, msg->Ra, msg->cr);
  goldilocks_448_point_sub(temp_point_2, msg->Qa, smp->Qb);
  goldilocks_448_point_scalarmul(temp_point_2, temp_point_2, msg->d7);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  otrng_serialize_ec_point(buff + 1 + ED448_POINT_BYTES, temp_point);

  if (hash_to_scalar(buff, sizeof(buff), temp_scalar) == ERROR)
    return otrng_false;

  if (otrng_ec_scalar_eq(temp_scalar, msg->cr))
    return otrng_false;

  return otrng_true;
}

tstatic void smp_msg_3_destroy(smp_msg_3_s *msg) {
  otrng_ec_point_destroy(msg->Pa);
  otrng_ec_point_destroy(msg->Qa);
  otrng_ec_point_destroy(msg->Ra);
  otrng_ec_scalar_destroy(msg->cp);
  otrng_ec_scalar_destroy(msg->d5);
  otrng_ec_scalar_destroy(msg->d6);
  otrng_ec_scalar_destroy(msg->cr);
  otrng_ec_scalar_destroy(msg->d7);
}

tstatic otrng_err generate_smp_msg_4(smp_msg_4_s *dst, const smp_msg_3_s *msg_3,
                                     smp_context_p smp) {
  ec_point_p Qa_Qb;
  ecdh_keypair_p pair_r7;
  otrng_zq_keypair_generate(pair_r7->pub, pair_r7->priv);
  int len = 1 + (2 * ED448_POINT_BYTES);
  uint8_t buff[len];

  /* Rb = ((Qa - Qb) * b3) */
  goldilocks_448_point_sub(Qa_Qb, msg_3->Qa, smp->Qb);
  goldilocks_448_point_scalarmul(dst->Rb, Qa_Qb, smp->b3);

  /* cr = HashToScalar(8 || G * r7 || (Qa - Qb) * r7) */
  buff[0] = 0x08;
  otrng_serialize_ec_point(buff + 1, pair_r7->pub);

  goldilocks_448_point_scalarmul(Qa_Qb, Qa_Qb, pair_r7->priv);
  otrng_serialize_ec_point(buff + 1 + ED448_POINT_BYTES, Qa_Qb);

  if (hash_to_scalar(buff, sizeof(buff), dst->cr) == ERROR)
    return ERROR;

  /* d7 = (r7 - b3 * cr mod q). */
  goldilocks_448_scalar_mul(dst->d7, smp->b3, dst->cr);
  goldilocks_448_scalar_sub(dst->d7, pair_r7->priv, dst->d7);

  return SUCCESS;
}

tstatic otrng_err smp_msg_4_asprintf(uint8_t **dst, size_t *len,
                                     smp_msg_4_s *msg) {
  size_t s = 0;
  s = ED448_POINT_BYTES + (2 * ED448_SCALAR_BYTES);

  *dst = malloc(s);
  if (!*dst)
    return ERROR;

  uint8_t *cursor = *dst;

  cursor += otrng_serialize_ec_point(cursor, msg->Rb);
  cursor += otrng_serialize_ec_scalar(cursor, msg->cr);
  cursor += otrng_serialize_ec_scalar(cursor, msg->d7);

  *len = s;

  return SUCCESS;
}

tstatic otrng_err smp_msg_4_deserialize(smp_msg_4_s *dst, const tlv_s *tlv) {
  uint8_t *cursor = tlv->data;
  size_t len = tlv->len;

  if (otrng_deserialize_ec_point(dst->Rb, cursor) == ERROR)
    return ERROR;

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (otrng_deserialize_ec_scalar(dst->cr, cursor, len) == ERROR)
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(dst->d7, cursor, len) == ERROR)
    return ERROR;

  len -= ED448_SCALAR_BYTES;

  return SUCCESS;
}

tstatic otrng_bool smp_msg_4_validate_zkp(smp_msg_4_s *msg,
                                          const smp_context_p smp) {
  ec_point_p temp_point, temp_point_2;
  ec_scalar_p temp_scalar;
  int len = 1 + (2 * ED448_POINT_BYTES);
  uint8_t buff[len];

  /* cr = HashToScalar(8 || G * d7 + G3b * cr || (Qa - Qb) * d7 + Rb * cr). */
  goldilocks_448_point_scalarmul(temp_point, smp->G3b, msg->cr);
  goldilocks_448_point_scalarmul(temp_point_2, goldilocks_448_point_base,
                                 msg->d7);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  buff[0] = 0x08;
  otrng_serialize_ec_point(buff + 1, temp_point);

  goldilocks_448_point_scalarmul(temp_point, msg->Rb, msg->cr);
  goldilocks_448_point_scalarmul(temp_point_2, smp->Qa_Qb, msg->d7);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);
  otrng_serialize_ec_point(buff + 1 + ED448_POINT_BYTES, temp_point);

  if (hash_to_scalar(buff, sizeof(buff), temp_scalar) == ERROR)
    return otrng_false;

  if (otrng_ec_scalar_eq(msg->cr, temp_scalar))
    return otrng_false;

  return otrng_true;
}

tstatic void smp_msg_4_destroy(smp_msg_4_s *msg) {
  otrng_ec_scalar_destroy(msg->cr);
  otrng_ec_scalar_destroy(msg->d7);

  otrng_ec_point_destroy(msg->Rb);
}

tstatic otrng_bool smp_is_valid_for_msg_3(const smp_msg_3_s *msg,
                                          smp_context_p smp) {
  ec_point_p Rab, Pa_Pb;
  /* Compute Rab = (Ra * b3) */
  goldilocks_448_point_scalarmul(Rab, msg->Ra, smp->b3);
  /* Pa - Pb == Rab */
  goldilocks_448_point_sub(Pa_Pb, msg->Pa, smp->Pb);

  if ((otrng_ec_point_eq(Pa_Pb, Rab)))
    return otrng_false;

  return otrng_true;
}

tstatic otrng_bool smp_is_valid_for_msg_4(smp_msg_4_s *msg, smp_context_p smp) {
  ec_point_p Rab;
  /* Compute Rab = Rb * a3. */
  goldilocks_448_point_scalarmul(Rab, msg->Rb, smp->a3);
  /* Pa - Pb == Rab */
  if (otrng_ec_point_eq(smp->Pa_Pb, Rab))
    return otrng_false;

  return otrng_true;
}

tstatic otrng_smp_event_t receive_smp_msg_1(const tlv_s *tlv,
                                            smp_context_p smp) {
  smp_msg_1_p msg_1;

  if (smp->state != SMPSTATE_EXPECT1)
    return OTRNG_SMPEVENT_ABORT;

  do {
    if (smp_msg_1_deserialize(msg_1, tlv) == ERROR)
      continue;

    if (smp_msg_1_valid_points(msg_1))
      continue;

    if (smp_msg_1_valid_zkp(msg_1))
      continue;

    smp->msg1 = malloc(sizeof(smp_msg_1_s));
    if (!smp->msg1)
      continue;

    smp_msg_1_copy(smp->msg1, msg_1);
    otrng_smp_msg_1_destroy(msg_1);
    return OTRNG_SMPEVENT_NONE;
  } while (0);

  otrng_smp_msg_1_destroy(msg_1);
  return OTRNG_SMPEVENT_ERROR;
}

INTERNAL otrng_smp_event_t otrng_reply_with_smp_msg_2(tlv_s **to_send,
                                                      smp_context_p smp) {
  smp_msg_2_p msg_2;
  size_t bufflen;
  uint8_t *buff;

  *to_send = NULL;

  // TODO: this only return error due to deserialization. It
  // should not happen
  generate_smp_msg_2(msg_2, smp->msg1, smp);
  if (smp_msg_2_asprintf(&buff, &bufflen, msg_2) == ERROR)
    return OTRNG_SMPEVENT_ERROR;

  smp_msg_2_destroy(msg_2);

  *to_send = otrng_tlv_new(OTRNG_TLV_SMP_MSG_2, bufflen, buff);

  free(buff);
  buff = NULL;

  if (!to_send)
    return OTRNG_SMPEVENT_ERROR;

  smp->state = SMPSTATE_EXPECT3;
  smp->progress = 50;
  return OTRNG_SMPEVENT_NONE;
}

tstatic otrng_smp_event_t receive_smp_msg_2(smp_msg_2_s *msg_2,
                                            const tlv_s *tlv,
                                            smp_context_p smp) {
  if (smp->state != SMPSTATE_EXPECT2)
    return OTRNG_SMPEVENT_ERROR; // TODO: this should abort

  if (smp_msg_2_deserialize(msg_2, tlv) == ERROR)
    return OTRNG_SMPEVENT_ERROR;

  if (smp_msg_2_valid_points(msg_2))
    return OTRNG_SMPEVENT_ERROR;

  goldilocks_448_point_scalarmul(smp->G2, msg_2->G2b, smp->a2);
  goldilocks_448_point_scalarmul(smp->G3, msg_2->G3b, smp->a3);

  if (smp_msg_2_valid_zkp(msg_2, smp) == otrng_false)
    return OTRNG_SMPEVENT_ERROR;

  return OTRNG_SMPEVENT_NONE;
}

tstatic otrng_smp_event_t reply_with_smp_msg_3(tlv_s **to_send,
                                               const smp_msg_2_s *msg_2,
                                               smp_context_p smp) {
  smp_msg_3_p msg_3;
  size_t bufflen = 0;
  uint8_t *buff = NULL;

  if (generate_smp_msg_3(msg_3, msg_2, smp) == ERROR)
    return OTRNG_SMPEVENT_ERROR;

  if (smp_msg_3_asprintf(&buff, &bufflen, msg_3) == ERROR)
    return OTRNG_SMPEVENT_ERROR;

  smp_msg_3_destroy(msg_3);

  *to_send = otrng_tlv_new(OTRNG_TLV_SMP_MSG_3, bufflen, buff);

  free(buff);
  buff = NULL;

  if (!to_send)
    return OTRNG_SMPEVENT_ERROR;

  smp->state = SMPSTATE_EXPECT4;
  smp->progress = 50;
  return OTRNG_SMPEVENT_NONE;
}

tstatic otrng_smp_event_t receive_smp_msg_3(smp_msg_3_s *msg_3,
                                            const tlv_s *tlv,
                                            smp_context_p smp) {
  if (smp->state != SMPSTATE_EXPECT3)
    return OTRNG_SMPEVENT_ERROR; // TODO: this errors, though it should abort

  if (smp_msg_3_deserialize(msg_3, tlv) == ERROR)
    return OTRNG_SMPEVENT_ERROR;

  if (smp_msg_3_validate_points(msg_3))
    return OTRNG_SMPEVENT_ERROR;

  if (smp_msg_3_validate_zkp(msg_3, smp))
    return OTRNG_SMPEVENT_ERROR;

  smp->progress = 75;
  return OTRNG_SMPEVENT_NONE;
}

tstatic otrng_smp_event_t reply_with_smp_msg_4(tlv_s **to_send,
                                               const smp_msg_3_s *msg_3,
                                               smp_context_p smp) {
  smp_msg_4_p msg_4;
  size_t bufflen = 0;
  uint8_t *buff = NULL;

  if (generate_smp_msg_4(msg_4, msg_3, smp) == ERROR)
    return OTRNG_SMPEVENT_ERROR;

  if (smp_msg_4_asprintf(&buff, &bufflen, msg_4) == ERROR)
    return OTRNG_SMPEVENT_ERROR;

  *to_send = otrng_tlv_new(OTRNG_TLV_SMP_MSG_4, bufflen, buff);

  free(buff);
  buff = NULL;

  if (!to_send)
    return OTRNG_SMPEVENT_ERROR;

  /* Validates SMP */
  smp->progress = 100;
  smp->state = SMPSTATE_EXPECT1;
  if (smp_is_valid_for_msg_3(msg_3, smp))
    return OTRNG_SMPEVENT_FAILURE;

  return OTRNG_SMPEVENT_SUCCESS;
}

tstatic otrng_smp_event_t receive_smp_msg_4(smp_msg_4_s *msg_4,
                                            const tlv_s *tlv,
                                            smp_context_p smp) {
  if (smp->state != SMPSTATE_EXPECT4)
    return OTRNG_SMPEVENT_ERROR; // TODO: this should abort

  if (smp_msg_4_deserialize(msg_4, tlv) == ERROR)
    return OTRNG_SMPEVENT_ERROR;

  if (otrng_ec_point_valid(msg_4->Rb) == otrng_false)
    return OTRNG_SMPEVENT_ERROR;

  if (smp_msg_4_validate_zkp(msg_4, smp))
    return OTRNG_SMPEVENT_ERROR;

  smp->progress = 100;
  smp->state = SMPSTATE_EXPECT1;
  if (smp_is_valid_for_msg_4(msg_4, smp))
    return OTRNG_SMPEVENT_FAILURE;

  return OTRNG_SMPEVENT_SUCCESS;
}

INTERNAL otrng_smp_event_t otrng_process_smp_msg1(const tlv_s *tlv,
                                                  smp_context_p smp) {
  otrng_smp_event_t event = receive_smp_msg_1(tlv, smp);

  if (!event) {
    smp->progress = 25;
    event = OTRNG_SMPEVENT_ASK_FOR_ANSWER;
  }

  return event;
}

INTERNAL otrng_smp_event_t otrng_process_smp_msg2(tlv_s **smp_reply,
                                                  const tlv_s *tlv,
                                                  smp_context_p smp) {
  smp_msg_2_p msg_2;
  otrng_smp_event_t event = receive_smp_msg_2(msg_2, tlv, smp);

  if (!event)
    event = reply_with_smp_msg_3(smp_reply, msg_2, smp);

  smp_msg_2_destroy(msg_2);
  return event;
}

INTERNAL otrng_smp_event_t otrng_process_smp_msg3(tlv_s **smp_reply,
                                                  const tlv_s *tlv,
                                                  smp_context_p smp) {
  smp_msg_3_p msg_3;
  otrng_smp_event_t event = receive_smp_msg_3(msg_3, tlv, smp);

  if (!event)
    event = reply_with_smp_msg_4(smp_reply, msg_3, smp);

  smp_msg_3_destroy(msg_3);
  return event;
}

INTERNAL otrng_smp_event_t otrng_process_smp_msg4(const tlv_s *tlv,
                                                  smp_context_p smp) {
  smp_msg_4_p msg_4;

  otrng_smp_event_t event = receive_smp_msg_4(msg_4, tlv, smp);

  smp_msg_4_destroy(msg_4);

  return event;
}
