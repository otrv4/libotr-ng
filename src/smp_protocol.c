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
  smp->state_expect = '1';
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
  hash_update(hd, version, 1);
  hash_update(hd, our_fp, FPRINT_LEN_BYTES);
  hash_update(hd, their_fp, FPRINT_LEN_BYTES);
  hash_update(hd, ssid, SSID_BYTES);
  hash_update(hd, answer, answer_len);

  hash_final(hd, hash, HASH_BYTES);
  hash_destroy(hd);

  *secret = otrng_secure_alloc(HASH_BYTES);

  memcpy(*secret, hash, HASH_BYTES);
  otrng_secure_wipe(hash, HASH_BYTES);
  free(hash);

  return OTRNG_SUCCESS;
}

tstatic otrng_result hash_to_scalar(ec_scalar_t destination, uint8_t *ser_p,
                                    size_t ser_p_len, const uint8_t usage_smp) {
  goldilocks_shake256_ctx_p hd;
  uint8_t *hash = otrng_secure_alloc(HASH_BYTES);

  hash_init_with_usage(hd, usage_smp);
  hash_update(hd, ser_p, ser_p_len);
  hash_final(hd, hash, HASH_BYTES);
  hash_destroy(hd);

  if (!otrng_deserialize_ec_scalar(destination, hash, ED448_SCALAR_BYTES)) {
    otrng_secure_wipe(hash, HASH_BYTES);
    free(hash);
    return OTRNG_ERROR;
  }
  otrng_secure_wipe(ser_p, ED448_POINT_BYTES);

  otrng_secure_wipe(hash, HASH_BYTES);
  free(hash);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_generate_smp_message_1(smp_message_1_s *destination,
                                                   smp_protocol_s *smp) {
  ecdh_keypair_s pair_r2, pair_r3;
  ec_scalar_t a3c3, a2c2;
  uint8_t ser_point_1[ED448_POINT_BYTES];
  uint8_t usage_smp_1 = 0x01;
  uint8_t ser_point_2[ED448_POINT_BYTES];
  uint8_t usage_smp_2 = 0x02;

  destination->q_len = 0;
  destination->question = NULL;

  /* G2a = G * a2 * and G3a = G * a3 */
  otrng_zq_keypair_generate(destination->g2a, smp->a2);
  otrng_zq_keypair_generate(destination->g3a, smp->a3);

  otrng_zq_keypair_generate(pair_r2.pub, pair_r2.priv);
  otrng_zq_keypair_generate(pair_r3.pub, pair_r3.priv);

  if (otrng_serialize_ec_point(ser_point_1, pair_r2.pub) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  /* c2 = hash_to_scalar(0x01 || G * r2) */
  if (!hash_to_scalar(destination->c2, ser_point_1, ED448_POINT_BYTES,
                      usage_smp_1)) {
    return OTRNG_ERROR;
  }

  /* d2 = r2 - a2 * c2 mod q */
  goldilocks_448_scalar_mul(a2c2, smp->a2, destination->c2);
  goldilocks_448_scalar_sub(destination->d2, pair_r2.priv, a2c2);

  if (otrng_serialize_ec_point(ser_point_2, pair_r3.pub) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  /* c3 = hash_to_scalar(0x02 || G * r3) */
  if (!hash_to_scalar(destination->c3, ser_point_2, ED448_POINT_BYTES,
                      usage_smp_2)) {
    return OTRNG_ERROR;
  }

  /* d3 = r3 - a3 * c3 mod q */
  goldilocks_448_scalar_mul(a3c3, smp->a3, destination->c3);
  goldilocks_448_scalar_sub(destination->d3, pair_r3.priv, a3c3);

  return OTRNG_SUCCESS;
}

tstatic void smp_message_1_copy(smp_message_1_s *destination,
                                const smp_message_1_s *source) {
  destination->q_len = source->q_len;
  if (source->question != NULL) {
    destination->question = otrng_xmemdup(source->question, source->q_len);
  } else {
    destination->question = NULL;
  }

  otrng_ec_point_copy(destination->g2a, source->g2a);
  otrng_ec_scalar_copy(destination->c2, source->c2);
  otrng_ec_scalar_copy(destination->d2, source->d2);
  otrng_ec_point_copy(destination->g3a, source->g3a);
  otrng_ec_scalar_copy(destination->c3, source->c3);
  otrng_ec_scalar_copy(destination->d3, source->d3);
}

INTERNAL otrng_result otrng_smp_message_1_serialize(
    uint8_t **destination, size_t *len, const smp_message_1_s *message) {
  size_t size = 0;
  uint8_t *cursor;
  size =
      4 + message->q_len + (2 * ED448_POINT_BYTES) + (4 * ED448_SCALAR_BYTES);

  *destination = otrng_xmalloc_z(size);

  cursor = *destination;

  cursor += otrng_serialize_data(cursor, message->question, message->q_len);
  cursor += otrng_serialize_ec_point(cursor, message->g2a);
  cursor += otrng_serialize_ec_scalar(cursor, message->c2);
  cursor += otrng_serialize_ec_scalar(cursor, message->d2);
  cursor += otrng_serialize_ec_point(cursor, message->g3a);
  cursor += otrng_serialize_ec_scalar(cursor, message->c3);
  cursor += otrng_serialize_ec_scalar(cursor, message->d3);

  if (len) {
    *len = (cursor - *destination);
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_1_deserialize(smp_message_1_s *message,
                                               const tlv_s *tlv) {
  const uint8_t *cursor = tlv->data;
  uint16_t len = tlv->len;
  size_t read = 0;

  message->question = NULL;
  if (!otrng_deserialize_data(&message->question, &message->q_len, cursor, len,
                              &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (!otrng_deserialize_ec_point(message->g2a, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(message->c2, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(message->d2, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_point(message->g3a, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(message->c3, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(message->d3, cursor, len)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_bool smp_message_1_valid_points(smp_message_1_s *message) {
  return otrng_ec_point_valid(message->g2a) &&
         otrng_ec_point_valid(message->g3a);
}

tstatic otrng_bool smp_message_1_valid_zkp(smp_message_1_s *message) {
  ec_scalar_t temp_scalar;
  ec_point_t ga_c, g_d;
  uint8_t ser_point_3[ED448_POINT_BYTES];
  uint8_t usage_zkp_smp_1 = 0x01;
  uint8_t usage_zkp_smp_2 = 0x02;
  uint8_t ser_point_4[ED448_POINT_BYTES];

  /* Check that c2 = hash_to_scalar(1 || G * d2 + G2a * c2). */
  goldilocks_448_point_scalarmul(ga_c, message->g2a, message->c2);
  goldilocks_448_point_scalarmul(g_d, goldilocks_448_point_base, message->d2);
  goldilocks_448_point_add(g_d, g_d, ga_c);

  if (otrng_serialize_ec_point(ser_point_3, g_d) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  if (!hash_to_scalar(temp_scalar, ser_point_3, ED448_POINT_BYTES,
                      usage_zkp_smp_1)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, message->c2)) {
    otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);
    return otrng_false;
  }
  otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);

  /* Check that c3 = hash_to_scalar(2 || G * d3 + G3a * c3). */
  goldilocks_448_point_scalarmul(ga_c, message->g3a, message->c3);
  goldilocks_448_point_scalarmul(g_d, goldilocks_448_point_base, message->d3);
  goldilocks_448_point_add(g_d, g_d, ga_c);

  if (otrng_serialize_ec_point(ser_point_4, g_d) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  if (!hash_to_scalar(temp_scalar, ser_point_4, ED448_POINT_BYTES,
                      usage_zkp_smp_2)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, message->c3)) {
    otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);
    return otrng_false;
  }

  otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);

  return otrng_true;
}

INTERNAL void otrng_smp_message_1_destroy(smp_message_1_s *message) {
  if (!message) {
    return;
  }

  free(message->question);
  message->question = NULL;
  message->q_len = 0;

  otrng_ec_point_destroy(message->g2a);
  otrng_ec_point_destroy(message->g3a);

  otrng_ec_scalar_destroy(message->c2);
  otrng_ec_scalar_destroy(message->c3);
  otrng_ec_scalar_destroy(message->d2);
  otrng_ec_scalar_destroy(message->d3);
}

tstatic otrng_result generate_smp_message_2(smp_message_2_s *destination,
                                            const smp_message_1_s *message_1,
                                            smp_protocol_s *smp) {
  ec_scalar_t b2, r6;
  ec_scalar_t temp_scalar;
  ecdh_keypair_s pair_r2, pair_r3, pair_r4, pair_r5;
  ec_point_t temp_point;
  uint8_t ser_point_1[ED448_POINT_BYTES];
  uint8_t usage_smp_3 = 0x03;
  uint8_t ser_point_2[ED448_POINT_BYTES];
  uint8_t usage_smp_4 = 0x04;
  ec_scalar_t secret_as_scalar;
  uint8_t ser_point_3[ED448_POINT_BYTES];
  uint8_t ser_point_4[ED448_POINT_BYTES];
  uint8_t hash[HASH_BYTES];
  goldilocks_shake256_ctx_p hd_2;
  uint8_t usage_smp_5 = 0x05;

  /* G2b = G * b2 and G3b = G * b3 */
  otrng_zq_keypair_generate(destination->g2b, b2);
  otrng_zq_keypair_generate(destination->g3b, smp->b3);

  otrng_zq_keypair_generate(pair_r2.pub, pair_r2.priv);
  otrng_zq_keypair_generate(pair_r3.pub, pair_r3.priv);
  otrng_zq_keypair_generate(pair_r4.pub, pair_r4.priv);
  otrng_zq_keypair_generate(pair_r5.pub, pair_r5.priv);

  ed448_random_scalar(r6);

  if (otrng_serialize_ec_point(ser_point_1, pair_r2.pub) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  /* c2 = HashToScalar(3 || G * r2) */
  if (!hash_to_scalar(destination->c2, ser_point_1, ED448_POINT_BYTES,
                      usage_smp_3)) {
    return OTRNG_ERROR;
  }

  /* d2 = (r2 - b2 * c2 mod q). */
  goldilocks_448_scalar_mul(temp_scalar, b2, destination->c2);
  goldilocks_448_scalar_sub(destination->d2, pair_r2.priv, temp_scalar);

  if (otrng_serialize_ec_point(ser_point_2, pair_r3.pub) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  /* c3 = HashToScalar(4 || G * r3) */
  if (!hash_to_scalar(destination->c3, ser_point_2, ED448_POINT_BYTES,
                      usage_smp_4)) {
    return OTRNG_ERROR;
  }

  /* d3 = (r3 - b3 * c3 mod q). */
  goldilocks_448_scalar_mul(temp_scalar, smp->b3, destination->c3);
  goldilocks_448_scalar_sub(destination->d3, pair_r3.priv, temp_scalar);

  /* Compute G2 = (G2a * b2). */
  goldilocks_448_point_scalarmul(smp->g2, message_1->g2a, b2);

  /* Compute G3 = (G3a * b3). */
  goldilocks_448_point_scalarmul(smp->g3, message_1->g3a, smp->b3);
  otrng_ec_point_copy(smp->g3a, message_1->g3a);

  /* Compute Pb = (G3 * r4). */
  goldilocks_448_point_scalarmul(destination->pb, smp->g3, pair_r4.priv);
  otrng_ec_point_copy(smp->pb, destination->pb);

  /* Compute Qb = (G * r4 + G2 * (y mod q)). */

  if (!otrng_deserialize_ec_scalar(secret_as_scalar, smp->secret, HASH_BYTES)) {
    return OTRNG_ERROR;
  }

  goldilocks_448_point_scalarmul(destination->qb, smp->g2, secret_as_scalar);
  goldilocks_448_point_add(destination->qb, pair_r4.pub, destination->qb);
  otrng_ec_point_copy(smp->qb, destination->qb);

  /* cp = HashToScalar(5 || G3 * r5 || G * r5 + G2 * r6) */
  goldilocks_448_point_scalarmul(temp_point, smp->g3, pair_r5.priv);
  if (otrng_serialize_ec_point(ser_point_3, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  goldilocks_448_point_scalarmul(temp_point, smp->g2, r6);
  goldilocks_448_point_add(temp_point, pair_r5.pub, temp_point);

  if (otrng_serialize_ec_point(ser_point_4, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  hash_init(hd_2);
  hash_update(hd_2, ser_point_3, ED448_POINT_BYTES);
  hash_update(hd_2, ser_point_4, ED448_POINT_BYTES);
  hash_final(hd_2, hash, HASH_BYTES);
  hash_destroy(hd_2);

  otrng_secure_wipe(ser_point_3, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_4, ED448_POINT_BYTES);

  if (!hash_to_scalar(destination->cp, hash, HASH_BYTES, usage_smp_5)) {
    return OTRNG_ERROR;
  }

  /* d5 = (r5 - r4 * cp mod q). */
  goldilocks_448_scalar_mul(destination->d5, pair_r4.priv, destination->cp);
  goldilocks_448_scalar_sub(destination->d5, pair_r5.priv, destination->d5);

  /* d6 = (r6 - (y mod q) * cp) mod q. */
  goldilocks_448_scalar_mul(destination->d6, secret_as_scalar, destination->cp);
  goldilocks_448_scalar_sub(destination->d6, r6, destination->d6);

  otrng_secure_wipe(secret_as_scalar, ED448_SCALAR_BYTES);

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_2_serialize(uint8_t **destination, size_t *len,
                                             const smp_message_2_s *message) {
  size_t size = 0;
  uint8_t *cursor;
  size += (4 * ED448_POINT_BYTES) + (7 * ED448_SCALAR_BYTES);

  *destination = otrng_xmalloc_z(size);

  cursor = *destination;

  cursor += otrng_serialize_ec_point(cursor, message->g2b);
  cursor += otrng_serialize_ec_scalar(cursor, message->c2);
  cursor += otrng_serialize_ec_scalar(cursor, message->d2);
  cursor += otrng_serialize_ec_point(cursor, message->g3b);
  cursor += otrng_serialize_ec_scalar(cursor, message->c3);
  cursor += otrng_serialize_ec_scalar(cursor, message->d3);
  cursor += otrng_serialize_ec_point(cursor, message->pb);
  cursor += otrng_serialize_ec_point(cursor, message->qb);
  cursor += otrng_serialize_ec_scalar(cursor, message->cp);
  cursor += otrng_serialize_ec_scalar(cursor, message->d5);
  cursor += otrng_serialize_ec_scalar(cursor, message->d6);

  if (len) {
    *len = (cursor - *destination);
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_2_deserialize(smp_message_2_s *message,
                                               const tlv_s *tlv) {
  const uint8_t *cursor = tlv->data;
  uint16_t len = tlv->len;

  if (!otrng_deserialize_ec_point(message->g2b, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(message->c2, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(message->d2, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_point(message->g3b, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(message->c3, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(message->d3, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_point(message->pb, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_point(message->qb, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(message->cp, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(message->d5, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(message->d6, cursor, len)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_bool smp_message_2_valid_points(smp_message_2_s *message) {
  return otrng_ec_point_valid(message->g2b) &&
         otrng_ec_point_valid(message->g3b) &&
         otrng_ec_point_valid(message->pb) && otrng_ec_point_valid(message->qb);
}

tstatic otrng_bool smp_message_2_valid_zkp(smp_message_2_s *message,
                                           const smp_protocol_s *smp) {
  ec_scalar_t temp_scalar;
  ec_point_t gb_c, g_d, point_cp;
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
  goldilocks_448_point_scalarmul(gb_c, message->g2b, message->c2);
  goldilocks_448_point_scalarmul(g_d, goldilocks_448_point_base, message->d2);
  goldilocks_448_point_add(g_d, g_d, gb_c);

  if (otrng_serialize_ec_point(ser_point_1, g_d) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  if (!hash_to_scalar(temp_scalar, ser_point_1, ED448_POINT_BYTES,
                      usage_zkp_smp_3)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, message->c2)) {
    otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);
    return otrng_false;
  }
  otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);

  /* c3 = HashToScalar(4 || G * d3 + G3b * c3). */
  goldilocks_448_point_scalarmul(gb_c, message->g3b, message->c3);
  goldilocks_448_point_scalarmul(g_d, goldilocks_448_point_base, message->d3);
  goldilocks_448_point_add(g_d, g_d, gb_c);

  if (otrng_serialize_ec_point(ser_point_2, g_d) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  if (!hash_to_scalar(temp_scalar, ser_point_2, ED448_POINT_BYTES,
                      usage_smp_zkp_4)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, message->c3)) {
    otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);
    return otrng_false;
  }
  otrng_secure_wipe(temp_scalar, ED448_SCALAR_BYTES);

  /* cp = HashToScalar(5 || G3 * d5 + Pb * cp || G * d5 + G2 * d6 +
   Qb * cp) */
  goldilocks_448_point_scalarmul(point_cp, message->pb, message->cp);
  goldilocks_448_point_scalarmul(g_d, smp->g3, message->d5);
  goldilocks_448_point_add(g_d, g_d, point_cp);

  if (otrng_serialize_ec_point(ser_point_3, g_d) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  goldilocks_448_point_scalarmul(point_cp, message->qb, message->cp);
  goldilocks_448_point_scalarmul(g_d, smp->g2, message->d6);
  goldilocks_448_point_add(g_d, g_d, point_cp);
  goldilocks_448_point_scalarmul(point_cp, goldilocks_448_point_base,
                                 message->d5);
  goldilocks_448_point_add(g_d, g_d, point_cp);

  if (otrng_serialize_ec_point(ser_point_4, g_d) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  hash_init(hd);
  hash_update(hd, ser_point_3, ED448_POINT_BYTES);
  hash_update(hd, ser_point_4, ED448_POINT_BYTES);
  hash_final(hd, hash, HASH_BYTES);
  hash_destroy(hd);

  otrng_secure_wipe(ser_point_3, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_4, ED448_POINT_BYTES);

  if (!hash_to_scalar(temp_scalar, hash, HASH_BYTES, usage_zkp_smp_5)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, message->cp)) {
    return otrng_false;
  }

  return otrng_true;
}

tstatic void smp_message_2_destroy(smp_message_2_s *message) {
  otrng_ec_point_destroy(message->g2b);
  otrng_ec_point_destroy(message->g3b);
  otrng_ec_point_destroy(message->pb);
  otrng_ec_point_destroy(message->qb);
  otrng_ec_scalar_destroy(message->c3);
  otrng_ec_scalar_destroy(message->d3);
  otrng_ec_scalar_destroy(message->c2);
  otrng_ec_scalar_destroy(message->d2);
  otrng_ec_scalar_destroy(message->cp);
  otrng_ec_scalar_destroy(message->d5);
  otrng_ec_scalar_destroy(message->d6);
}

tstatic otrng_result generate_smp_message_3(smp_message_3_s *destination,
                                            const smp_message_2_s *message_2,
                                            smp_protocol_s *smp) {
  ecdh_keypair_s pair_r4, pair_r5, pair_r7;
  ec_scalar_t r6;
  ec_point_t temp_point;
  ec_scalar_t secret_as_scalar;
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

  otrng_ec_point_copy(smp->g3b, message_2->g3b);

  /* Pa = (G3 * r4) */
  goldilocks_448_point_scalarmul(destination->pa, smp->g3, pair_r4.priv);
  goldilocks_448_point_sub(smp->pa_pb, destination->pa, message_2->pb);

  /* Qa = G * r4 + G2 * (x mod q)) */

  if (!otrng_deserialize_ec_scalar(secret_as_scalar, smp->secret, HASH_BYTES)) {
    return OTRNG_ERROR;
  }

  goldilocks_448_point_scalarmul(destination->qa, smp->g2, secret_as_scalar);
  goldilocks_448_point_add(destination->qa, pair_r4.pub, destination->qa);

  /* cp = HashToScalar(6 || G3 * r5 || G * r5 + G2 * r6) */
  goldilocks_448_point_scalarmul(temp_point, smp->g3, pair_r5.priv);

  if (otrng_serialize_ec_point(ser_point_1, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  goldilocks_448_point_scalarmul(temp_point, smp->g2, r6);
  goldilocks_448_point_add(temp_point, pair_r5.pub, temp_point);

  if (otrng_serialize_ec_point(ser_point_2, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  hash_init(hd_2);
  hash_update(hd_2, ser_point_1, ED448_POINT_BYTES);
  hash_update(hd_2, ser_point_2, ED448_POINT_BYTES);
  hash_final(hd_2, hash_1, HASH_BYTES);
  hash_destroy(hd_2);

  otrng_secure_wipe(ser_point_1, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_2, ED448_POINT_BYTES);

  if (!hash_to_scalar(destination->cp, hash_1, HASH_BYTES, usage_smp_6)) {
    return OTRNG_ERROR;
  }

  /* d5 = (r5 - r4 * cp mod q). */
  goldilocks_448_scalar_mul(destination->d5, pair_r4.priv, destination->cp);
  goldilocks_448_scalar_sub(destination->d5, pair_r5.priv, destination->d5);

  /* d6 = (r6 - (x mod q) * cp) mod q. */
  goldilocks_448_scalar_mul(destination->d6, secret_as_scalar, destination->cp);
  goldilocks_448_scalar_sub(destination->d6, r6, destination->d6);

  /* Ra = ((Qa - Qb) * a3) */
  goldilocks_448_point_sub(smp->qa_qb, destination->qa, message_2->qb);
  goldilocks_448_point_scalarmul(destination->ra, smp->qa_qb, smp->a3);

  /* cr = HashToScalar(7 || G * r7 || (Qa - Qb) * r7) */
  if (otrng_serialize_ec_point(ser_point_3, pair_r7.pub) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  goldilocks_448_point_scalarmul(temp_point, smp->qa_qb, pair_r7.priv);
  if (otrng_serialize_ec_point(ser_point_4, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  hash_init(hd_3);
  hash_update(hd_3, ser_point_3, ED448_POINT_BYTES);
  hash_update(hd_3, ser_point_4, ED448_POINT_BYTES);
  hash_final(hd_3, hash_2, HASH_BYTES);
  hash_destroy(hd_3);

  otrng_secure_wipe(ser_point_3, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_4, ED448_POINT_BYTES);

  if (!hash_to_scalar(destination->cr, hash_2, HASH_BYTES, usage_smp_7)) {
    return OTRNG_ERROR;
  }

  /* d7 = (r7 - a3 * cr mod q). */
  goldilocks_448_scalar_mul(destination->d7, smp->a3, destination->cr);
  goldilocks_448_scalar_sub(destination->d7, pair_r7.priv, destination->d7);

  otrng_secure_wipe(secret_as_scalar, ED448_SCALAR_BYTES);

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_3_serialize(uint8_t **destination, size_t *len,
                                             const smp_message_3_s *message) {
  size_t size = 0;
  uint8_t *cursor;
  size += (3 * ED448_POINT_BYTES) + (5 * ED448_SCALAR_BYTES);

  *destination = otrng_xmalloc_z(size);

  cursor = *destination;

  cursor += otrng_serialize_ec_point(cursor, message->pa);
  cursor += otrng_serialize_ec_point(cursor, message->qa);
  cursor += otrng_serialize_ec_scalar(cursor, message->cp);
  cursor += otrng_serialize_ec_scalar(cursor, message->d5);
  cursor += otrng_serialize_ec_scalar(cursor, message->d6);
  cursor += otrng_serialize_ec_point(cursor, message->ra);
  cursor += otrng_serialize_ec_scalar(cursor, message->cr);
  cursor += otrng_serialize_ec_scalar(cursor, message->d7);

  if (len) {
    *len = (cursor - *destination);
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_3_deserialize(smp_message_3_s *destination,
                                               const tlv_s *tlv) {
  const uint8_t *cursor = tlv->data;
  uint16_t len = tlv->len;

  if (!otrng_deserialize_ec_point(destination->pa, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_point(destination->qa, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(destination->cp, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(destination->d5, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(destination->d6, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_point(destination->ra, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(destination->cr, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(destination->d7, cursor, len)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_bool smp_message_3_validate_points(smp_message_3_s *message) {
  return otrng_ec_point_valid(message->pa) &&
         otrng_ec_point_valid(message->qa) && otrng_ec_point_valid(message->ra);
}

tstatic otrng_bool smp_message_3_validate_zkp(smp_message_3_s *message,
                                              const smp_protocol_s *smp) {
  ec_point_t temp_point, temp_point_2;
  ec_scalar_t temp_scalar;
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
  goldilocks_448_point_scalarmul(temp_point, message->pa, message->cp);
  goldilocks_448_point_scalarmul(temp_point_2, smp->g3, message->d5);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  if (otrng_serialize_ec_point(ser_point_1, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  goldilocks_448_point_scalarmul(temp_point, message->qa, message->cp);
  goldilocks_448_point_scalarmul(temp_point_2, smp->g2, message->d6);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);
  goldilocks_448_point_scalarmul(temp_point_2, goldilocks_448_point_base,
                                 message->d5);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  if (otrng_serialize_ec_point(ser_point_2, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  hash_init(hd_1);
  hash_update(hd_1, ser_point_1, ED448_POINT_BYTES);
  hash_update(hd_1, ser_point_2, ED448_POINT_BYTES);
  hash_final(hd_1, hash_1, HASH_BYTES);
  hash_destroy(hd_1);

  otrng_secure_wipe(ser_point_1, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_2, ED448_POINT_BYTES);

  if (!hash_to_scalar(temp_scalar, hash_1, HASH_BYTES, usage_zkp_smp_6)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, message->cp)) {
    return otrng_false;
  }

  /* cr = Hash_to_scalar(7 || G * d7 + G3a * cr || (Qa - Qb) * d7 + Ra * cr) */
  goldilocks_448_point_scalarmul(temp_point, smp->g3a, message->cr);
  goldilocks_448_point_scalarmul(temp_point_2, goldilocks_448_point_base,
                                 message->d7);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  if (otrng_serialize_ec_point(ser_point_3, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  goldilocks_448_point_scalarmul(temp_point, message->ra, message->cr);
  goldilocks_448_point_sub(temp_point_2, message->qa, smp->qb);
  goldilocks_448_point_scalarmul(temp_point_2, temp_point_2, message->d7);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  if (otrng_serialize_ec_point(ser_point_4, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  hash_init(hd_2);
  hash_update(hd_2, ser_point_3, ED448_POINT_BYTES);
  hash_update(hd_2, ser_point_4, ED448_POINT_BYTES);
  hash_final(hd_2, hash_2, HASH_BYTES);
  hash_destroy(hd_2);

  otrng_secure_wipe(ser_point_3, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_4, ED448_POINT_BYTES);

  if (!hash_to_scalar(temp_scalar, hash_2, HASH_BYTES, usage_zkp_smp_7)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(temp_scalar, message->cr)) {
    return otrng_false;
  }

  return otrng_true;
}

tstatic void smp_message_3_destroy(smp_message_3_s *message) {
  otrng_ec_point_destroy(message->pa);
  otrng_ec_point_destroy(message->qa);
  otrng_ec_point_destroy(message->ra);
  otrng_ec_scalar_destroy(message->cp);
  otrng_ec_scalar_destroy(message->d5);
  otrng_ec_scalar_destroy(message->d6);
  otrng_ec_scalar_destroy(message->cr);
  otrng_ec_scalar_destroy(message->d7);
}

tstatic otrng_result generate_smp_message_4(smp_message_4_s *destination,
                                            const smp_message_3_s *message_3,
                                            smp_protocol_s *smp) {
  ec_point_t qa_qb;
  ecdh_keypair_s pair_r7;
  uint8_t ser_point_1[ED448_POINT_BYTES];
  uint8_t ser_point_2[ED448_POINT_BYTES];
  uint8_t hash[HASH_BYTES];
  goldilocks_shake256_ctx_p hd;
  uint8_t usage_smp_8 = 0x08;

  otrng_zq_keypair_generate(pair_r7.pub, pair_r7.priv);

  /* Rb = ((Qa - Qb) * b3) */
  goldilocks_448_point_sub(qa_qb, message_3->qa, smp->qb);
  goldilocks_448_point_scalarmul(destination->rb, qa_qb, smp->b3);

  /* cr = HashToScalar(8 || G * r7 || (Qa - Qb) * r7) */
  if (otrng_serialize_ec_point(ser_point_1, pair_r7.pub) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  goldilocks_448_point_scalarmul(qa_qb, qa_qb, pair_r7.priv);

  if (otrng_serialize_ec_point(ser_point_2, qa_qb) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  hash_init(hd);
  hash_update(hd, ser_point_1, ED448_POINT_BYTES);
  hash_update(hd, ser_point_2, ED448_POINT_BYTES);
  hash_final(hd, hash, HASH_BYTES);
  hash_destroy(hd);

  otrng_secure_wipe(ser_point_1, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_2, ED448_POINT_BYTES);

  if (!hash_to_scalar(destination->cr, hash, HASH_BYTES, usage_smp_8)) {
    return OTRNG_ERROR;
  }

  /* d7 = (r7 - b3 * cr mod q). */
  goldilocks_448_scalar_mul(destination->d7, smp->b3, destination->cr);
  goldilocks_448_scalar_sub(destination->d7, pair_r7.priv, destination->d7);

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_4_serialize(uint8_t **destination, size_t *len,
                                             smp_message_4_s *message) {
  size_t size = 0;
  uint8_t *cursor;
  size = ED448_POINT_BYTES + (2 * ED448_SCALAR_BYTES);

  *destination = otrng_xmalloc_z(size);

  cursor = *destination;

  cursor += otrng_serialize_ec_point(cursor, message->rb);
  cursor += otrng_serialize_ec_scalar(cursor, message->cr);
  cursor += otrng_serialize_ec_scalar(cursor, message->d7);

  if (len) {
    *len = (cursor - *destination);
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result smp_message_4_deserialize(smp_message_4_s *destination,
                                               const tlv_s *tlv) {
  uint8_t *cursor = tlv->data;
  size_t len = tlv->len;

  if (!otrng_deserialize_ec_point(destination->rb, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_POINT_BYTES;
  len -= ED448_POINT_BYTES;

  if (!otrng_deserialize_ec_scalar(destination->cr, cursor, len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(destination->d7, cursor, len)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_bool smp_message_4_validate_zkp(smp_message_4_s *message,
                                              const smp_protocol_s *smp) {
  ec_point_t temp_point, temp_point_2;
  ec_scalar_t temp_scalar;
  uint8_t ser_point_1[ED448_POINT_BYTES];
  uint8_t ser_point_2[ED448_POINT_BYTES];
  uint8_t hash[HASH_BYTES];
  goldilocks_shake256_ctx_p hd;
  uint8_t usage_zkp_smp_8 = 0x08;

  /* cr = HashToScalar(8 || G * d7 + G3b * cr || (Qa - Qb) * d7 + Rb * cr). */
  goldilocks_448_point_scalarmul(temp_point, smp->g3b, message->cr);
  goldilocks_448_point_scalarmul(temp_point_2, goldilocks_448_point_base,
                                 message->d7);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);

  if (otrng_serialize_ec_point(ser_point_1, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  goldilocks_448_point_scalarmul(temp_point, message->rb, message->cr);
  goldilocks_448_point_scalarmul(temp_point_2, smp->qa_qb, message->d7);
  goldilocks_448_point_add(temp_point, temp_point, temp_point_2);
  if (otrng_serialize_ec_point(ser_point_2, temp_point) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  hash_init(hd);
  hash_update(hd, ser_point_1, ED448_POINT_BYTES);
  hash_update(hd, ser_point_2, ED448_POINT_BYTES);
  hash_final(hd, hash, HASH_BYTES);
  hash_destroy(hd);

  otrng_secure_wipe(ser_point_1, ED448_POINT_BYTES);
  otrng_secure_wipe(ser_point_2, ED448_POINT_BYTES);

  if (!hash_to_scalar(temp_scalar, hash, HASH_BYTES, usage_zkp_smp_8)) {
    return otrng_false;
  }

  if (!otrng_ec_scalar_eq(message->cr, temp_scalar)) {
    return otrng_false;
  }

  return otrng_true;
}

tstatic void smp_message_4_destroy(smp_message_4_s *message) {
  otrng_ec_scalar_destroy(message->cr);
  otrng_ec_scalar_destroy(message->d7);

  otrng_ec_point_destroy(message->rb);
}

tstatic otrng_bool smp_is_valid_for_message_3(const smp_message_3_s *message,
                                              smp_protocol_s *smp) {
  ec_point_t rab, pa_pb;
  /* Compute Rab = (Ra * b3) */
  goldilocks_448_point_scalarmul(rab, message->ra, smp->b3);
  /* Pa - Pb == Rab */
  goldilocks_448_point_sub(pa_pb, message->pa, smp->pb);

  if (!otrng_ec_point_eq(pa_pb, rab)) {
    return otrng_false;
  }

  return otrng_true;
}

tstatic otrng_bool smp_is_valid_for_message_4(smp_message_4_s *message,
                                              smp_protocol_s *smp) {
  ec_point_t rab;
  /* Compute Rab = Rb * a3. */
  goldilocks_448_point_scalarmul(rab, message->rb, smp->a3);
  /* Pa - Pb == Rab */
  if (!otrng_ec_point_eq(smp->pa_pb, rab)) {
    return otrng_false;
  }

  return otrng_true;
}

tstatic otrng_smp_event_t receive_smp_message_1(const tlv_s *tlv,
                                                smp_protocol_s *smp) {
  smp_message_1_s message_1;

  if (smp->state_expect != '1') {
    smp->progress = SMP_ZERO_PROGRESS;
    return OTRNG_SMP_EVENT_ABORT;
  }

  do {
    if (!smp_message_1_deserialize(&message_1, tlv)) {
      continue;
    }

    if (!smp_message_1_valid_points(&message_1)) {
      continue;
    }

    if (!smp_message_1_valid_zkp(&message_1)) {
      continue;
    }

    smp->message1 = otrng_xmalloc_z(sizeof(smp_message_1_s));

    smp_message_1_copy(smp->message1, &message_1);
    otrng_smp_message_1_destroy(&message_1);
    return OTRNG_SMP_EVENT_NONE;
  } while (0);

  otrng_smp_message_1_destroy(&message_1);
  return OTRNG_SMP_EVENT_ERROR;
}

INTERNAL otrng_smp_event_t otrng_reply_with_smp_message_2(tlv_s **to_send,
                                                          smp_protocol_s *smp) {
  smp_message_2_s message_2;
  size_t bufflen;
  uint8_t *buff;

  *to_send = NULL;

  generate_smp_message_2(&message_2, smp->message1, smp);
  if (!smp_message_2_serialize(&buff, &bufflen, &message_2)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  smp_message_2_destroy(&message_2);

  *to_send = otrng_tlv_new(OTRNG_TLV_SMP_MESSAGE_2, bufflen, buff);

  free(buff);

  if (!to_send) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  smp->state_expect = '3';
  smp->progress = SMP_HALF_PROGRESS;
  return OTRNG_SMP_EVENT_NONE;
}

tstatic otrng_smp_event_t receive_smp_message_2(smp_message_2_s *message_2,
                                                const tlv_s *tlv,
                                                smp_protocol_s *smp) {
  if (smp->state_expect != '2') {
    smp->progress = SMP_ZERO_PROGRESS;
    return OTRNG_SMP_EVENT_ABORT;
  }

  if (!smp_message_2_deserialize(message_2, tlv)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_2_valid_points(message_2)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  goldilocks_448_point_scalarmul(smp->g2, message_2->g2b, smp->a2);
  goldilocks_448_point_scalarmul(smp->g3, message_2->g3b, smp->a3);

  if (!smp_message_2_valid_zkp(message_2, smp)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  return OTRNG_SMP_EVENT_NONE;
}

tstatic otrng_smp_event_t reply_with_smp_message_3(
    tlv_s **to_send, const smp_message_2_s *message_2, smp_protocol_s *smp) {
  smp_message_3_s message_3;
  size_t bufflen = 0;
  uint8_t *buff = NULL;

  if (!generate_smp_message_3(&message_3, message_2, smp)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_3_serialize(&buff, &bufflen, &message_3)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  smp_message_3_destroy(&message_3);

  *to_send = otrng_tlv_new(OTRNG_TLV_SMP_MESSAGE_3, bufflen, buff);

  free(buff);

  if (!*to_send) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  smp->state_expect = '4';
  smp->progress = SMP_HALF_PROGRESS;

  return OTRNG_SMP_EVENT_NONE;
}

tstatic otrng_smp_event_t receive_smp_message_3(smp_message_3_s *message_3,
                                                const tlv_s *tlv,
                                                smp_protocol_s *smp) {
  if (smp->state_expect != '3') {
    smp->progress = SMP_ZERO_PROGRESS;
    return OTRNG_SMP_EVENT_ABORT;
  }

  if (!smp_message_3_deserialize(message_3, tlv)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_3_validate_points(message_3)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_3_validate_zkp(message_3, smp)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  smp->progress = SMP_HALF_QUARTER_PROGRESS;
  return OTRNG_SMP_EVENT_NONE;
}

tstatic otrng_smp_event_t reply_with_smp_message_4(
    tlv_s **to_send, const smp_message_3_s *message_3, smp_protocol_s *smp) {
  smp_message_4_s message_4;
  size_t bufflen = 0;
  uint8_t *buff = NULL;

  if (!generate_smp_message_4(&message_4, message_3, smp)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_4_serialize(&buff, &bufflen, &message_4)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  *to_send = otrng_tlv_new(OTRNG_TLV_SMP_MESSAGE_4, bufflen, buff);

  free(buff);

  if (!*to_send) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  /* Validates SMP */
  smp->progress = SMP_TOTAL_PROGRESS;
  smp->state_expect = '1';
  if (!smp_is_valid_for_message_3(message_3, smp)) {
    return OTRNG_SMP_EVENT_FAILURE;
  }

  return OTRNG_SMP_EVENT_SUCCESS;
}

tstatic otrng_smp_event_t receive_smp_message_4(smp_message_4_s *message_4,
                                                const tlv_s *tlv,
                                                smp_protocol_s *smp) {
  if (smp->state_expect != '4') {
    smp->progress = SMP_ZERO_PROGRESS;
    return OTRNG_SMP_EVENT_ABORT;
  }

  if (!smp_message_4_deserialize(message_4, tlv)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!otrng_ec_point_valid(message_4->rb)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  if (!smp_message_4_validate_zkp(message_4, smp)) {
    return OTRNG_SMP_EVENT_ERROR;
  }

  smp->progress = SMP_TOTAL_PROGRESS;
  smp->state_expect = '1';
  if (!smp_is_valid_for_message_4(message_4, smp)) {
    return OTRNG_SMP_EVENT_FAILURE;
  }

  return OTRNG_SMP_EVENT_SUCCESS;
}

INTERNAL otrng_smp_event_t otrng_process_smp_message1(const tlv_s *tlv,
                                                      smp_protocol_s *smp) {
  otrng_smp_event_t event = receive_smp_message_1(tlv, smp);

  if (!event) {
    smp->progress = SMP_QUARTER_PROGRESS;
    event = OTRNG_SMP_EVENT_ASK_FOR_ANSWER;
  }

  return event;
}

INTERNAL otrng_smp_event_t otrng_process_smp_message2(tlv_s **smp_reply,
                                                      const tlv_s *tlv,
                                                      smp_protocol_s *smp) {
  smp_message_2_s message_2;
  otrng_smp_event_t event = receive_smp_message_2(&message_2, tlv, smp);

  if (!event) {
    event = reply_with_smp_message_3(smp_reply, &message_2, smp);
  }

  smp_message_2_destroy(&message_2);
  return event;
}

INTERNAL otrng_smp_event_t otrng_process_smp_message3(tlv_s **smp_reply,
                                                      const tlv_s *tlv,
                                                      smp_protocol_s *smp) {
  smp_message_3_s message_3;
  otrng_smp_event_t event = receive_smp_message_3(&message_3, tlv, smp);

  if (!event) {
    event = reply_with_smp_message_4(smp_reply, &message_3, smp);
  }

  smp_message_3_destroy(&message_3);
  return event;
}

INTERNAL otrng_smp_event_t otrng_process_smp_message4(const tlv_s *tlv,
                                                      smp_protocol_s *smp) {
  smp_message_4_s message_4;

  otrng_smp_event_t event = receive_smp_message_4(&message_4, tlv, smp);

  smp_message_4_destroy(&message_4);

  return event;
}
