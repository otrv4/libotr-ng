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

#ifndef OTRNG_SMP_PROTOCOL_H
#define OTRNG_SMP_PROTOCOL_H

#include "client_callbacks.h"
#include "fingerprint.h"
#include "shared.h"
#include "str.h"
#include "tlv.h"

#define SMP_VERSION 0x01
#define SMP_MIN_SECRET_BYTES (1 + 64 * 2 + 8)

#define SMP_ZERO_PROGRESS 0
#define SMP_QUARTER_PROGRESS 25
#define SMP_HALF_PROGRESS 50
#define SMP_HALF_QUARTER_PROGRESS 75
#define SMP_TOTAL_PROGRESS 100

/**
 * @warning the [question] field is NOT zero terminated, and can't be relied on
 *    to be. the length of this field is contained in the [q_len] field.
 **/
typedef struct smp_message_1_s {
  uint8_t *question;
  size_t q_len;
  ec_point_t g2a;
  ec_scalar_t c2;
  ec_scalar_t d2;
  ec_point_t g3a;
  ec_scalar_t c3;
  ec_scalar_t d3;
} smp_message_1_s;

typedef struct smp_message_2_s {
  ec_point_t g2b;
  ec_scalar_t c2;
  ec_scalar_t d2;
  ec_point_t g3b;
  ec_scalar_t c3;
  ec_scalar_t d3;
  ec_point_t pb;
  ec_point_t qb;
  ec_scalar_t cp;
  ec_scalar_t d5;
  ec_scalar_t d6;
} smp_message_2_s;

typedef struct smp_message_3_s {
  ec_point_t pa, qa;
  ec_scalar_t cp, d5, d6;
  ec_point_t ra;
  ec_scalar_t cr, d7;
} smp_message_3_s;

typedef struct smp_message_4_s {
  ec_point_t rb;
  ec_scalar_t cr, d7;
} smp_message_4_s;

typedef struct smp_protocol_s {
  char state_expect; // TODO: why is this a char? Let's extract this
  uint8_t *secret;   /* already hashed: 64 bytes long */
  ec_scalar_t a2, a3, b3;
  ec_point_t g2, g3;
  ec_point_t g3a, g3b;
  ec_point_t pb, qb;
  ec_point_t pa_pb, qa_qb;

  uint8_t progress;
  smp_message_1_s *message1;
} smp_protocol_s;

INTERNAL void otrng_smp_protocol_init(smp_protocol_s *smp);

INTERNAL void otrng_smp_destroy(smp_protocol_s *smp);

INTERNAL otrng_result otrng_generate_smp_secret(unsigned char **secret,
                                                otrng_fingerprint our_fp,
                                                otrng_fingerprint their_fp,
                                                uint8_t *ssid,
                                                const uint8_t *answer,
                                                size_t answer_len);

INTERNAL otrng_result otrng_generate_smp_message_1(smp_message_1_s *destination,
                                                   smp_protocol_s *smp);

INTERNAL otrng_result otrng_smp_message_1_serialize(
    uint8_t **destination, size_t *len, const smp_message_1_s *message);

INTERNAL void otrng_smp_message_1_destroy(smp_message_1_s *message);

INTERNAL otrng_smp_event_t otrng_reply_with_smp_message_2(tlv_s **to_send,
                                                          smp_protocol_s *smp);

INTERNAL otrng_smp_event_t otrng_process_smp_message1(const tlv_s *tlv,
                                                      smp_protocol_s *smp);

INTERNAL otrng_smp_event_t otrng_process_smp_message2(tlv_s **smp_reply,
                                                      const tlv_s *tlv,
                                                      smp_protocol_s *smp);

INTERNAL otrng_smp_event_t otrng_process_smp_message3(tlv_s **smp_reply,
                                                      const tlv_s *tlv,
                                                      smp_protocol_s *smp);

INTERNAL otrng_smp_event_t otrng_process_smp_message4(const tlv_s *tlv,
                                                      smp_protocol_s *smp);

#ifdef OTRNG_SMP_PROTOCOL_PRIVATE

tstatic otrng_result smp_message_1_deserialize(smp_message_1_s *message,
                                               const tlv_s *tlv);

tstatic otrng_result generate_smp_message_2(smp_message_2_s *destination,
                                            const smp_message_1_s *message_1,
                                            smp_protocol_s *smp);

tstatic otrng_result smp_message_2_deserialize(smp_message_2_s *message,
                                               const tlv_s *tlv);

tstatic void smp_message_2_destroy(smp_message_2_s *message);

tstatic otrng_result generate_smp_message_3(smp_message_3_s *destination,
                                            const smp_message_2_s *message_2,
                                            smp_protocol_s *smp);

tstatic otrng_result generate_smp_message_4(smp_message_4_s *destination,
                                            const smp_message_3_s *message_3,
                                            smp_protocol_s *smp);

#endif

#endif
