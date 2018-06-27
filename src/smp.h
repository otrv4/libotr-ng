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

#ifndef OTRNG_SMP_H
#define OTRNG_SMP_H

#include "client_callbacks.h"
#include "fingerprint.h"
#include "shared.h"
#include "str.h"
#include "tlv.h"

#define SMP_VERSION 0x01
#define SMP_MIN_SECRET_BYTES (1 + 64 * 2 + 8)

typedef enum {
  SMPSTATE_EXPECT1,
  SMPSTATE_EXPECT2,
  SMPSTATE_EXPECT3,
  SMPSTATE_EXPECT4
} smp_state_t;

/**
 * @warning the [question] field is NOT zero terminated, and can't be relied on
 *    to be. the length of this field is contained in the [q_len] field.
 **/
typedef struct smp_msg_1_s {
  uint32_t q_len;
  uint8_t *question;
  ec_point_p g2a;
  ec_scalar_p c2;
  ec_scalar_p d2;
  ec_point_p g3a;
  ec_scalar_p c3;
  ec_scalar_p d3;
} smp_msg_1_s, smp_msg_1_p[1];

typedef struct smp_msg_2_s {
  ec_point_p g2b;
  ec_scalar_p c2;
  ec_scalar_p d2;
  ec_point_p g3b;
  ec_scalar_p c3;
  ec_scalar_p d3;
  ec_point_p pb;
  ec_point_p qb;
  ec_scalar_p cp;
  ec_scalar_p d5;
  ec_scalar_p d6;
} smp_msg_2_s, smp_msg_2_p[1];

typedef struct smp_msg_3_s {
  ec_point_p pa, qa;
  ec_scalar_p cp, d5, d6;
  ec_point_p ra;
  ec_scalar_p cr, d7;
} smp_msg_3_s, smp_msg_3_p[1];

typedef struct smp_msg_4_s {
  ec_point_p rb;
  ec_scalar_p cr, d7;
} smp_msg_4_s, smp_msg_4_p[1];

typedef struct smp_context_s {
  smp_state_t state;
  unsigned char *secret; /* already hashed: 64 bytes long */
  ec_scalar_p a2, a3, b3;
  ec_point_p g2, g3;
  ec_point_p g3a, g3b;
  ec_point_p pb, qb;
  ec_point_p pa_pb, qa_qb;

  uint8_t progress;
  smp_msg_1_s *msg1;
} smp_context_s, smp_context_p[1];

INTERNAL void otrng_smp_context_init(smp_context_p smp);

INTERNAL void otrng_smp_destroy(smp_context_p smp);

INTERNAL otrng_err otrng_generate_smp_secret(unsigned char **secret,
                                             otrng_fingerprint_p our_fp,
                                             otrng_fingerprint_p their_fp,
                                             uint8_t *ssid,
                                             const uint8_t *answer,
                                             size_t answerlen);

INTERNAL otrng_err otrng_generate_smp_msg_1(smp_msg_1_s *dst,
                                            smp_context_p smp);

INTERNAL otrng_err otrng_smp_msg_1_asprintf(uint8_t **dst, size_t *len,
                                            const smp_msg_1_s *msg);

INTERNAL void otrng_smp_msg_1_destroy(smp_msg_1_s *msg);

INTERNAL otrng_smp_event_t otrng_reply_with_smp_msg_2(tlv_s **to_send,
                                                      smp_context_p smp);

// TODO: @refactoring should be exposed?
INTERNAL otrng_smp_event_t otrng_process_smp_msg1(const tlv_s *tlv,
                                                  smp_context_p smp);

INTERNAL otrng_smp_event_t otrng_process_smp_msg2(tlv_s **smp_reply,
                                                  const tlv_s *tlv,
                                                  smp_context_p smp);

INTERNAL otrng_smp_event_t otrng_process_smp_msg3(tlv_s **smp_reply,
                                                  const tlv_s *tlv,
                                                  smp_context_p smp);

INTERNAL otrng_smp_event_t otrng_process_smp_msg4(const tlv_s *tlv,
                                                  smp_context_p smp);

#ifdef OTRNG_SMP_PRIVATE

tstatic otrng_err smp_msg_1_deserialize(smp_msg_1_s *msg, const tlv_s *tlv);

tstatic otrng_err generate_smp_msg_2(smp_msg_2_s *dst, const smp_msg_1_s *msg_1,
                                     smp_context_p smp);

tstatic otrng_err smp_msg_2_deserialize(smp_msg_2_s *dst, const tlv_s *tlv);

tstatic void smp_msg_2_destroy(smp_msg_2_s *msg);

tstatic otrng_err generate_smp_msg_3(smp_msg_3_s *dst, const smp_msg_2_s *msg_2,
                                     smp_context_p smp);

tstatic otrng_err generate_smp_msg_4(smp_msg_4_s *dst, const smp_msg_3_s *msg_3,
                                     smp_context_p smp);

#endif

#endif
