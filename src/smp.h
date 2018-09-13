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

#ifndef OTRNG_SMP_H
#define OTRNG_SMP_H

#include "protocol.h"
#include "shared.h"
#include "tlv.h"

INTERNAL tlv_s *otrng_process_smp_tlv(const tlv_s *tlv, otrng_s *otr);

INTERNAL otrng_result otrng_smp_start(string_p *to_send,
                                      const uint8_t *question,
                                      const size_t q_len, const uint8_t *answer,
                                      const size_t answer_len, otrng_s *otr);

INTERNAL otrng_result otrng_smp_continue(string_p *to_send,
                                         const uint8_t *secret,
                                         const size_t secretlen, otrng_s *otr);

API otrng_result otrng_smp_abort(string_p *to_send, otrng_s *otr);

#ifdef OTRNG_SMP_PRIVATE

tstatic tlv_s *otrng_smp_initiate(const client_profile_s *initiator_profile,
                                  const client_profile_s *responder_profile,
                                  const uint8_t *question, const size_t q_len,
                                  const uint8_t *secret, const size_t secretlen,
                                  uint8_t *ssid, smp_protocol_p smp,
                                  otrng_s *conversation);

tstatic tlv_s *otrng_smp_provide_secret(otrng_smp_event_t *event,
                                        smp_protocol_p smp,
                                        const client_profile_s *our_profile,
                                        const client_profile_s *their_profile,
                                        uint8_t *ssid, const uint8_t *secret,
                                        const size_t secretlen);

#endif

#endif
