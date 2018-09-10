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

#ifndef OTRNG_DATA_MESSAGE_H
#define OTRNG_DATA_MESSAGE_H

#include <sodium.h>
#include <stdint.h>
#include <string.h>

#include "constants.h"
#include "key_management.h"
#include "shared.h"

typedef struct data_message_s {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  uint8_t flags;
  uint32_t previous_chain_n;

  uint32_t ratchet_id;
  uint32_t message_id;
  ec_point_p ecdh;
  dh_public_key_p dh;
  uint8_t nonce[DATA_MSG_NONCE_BYTES];
  uint8_t *enc_msg;
  size_t enc_msg_len;
  uint8_t mac[DATA_MSG_MAC_BYTES];
} data_message_s, data_message_p[1];

INTERNAL data_message_s *otrng_data_message_new(void);

INTERNAL void otrng_data_message_free(data_message_s *data_msg);

INTERNAL otrng_result otrng_data_message_body_asprintf(
    uint8_t **body, size_t *bodylen, const data_message_s *data_msg);

INTERNAL otrng_result otrng_data_message_deserialize(data_message_s *dst,
                                                     const uint8_t *buff,
                                                     size_t bufflen,
                                                     size_t *nread);

INTERNAL otrng_result otrng_data_message_authenticator(
    uint8_t *dst, size_t dstlen, const msg_mac_key_p mac_key,
    const uint8_t *body, size_t bodylen);

INTERNAL otrng_bool otrng_valid_data_message(msg_mac_key_p mac_key,
                                             const data_message_s *data_msg);

#ifdef OTRNG_DATA_MESSAGE_PRIVATE
tstatic void data_message_destroy(data_message_s *data_msg);
#endif

#endif
