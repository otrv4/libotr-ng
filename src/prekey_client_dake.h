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

/**
 * TODO: concurrency comment
 */

#ifndef OTRNG_PREKEY_CLIENT_DAKE_H
#define OTRNG_PREKEY_CLIENT_DAKE_H

#include <stdint.h>

#include "alloc.h"
#include "auth.h"
#include "client_profile.h"
#include "shared.h"

#define OTRNG_PREKEY_DAKE1_MSG 0x35
#define OTRNG_PREKEY_DAKE2_MSG 0x36
#define OTRNG_PREKEY_DAKE3_MSG 0x37

typedef struct {
  uint32_t client_instance_tag;
  otrng_client_profile_s *client_profile;
  ec_point I;
} otrng_prekey_dake1_message_s;

typedef struct {
  uint32_t client_instance_tag;

  uint8_t *composite_identity;
  size_t composite_identity_len;

  uint8_t *server_identity;
  size_t server_identity_len;
  otrng_public_key server_pub_key;
  ec_point S;
  ring_sig_s *sigma;
} otrng_prekey_dake2_message_s;

typedef struct {
  uint32_t client_instance_tag;
  ring_sig_s *sigma;
  uint8_t *msg;
  size_t msg_len;
} otrng_prekey_dake3_message_s;

INTERNAL void
otrng_prekey_dake1_message_destroy(otrng_prekey_dake1_message_s *msg);

INTERNAL otrng_result otrng_prekey_dake1_message_serialize(
    uint8_t **ser, size_t *ser_len, const otrng_prekey_dake1_message_s *msg);

INTERNAL otrng_prekey_dake2_message_s *otrng_prekey_dake2_message_new(void);

INTERNAL void
otrng_prekey_dake2_message_init(otrng_prekey_dake2_message_s *msg);

INTERNAL otrng_result otrng_prekey_dake2_message_deserialize(
    otrng_prekey_dake2_message_s *dst, const uint8_t *ser, size_t ser_len);

INTERNAL void
otrng_prekey_dake2_message_destroy(otrng_prekey_dake2_message_s *msg);

INTERNAL otrng_prekey_dake3_message_s *otrng_prekey_dake3_message_new(void);

INTERNAL void
otrng_prekey_dake3_message_init(otrng_prekey_dake3_message_s *msg);

INTERNAL void
otrng_prekey_dake3_message_destroy(otrng_prekey_dake3_message_s *msg);

INTERNAL void
otrng_prekey_dake3_message_serialize(uint8_t **ser, size_t *ser_len,
                                     const otrng_prekey_dake3_message_s *msg);

#ifdef OTRNG_PREKEY_CLIENT_DAKE_PRIVATE

#endif

#endif
