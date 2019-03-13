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
 * The functions in this file only operate on their arguments, and doesn't touch
 * any global state. It is safe to call these functions concurrently from
 * different threads, as long as arguments pointing to the same memory areas are
 * not used from different threads.
 */

#ifndef OTRNG_PREKEY_MESSAGE_H
#define OTRNG_PREKEY_MESSAGE_H

#include <stdint.h>

#include "dh.h"
#include "ed448.h"

typedef struct prekey_message_s {
  uint32_t id;
  uint32_t sender_instance_tag;
  ec_point Y;
  dh_public_key B;

  ecdh_keypair_s *y; /* Y and y */
  dh_keypair_s *b;   /* B and b */

  otrng_bool should_publish;
  otrng_bool is_publishing;
} prekey_message_s;

INTERNAL prekey_message_s *
otrng_prekey_message_create_copy(const prekey_message_s *src);

INTERNAL prekey_message_s *otrng_prekey_message_build(uint32_t instance_tag,
                                                      const ecdh_keypair_s *y,
                                                      const dh_keypair_s *b);

INTERNAL void otrng_prekey_message_free(prekey_message_s *prekey_msg);

INTERNAL otrng_result otrng_prekey_message_deserialize(prekey_message_s *dst,
                                                       const uint8_t *src,
                                                       size_t src_len,
                                                       size_t *nread);

INTERNAL otrng_result otrng_prekey_message_deserialize_with_metadata(
    prekey_message_s *dst, const uint8_t *src, size_t src_len,
    /*@null@*/ size_t *nread);

INTERNAL otrng_result otrng_prekey_message_serialize_into(
    uint8_t **dst, size_t *nbytes, const prekey_message_s *prekey_msg);

INTERNAL otrng_result otrng_prekey_message_serialize(
    uint8_t *dst, size_t dst_len, size_t *written, const prekey_message_s *src);

INTERNAL otrng_result otrng_prekey_message_serialize_with_metadata(
    uint8_t *dst, size_t dst_len, size_t *written, const prekey_message_s *src);

#ifdef OTRNG_PREKEY_MESSAGE_PRIVATE

tstatic prekey_message_s *otrng_prekey_message_new(void);

#endif

#endif
