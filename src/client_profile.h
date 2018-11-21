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

#ifndef OTRNG_CLIENT_PROFILE_H
#define OTRNG_CLIENT_PROFILE_H

#include <stdint.h>

#ifndef S_SPLINT_S
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <libotr/privkey.h>
#pragma clang diagnostic pop
#endif

#include "keys.h"
#include "mpi.h"
#include "shared.h"
#include "str.h"

#define OTRNG_DH1536_MOD_LEN_BYTES 192

#define DSA_PUBKEY_MAX_BYTES (2 + 4 * (4 + OTRNG_DH1536_MOD_LEN_BYTES))
#define OTRv3_DSA_SIG_BYTES 40

#define OTRNG_CLIENT_PROFILE_FIELDS_MAX_BYTES(v)                               \
  (2 + 4                      /* instance tag */                               \
   + 2 + ED448_PUBKEY_BYTES   /* Ed448 pub key */                              \
   + 2 + ED448_PUBKEY_BYTES   /* Ed448 pub forging key */                      \
   + 2 + v                    /* Versions */                                   \
   + 2 + 8                    /* Expiration */                                 \
   + 2 + DSA_PUBKEY_MAX_BYTES /* DSA pubkey */                                 \
   + 2 + OTRv3_DSA_SIG_BYTES  /* Transitional signature */                     \
  )

#define OTRNG_CLIENT_PROFILE_MAX_BYTES(v)                                      \
  (4 +                                      /* num fields */                   \
   OTRNG_CLIENT_PROFILE_FIELDS_MAX_BYTES(v) /* Fields */                       \
   + ED448_SIGNATURE_BYTES                  /* Client Profile Signature */     \
  )

#define OTRNG_CLIENT_PROFILE_MAX_WITH_METADATA_BYTES(v)                        \
  (4 +                                      /* num fields */                   \
   OTRNG_CLIENT_PROFILE_FIELDS_MAX_BYTES(v) /* Fields */                       \
   + ED448_SIGNATURE_BYTES                  /* Client Profile Signature */     \
   + 1                                      /* metadata */                     \
  )

#define OTRNG_CLIENT_PROFILE_FIELD_INSTANCE_TAG 0x01
#define OTRNG_CLIENT_PROFILE_FIELD_PUBLIC_KEY 0x02
#define OTRNG_CLIENT_PROFILE_FIELD_FORGING_KEY 0x03
#define OTRNG_CLIENT_PROFILE_FIELD_VERSIONS 0x04
#define OTRNG_CLIENT_PROFILE_FIELD_EXPIRATION 0x05
#define OTRNG_CLIENT_PROFILE_FIELD_DSA_KEY 0x06
#define OTRNG_CLIENT_PROFILE_FIELD_TRANSITIONAL_SIGNATURE 0x07

typedef struct otrng_client_profile_s {
  uint32_t sender_instance_tag;
  otrng_public_key long_term_pub_key;
  otrng_public_key forging_pub_key;
  char *versions;
  uint64_t expires;
  uint8_t *dsa_key;
  size_t dsa_key_len;
  uint8_t *transitional_signature;

  eddsa_signature signature;

  otrng_bool should_publish;
  otrng_bool is_publishing;

  otrng_bool has_validated;
  otrng_bool validation_result;
} otrng_client_profile_s;

INTERNAL otrng_bool otrng_client_profile_copy(
    otrng_client_profile_s *dst, const otrng_client_profile_s *src);

INTERNAL void otrng_client_profile_destroy(otrng_client_profile_s *profile);

INTERNAL void otrng_client_profile_free(otrng_client_profile_s *profile);

INTERNAL otrng_result otrng_client_profile_deserialize(
    otrng_client_profile_s *target, const uint8_t *buffer, size_t buff_len,
    size_t *nread);

INTERNAL otrng_result otrng_client_profile_deserialize_with_metadata(
    otrng_client_profile_s *target, const uint8_t *buffer, size_t buff_len,
    /*@null@*/ size_t *nread);

INTERNAL otrng_result otrng_client_profile_serialize(
    uint8_t **dst, size_t *nbytes, const otrng_client_profile_s *profile);

INTERNAL otrng_result otrng_client_profile_serialize_with_metadata(
    uint8_t **dst, size_t *nbytes, const otrng_client_profile_s *profile);

INTERNAL otrng_client_profile_s *otrng_client_profile_build(
    uint32_t instance_tag, const char *versions, const otrng_keypair_s *keypair,
    const otrng_public_key forging_key, unsigned int expiration_time);

INTERNAL otrng_bool otrng_client_profile_is_close_to_expiry(
    const otrng_client_profile_s *profile, uint64_t buffer_time);

INTERNAL otrng_bool otrng_client_profile_is_expired_but_valid(
    const otrng_client_profile_s *profile, uint32_t itag,
    uint64_t extra_valid_time);

INTERNAL otrng_bool otrng_client_profile_valid(
    const otrng_client_profile_s *profile, const uint32_t sender_instance_tag);

INTERNAL otrng_bool otrng_client_profile_fast_valid(
    otrng_client_profile_s *profile, const uint32_t sender_instance_tag);

INTERNAL otrng_result otrng_client_profile_transitional_sign(
    otrng_client_profile_s *profile, OtrlPrivKey *privkey);

API void otrng_client_profile_start_publishing(otrng_client_profile_s *profile);
API otrng_bool
otrng_client_profile_should_publish(const otrng_client_profile_s *profile);

#ifdef DEBUG_API

API void otrng_client_profile_debug_print(FILE *, int,
                                          otrng_client_profile_s *);

#endif

#ifdef OTRNG_USER_PROFILE_PRIVATE

tstatic otrng_client_profile_s *client_profile_new(const char *versions);

tstatic otrng_result client_profile_sign(otrng_client_profile_s *profile,
                                         const otrng_keypair_s *keypair);

tstatic otrng_result client_profile_body_serialize_into(
    uint8_t **dst, size_t *nbytes, const otrng_client_profile_s *profile);

tstatic otrng_bool
client_profile_verify_signature(const otrng_client_profile_s *profile);

tstatic otrng_result client_profile_verify_transitional_signature(
    const otrng_client_profile_s *profile);

#endif

#endif
