#ifndef OTRV4_USER_PROFILE_H
#define OTRV4_USER_PROFILE_H

#include <stdint.h>

#include "shared.h"
#include "keys.h"
#include "mpi.h"
#include "str.h"

typedef struct {
  otrv4_public_key_t pub_key;
  string_t versions;
  uint64_t expires;
  otrv4_shared_prekey_pub_t shared_prekey;
  eddsa_signature_t signature;
  otrv4_mpi_t transitional_signature; // TODO: this should be a signature type
} user_profile_t;

INTERNAL otrv4_bool_t otrv4_user_profile_verify_signature(const user_profile_t *profile);

INTERNAL void otrv4_user_profile_copy(user_profile_t *dst, const user_profile_t *src);

INTERNAL void otrv4_user_profile_destroy(user_profile_t *profile);

INTERNAL void otrv4_user_profile_free(user_profile_t *profile);

INTERNAL otrv4_err_t otrv4_user_profile_deserialize(user_profile_t *target,
                                     const uint8_t *buffer, size_t buflen,
                                     size_t *nread);

INTERNAL otrv4_err_t otrv4_user_profile_asprintf(uint8_t **dst, size_t *nbytes,
                                  const user_profile_t *profile);

INTERNAL user_profile_t *
otrv4_user_profile_build(const string_t versions, otrv4_keypair_t *keypair,
                   otrv4_shared_prekey_pair_t *shared_prekey_keypair);


#ifdef OTRV4_USER_PROFILE_PRIVATE

tstatic user_profile_t *user_profile_new(const string_t versions);

tstatic otrv4_err_t user_profile_sign(user_profile_t *profile,
                              const otrv4_keypair_t *keypair);

tstatic otrv4_err_t user_profile_body_asprintf(uint8_t **dst, size_t *nbytes,
                                       const user_profile_t *profile);

#endif

#endif
