#ifndef USER_PROFILE_H
#define USER_PROFILE_H

#include <stdint.h>

#include "keys.h"
#include "mpi.h"
#include "str.h"

typedef struct {
  otrv4_public_key_t pub_key;
  string_t versions;
  uint64_t expires;
  otrv4_shared_prekey_t shared_prekey;
  eddsa_signature_t signature;
  otr_mpi_t transitional_signature; // TODO: this should be a signature type
} user_profile_t;

user_profile_t *user_profile_new(const string_t versions);

otr4_err_t user_profile_sign(user_profile_t *profile,
                             const otrv4_keypair_t *keypair);

bool user_profile_valid_signature(const user_profile_t *profile);

void user_profile_copy(user_profile_t *dst, const user_profile_t *src);

void user_profile_destroy(user_profile_t *profile);

void user_profile_free(user_profile_t *profile);

otr4_err_t user_profile_deserialize(user_profile_t *target,
                                    const uint8_t *buffer, size_t buflen,
                                    size_t *nread);

otr4_err_t user_profile_body_asprintf(uint8_t **dst, size_t *nbytes,
                                      const user_profile_t *profile);

otr4_err_t user_profile_asprintf(uint8_t **dst, size_t *nbytes,
                                 const user_profile_t *profile);

user_profile_t *user_profile_build(const string_t versions,
                                   otrv4_keypair_t *keypair);

#endif
