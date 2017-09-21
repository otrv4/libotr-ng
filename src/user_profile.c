#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "deserialize.h"
#include "mpi.h"
#include "random.h"
#include "serialize.h"
#include "str.h"
#include "user_profile.h"

user_profile_t *user_profile_new(const string_t versions) {
  if (!versions)
    return NULL;

  user_profile_t *profile = malloc(sizeof(user_profile_t));
  if (!profile)
    return NULL;

  // the compiler might optimize this
  memset_s(profile->pub_key, sizeof(profile->pub_key), 0, sizeof(profile->pub_key));
  profile->expires = 0;
  profile->versions = otrv4_strdup(versions);
  memset(profile->signature, 0, sizeof(eddsa_signature_t));
  otr_mpi_init(profile->transitional_signature);

  return profile;
}

void user_profile_copy(user_profile_t *dst, const user_profile_t *src) {
  // TODO should we set dst to a valid (but empty) profile?
  if (!src)
    return;

  ec_point_copy(dst->pub_key, src->pub_key);
  dst->versions = otrv4_strdup(src->versions);
  dst->expires = src->expires;

  memcpy(dst->signature, src->signature, sizeof(eddsa_signature_t));
  otr_mpi_copy(dst->transitional_signature, src->transitional_signature);
}

void user_profile_destroy(user_profile_t *profile) {
  if (!profile)
    return;

  ec_point_destroy(profile->pub_key);
  free(profile->versions);
  profile->versions = NULL;
  sodium_memzero(profile->signature, ED448_SIGNATURE_BYTES);

  otr_mpi_free(profile->transitional_signature);
}

void user_profile_free(user_profile_t *profile) {
  user_profile_destroy(profile);
  free(profile);
}

static int user_profile_body_serialize(uint8_t *dst,
                                       const user_profile_t *profile) {
  uint8_t *target = dst;

  target += serialize_otrv4_public_key(target, profile->pub_key);
  target += serialize_data(target, (uint8_t *)profile->versions,
                           strlen(profile->versions) + 1);
  target += serialize_uint64(target, profile->expires);

  return target - dst;
}

otr4_err_t user_profile_body_asprintf(uint8_t **dst, size_t *nbytes,
                                      const user_profile_t *profile) {
  size_t s = ED448_PUBKEY_BYTES + strlen(profile->versions) + 1 + 4 + 8;

  uint8_t *buff = malloc(s);
  if (!buff)
    return OTR4_ERROR;

  user_profile_body_serialize(buff, profile);

  *dst = buff;
  if (nbytes)
    *nbytes = s;

  return OTR4_SUCCESS;
}

otr4_err_t user_profile_asprintf(uint8_t **dst, size_t *nbytes,
                                 const user_profile_t *profile) {
  // TODO: should it check if the profile is signed?
  uint8_t *buff = NULL;
  size_t body_len = 0;
  uint8_t *body = NULL;
  if (user_profile_body_asprintf(&body, &body_len, profile))
    return OTR4_ERROR;

  size_t s = body_len + 4 + sizeof(eddsa_signature_t) +
             profile->transitional_signature->len;
  buff = malloc(s);
  if (!buff) {
    free(body);
    return OTR4_ERROR;
  }

  uint8_t *cursor = buff;
  cursor += serialize_bytes_array(cursor, body, body_len);
  cursor += serialize_bytes_array(cursor, profile->signature,
                                  sizeof(eddsa_signature_t));
  cursor += serialize_mpi(cursor, profile->transitional_signature);

  *dst = buff;
  if (nbytes)
    *nbytes = s;

  free(body);
  return OTR4_SUCCESS;
}

otr4_err_t user_profile_deserialize(user_profile_t *target,
                                    const uint8_t *buffer, size_t buflen,
                                    size_t *nread) {
  size_t read = 0;
  int walked = 0;

  if (!target)
    return OTR4_ERROR;

  otr4_err_t ok = OTR4_ERROR;
  do {
    if (deserialize_otrv4_public_key(target->pub_key, buffer, buflen, &read))
      continue;

    walked += read;

    if (deserialize_data((uint8_t **)&target->versions, buffer + walked,
                         buflen - walked, &read))
      continue;

    walked += read;

    if (deserialize_uint64(&target->expires, buffer + walked, buflen - walked,
                           &read))
      continue;

    walked += read;

    // TODO: check the len
    if (buflen - walked < sizeof(eddsa_signature_t))
      continue;

    memcpy(target->signature, buffer + walked, sizeof(eddsa_signature_t));

    walked += sizeof(eddsa_signature_t);

    if (otr_mpi_deserialize(target->transitional_signature, buffer + walked,
                            buflen - walked, &read))
      continue;

    walked += read;

    ok = OTR4_SUCCESS;
  } while (0);

  if (nread)
    *nread = walked;

  return ok;
}

otr4_err_t user_profile_sign(user_profile_t *profile,
                             const otrv4_keypair_t *keypair) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  ec_point_copy(profile->pub_key, keypair->pub);
  if (user_profile_body_asprintf(&body, &bodylen, profile))
    return OTR4_ERROR;

  uint8_t pubkey[ED448_POINT_BYTES];
  if (ec_point_serialize(pubkey, ED448_POINT_BYTES, keypair->pub)) {
    return OTR4_ERROR;
  }
  // maybe ec_derive_public_key again?

  ec_sign(profile->signature, (uint8_t *)keypair->sym, pubkey, body, bodylen);

  free(body);
  body = NULL;
  return OTR4_SUCCESS;
}

// TODO: I dont think this needs the data structure. Could verify from the
// deserialized bytes.
bool user_profile_valid_signature(const user_profile_t *profile) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  if (!profile->signature[0])
    return false;

  if (user_profile_body_asprintf(&body, &bodylen, profile))
    return false;

  uint8_t pubkey[ED448_POINT_BYTES];
  if (ec_point_serialize(pubkey, ED448_POINT_BYTES, profile->pub_key)) {
    free(body);
    body = NULL;
    return false;
  }

  bool valid = ec_verify(profile->signature, pubkey, body, bodylen);

  free(body);
  body = NULL;

  return valid;
}

user_profile_t *user_profile_build(const string_t versions,
                                   otrv4_keypair_t *keypair) {
  user_profile_t *profile = user_profile_new(versions);
  if (!profile)
    return NULL;

#define PROFILE_EXPIRATION_SECONDS 2 * 7 * 24 * 60 * 60; /* 2 weeks */
  time_t expires = time(NULL);
  profile->expires = expires + PROFILE_EXPIRATION_SECONDS;

  if (user_profile_sign(profile, keypair)) {
    user_profile_free(profile);
    return NULL;
  }

  return profile;
}
