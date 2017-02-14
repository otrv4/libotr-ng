#include <glib.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "../str.h"
#include "../user_profile.h"
#include "../serialize.h"

void
test_user_profile_create() {
  cs_keypair_t keypair;
  cs_keypair_generate(keypair);

  user_profile_t *profile = user_profile_new("4");
  otrv4_assert(profile != NULL);
  user_profile_free(profile);
}

void
test_user_profile_serializes_body() {
  cs_keypair_t keypair;
  cs_keypair_generate(keypair);

  user_profile_t *profile = user_profile_new("4");
  otrv4_assert(profile != NULL);
  profile->expires = 15;
  otrv4_assert(user_profile_sign(profile, keypair)); 

  const uint8_t transitional_signature[40] = { 0 };
  otr_mpi_set(profile->transitional_signature, transitional_signature, sizeof(transitional_signature));
  
  uint8_t expected_pubkey[170] = { 0 };
  serialize_cs_public_key(expected_pubkey, keypair->pub);

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrv4_assert(user_profile_body_aprint(&serialized, &written, profile));
  g_assert_cmpint(184, ==, written);

  otrv4_assert_cmpmem(expected_pubkey, serialized, 170);

  char expected[] = {
    0x0, 0x0, 0x0, 0x2,                             // versions len
    0x34, 0x0,                                      // versions data
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0F,        // expires
  };

  otrv4_assert_cmpmem(expected, serialized+170, sizeof(expected));

  user_profile_free(profile);
  free(serialized);
}

void
test_user_profile_serializes() {
  cs_keypair_t keypair;
  cs_keypair_generate(keypair);

  user_profile_t *profile = user_profile_new("4");
  otrv4_assert(profile != NULL);
  profile->expires = 15;

  user_profile_sign(profile, keypair); 
  const uint8_t transitional_signature[40] = { 0 };
  otr_mpi_set(profile->transitional_signature, transitional_signature, sizeof(transitional_signature));

  uint8_t expected_pubkey[170] = { 0 };
  serialize_cs_public_key(expected_pubkey, keypair->pub);

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrv4_assert(user_profile_aprint(&serialized, &written, profile));
  //g_assert_cmpint(340, ==, written);

  //check "body"
  size_t body_len = 0;
  uint8_t *body = NULL;
  otrv4_assert(user_profile_body_aprint(&body, &body_len, profile));
  otrv4_assert_cmpmem(body, serialized, body_len);

  char expected_transitional_signature[] = {
    0x0, 0x0, 0x0, 0x28,                            // len
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,         // transitional signature
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
  };

  //transitional signature
  otrv4_assert_cmpmem(expected_transitional_signature, serialized+body_len+4+112,
      sizeof(expected_transitional_signature));

  user_profile_free(profile);
  free(body);
  free(serialized);
}

void
test_user_profile_deserializes() {
  cs_keypair_t keypair;
  cs_keypair_generate(keypair);

  user_profile_t *profile = user_profile_new("4");
  otrv4_assert(profile != NULL);
  user_profile_sign(profile, keypair); 

  size_t written = 0;
  uint8_t *serialized = NULL;
  user_profile_aprint(&serialized, &written, profile);

  user_profile_t *deserialized = malloc(sizeof(user_profile_t));
  otrv4_assert(user_profile_deserialize(deserialized, serialized, written, NULL));
  otrv4_assert_user_profile_eq(deserialized, profile);

  user_profile_free(profile);
  user_profile_free(deserialized);
  free(serialized);
}

void
test_user_profile_signs_and_verify() {
  cs_keypair_t keypair;
  cs_keypair_generate(keypair);

  user_profile_t *profile = user_profile_new("4");
  otrv4_assert(profile != NULL);
  user_profile_sign(profile, keypair);

  otrv4_assert(user_profile_verify_signature(profile));

  user_profile_free(profile);
}
