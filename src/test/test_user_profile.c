#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../serialize.h"
#include "../user_profile.h"

void test_user_profile_create() {
  user_profile_t *profile = user_profile_new("4");
  otrv4_assert(profile != NULL);
  user_profile_free(profile);
}

void test_user_profile_serializes_body() {
  otrv4_keypair_t keypair[1];
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrv4_keypair_generate(keypair, sym);

  user_profile_t *profile = user_profile_new("4");

  otrv4_shared_prekey_pair_t shared_prekey[1];
  otrv4_shared_prekey_pair_generate(shared_prekey, sym);
  memcpy(profile->shared_prekey, shared_prekey->pub,
         sizeof(otrv4_shared_prekey_pub_t));

  otrv4_assert(profile != NULL);
  profile->expires = 15;
  otrv4_assert(user_profile_sign(profile, keypair) == SUCCESS);

  const uint8_t transitional_signature[40] = {0};
  otr_mpi_set(profile->transitional_signature, transitional_signature,
              sizeof(transitional_signature));

  uint8_t expected_pubkey[ED448_PUBKEY_BYTES] = {0};
  serialize_otrv4_public_key(expected_pubkey, keypair->pub);

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrv4_assert(user_profile_body_asprintf(&serialized, &written, profile) ==
               SUCCESS);
  g_assert_cmpint(132, ==, written);

  otrv4_assert_cmpmem(expected_pubkey, serialized, ED448_PUBKEY_BYTES);

  char expected[] = {
      0x0,  0x0, 0x0, 0x2,                      // versions len
      0x34, 0x0,                                // versions data
      0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0F, // expires
  };

  otrv4_assert_cmpmem(expected, serialized + ED448_PUBKEY_BYTES,
                      sizeof(expected));

  uint8_t expected_shared_prekey[ED448_SHARED_PREKEY_BYTES] = {0};
  serialize_otrv4_shared_prekey(expected_shared_prekey, profile->shared_prekey);

  otrv4_assert_cmpmem(expected_shared_prekey,
                      serialized + ED448_PUBKEY_BYTES + 14,
                      ED448_SHARED_PREKEY_BYTES);

  free(serialized);
  serialized = NULL;
  user_profile_free(profile);
}

void test_user_profile_serializes() {
  otrv4_keypair_t keypair[1];
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrv4_keypair_generate(keypair, sym);

  user_profile_t *profile = user_profile_new("4");

  otrv4_shared_prekey_pair_t shared_prekey[1];
  otrv4_shared_prekey_pair_generate(shared_prekey, sym);
  memcpy(profile->shared_prekey, shared_prekey->pub,
         sizeof(otrv4_shared_prekey_pair_t));

  otrv4_assert(profile != NULL);
  profile->expires = 15;

  user_profile_sign(profile, keypair);
  const uint8_t transitional_signature[40] = {0};
  otr_mpi_set(profile->transitional_signature, transitional_signature,
              sizeof(transitional_signature));

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrv4_assert(user_profile_asprintf(&serialized, &written, profile) ==
               SUCCESS);
  g_assert_cmpint(written, ==, 290);

  // check "body"
  size_t body_len = 0;
  uint8_t *body = NULL;
  otrv4_assert(user_profile_body_asprintf(&body, &body_len, profile) ==
               SUCCESS);
  otrv4_assert_cmpmem(body, serialized, body_len);

  char expected_transitional_signature[] = {
      0x0, 0x0, 0x0, 0x28,                     // len
      0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, // transitional signature
      0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

  // transitional signature
  otrv4_assert_cmpmem(expected_transitional_signature,
                      serialized + body_len + sizeof(eddsa_signature_t),
                      sizeof(expected_transitional_signature));

  free(body);
  body = NULL;
  free(serialized);
  serialized = NULL;
  user_profile_free(profile);
}

void test_user_profile_deserializes() {
  otrv4_keypair_t keypair[1];
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrv4_keypair_generate(keypair, sym);

  user_profile_t *profile = user_profile_new("4");

  otrv4_shared_prekey_pair_t shared_prekey[1];
  otrv4_shared_prekey_pair_generate(shared_prekey, sym);
  memcpy(profile->shared_prekey, shared_prekey->pub,
         sizeof(otrv4_shared_prekey_pub_t));

  otrv4_assert(profile != NULL);
  user_profile_sign(profile, keypair);

  size_t written = 0;
  uint8_t *serialized = NULL;
  user_profile_asprintf(&serialized, &written, profile);

  user_profile_t *deserialized = malloc(sizeof(user_profile_t));
  otrv4_assert(user_profile_deserialize(deserialized, serialized, written,
                                        NULL) == SUCCESS);
  otrv4_assert_user_profile_eq(deserialized, profile);

  free(serialized);
  serialized = NULL;
  user_profile_free(profile);
  user_profile_free(deserialized);
}

void test_user_profile_signs_and_verify() {
  otrv4_keypair_t keypair[1];
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrv4_keypair_generate(keypair, sym);

  user_profile_t *profile = user_profile_new("4");

  otrv4_shared_prekey_pair_t shared_prekey[1];
  otrv4_shared_prekey_pair_generate(shared_prekey, sym);
  memcpy(profile->shared_prekey, shared_prekey->pub,
         sizeof(otrv4_shared_prekey_pair_t));

  otrv4_assert(profile != NULL);
  user_profile_sign(profile, keypair);

  otrv4_assert(user_profile_verify_signature(profile) == otrv4_true);

  memset(profile->signature, 0, sizeof(profile->signature));

  otrv4_assert(user_profile_verify_signature(profile) == otrv4_false);

  user_profile_free(profile);
}

void test_user_profile_build() {
  user_profile_t *profile = user_profile_build(NULL, NULL, NULL);
  otrv4_assert(!profile);

  otrv4_keypair_t keypair[1];
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrv4_keypair_generate(keypair, sym);

  otrv4_shared_prekey_pair_t shared_prekey[1];
  otrv4_shared_prekey_pair_generate(shared_prekey, sym);

  profile = user_profile_build("3", keypair, shared_prekey);
  g_assert_cmpstr(profile->versions, ==, "3");
  otrv4_assert(otrv4_ec_point_valid(profile->shared_prekey) == otrv4_true);

  user_profile_free(profile);
}
