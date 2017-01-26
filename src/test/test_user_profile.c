#include <glib.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "../user_profile.h"

void
test_user_profile_create() {
  user_profile_t *profile = user_profile_new();
  user_profile_free(profile);
}

void
test_user_profile_serializes() {
  cs_keypair_t keypair;
  cs_generate_keypair(keypair);

  user_profile_t *profile = user_profile_new();
  profile->versions = otrv4_strdup("4");
  profile->expires = 15;
  memset(profile->signature, 1, sizeof(ec_signature_t));
  profile->transitional_signature = malloc(40);
  otrv4_assert(profile->transitional_signature != NULL);
  memset(profile->transitional_signature, 0, 40);
  cs_public_key_copy(profile->pub_key, keypair->pub);
  
  uint8_t expected_pubkey[170] = { 0 };
  serialize_cs_public_key(expected_pubkey, keypair->pub);

  uint8_t serialized[500] = { 0 };

  int writen = user_profile_serialize(serialized, profile);

  char expected[] = {
    0x34, 0x0, // versions supported
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0F, // expires
    0x0, 0x0, 0x0, 0x70, // len
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // signature
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x0, 0x0, 0x0, 0x28, // transitional signature
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
  };

  int expected_size = sizeof(expected_pubkey)+sizeof(expected);
  g_assert_cmpint(writen, ==, expected_size);

  // pubkey
  otrv4_assert_cmpmem(expected_pubkey, serialized, sizeof(expected_pubkey));
  otrv4_assert_cmpmem(expected, serialized+sizeof(expected_pubkey), sizeof(expected));

  user_profile_free(profile);
}

void
test_user_profile_deserializes() {
  cs_keypair_t keypair;
  cs_generate_keypair(keypair);

  user_profile_t *profile = user_profile_new();
  profile->versions = otrv4_strdup("4");
  cs_public_key_copy(profile->pub_key, keypair->pub);
  
  uint8_t serialized[1000] = { 0 };
  user_profile_serialize(serialized, profile);
  
  user_profile_t *deserialized = malloc(sizeof(user_profile_t));

  otrv4_assert(user_profile_deserialize(deserialized, serialized, sizeof(serialized)) == true);

  otrv4_assert_point_equals(deserialized->pub_key->c, profile->pub_key->c);
  otrv4_assert_point_equals(deserialized->pub_key->d, profile->pub_key->d);
  otrv4_assert_point_equals(deserialized->pub_key->h, profile->pub_key->h);

  otrv4_assert_cmpmem(deserialized->versions, profile->versions, strlen(profile->versions));

  g_assert_cmpuint(deserialized->expires, ==, profile->expires);

  otrv4_assert_cmpmem(deserialized->signature, profile->signature, EC_SIGNATURE_BYTES);

  user_profile_free(profile);
  user_profile_free(deserialized);
}
