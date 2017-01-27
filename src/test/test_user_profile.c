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
  cs_generate_keypair(keypair);

  user_profile_t *profile = user_profile_new("4");
  otrv4_assert(profile != NULL);
  user_profile_free(profile);
}

void
test_user_profile_serializes() {
  cs_keypair_t keypair;
  cs_generate_keypair(keypair);

  user_profile_t *profile = user_profile_new("4");
  otrv4_assert(profile != NULL);
  profile->expires = 15;

  user_profile_sign(profile, keypair); 
  const uint8_t transitional_signature[40] = { 0 };
  otr_mpi_set(profile->transitional_signature, transitional_signature, sizeof(transitional_signature));
  
  uint8_t expected_pubkey[170] = { 0 };
  serialize_cs_public_key(expected_pubkey, keypair->pub);

  uint8_t serialized[500] = { 0 };
  int writen = user_profile_serialize(serialized, profile);

  char expected[] = {
    0x34, 0x0,                                      // versions supported
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0F,        // expires
    0x0, 0x0, 0x0, 0x70,                            // len
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // signature
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0, 0x0, 0x0, 0x28,                            // len
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,         // transitional signature
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
  };

  int expected_size = sizeof(expected_pubkey)+sizeof(expected);
  g_assert_cmpint(writen, ==, expected_size);

  // pubkey
  otrv4_assert_cmpmem(expected_pubkey, serialized, sizeof(expected_pubkey));
  otrv4_assert_cmpmem(expected, serialized+sizeof(expected_pubkey), 14);
  //skip signature (112 bytes)
  //transitional signature
  otrv4_assert_cmpmem(expected+14+112, serialized+sizeof(expected_pubkey)+14+112, sizeof(expected)-112-14);

  user_profile_free(profile);
}

void
test_user_profile_deserializes() {
  cs_keypair_t keypair;
  cs_generate_keypair(keypair);

  user_profile_t *profile = user_profile_new("4");
  otrv4_assert(profile != NULL);
  user_profile_sign(profile, keypair); 

  uint8_t serialized[1000] = { 0 };
  user_profile_serialize(serialized, profile);

  user_profile_t *deserialized = malloc(sizeof(user_profile_t));

  otrv4_assert(user_profile_deserialize(deserialized, serialized, sizeof(serialized), NULL));
  otrv4_assert_user_profile_eq(deserialized, profile);

  user_profile_free(profile);
  user_profile_free(deserialized);
}

void
test_user_profile_signs_and_verify() {
  cs_keypair_t keypair;
  cs_generate_keypair(keypair);

  user_profile_t *profile = user_profile_new("4");
  otrv4_assert(profile != NULL);
  user_profile_sign(profile, keypair);

  otrv4_assert(user_profile_verify_signature(profile));

  user_profile_free(profile);
}
