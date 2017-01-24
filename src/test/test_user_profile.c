#include <glib.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "../user_profile.h"

void
test_user_profile_create() {
  const char *handler = "handler@service.net";
  
  user_profile_t *profile = user_profile_get_or_create_for(handler);

  g_assert_cmpstr(profile->versions, ==, "4");
  g_assert_cmpint(profile->expires, >=, time(NULL) + 2592000);
  char signature[112] = { 0 };
  g_assert_cmpint(memcmp(profile->signature, signature, 112), ==, 0);

  user_profile_free(profile);
}

void
test_user_profile_serializes() {
  user_profile_t *profile = user_profile_get_or_create_for("h@c.com");
  profile->expires = 15;
  profile->transitional_signature = malloc(40);
  memset(profile->transitional_signature, 0, 40);

  cs_keypair_t keypair;
  cs_generate_keypair(keypair);
  profile->pub_key = keypair->pub;
  
  uint8_t expected_pubkey[170] = { 0 };
  serialize_cs_public_key(expected_pubkey, keypair->pub);

  uint8_t serialized[500] = { 0 };

  int writen = user_profile_serialize(serialized, profile);

  char expected[] = {
    0x34, 0x0, // versions supported
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0F, // expires
    0x0, 0x0, 0x0, 0x70, // len
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // signature
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x28, // transitional signature
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
  };
  
  int expected_size = sizeof(expected_pubkey)+sizeof(expected);
  g_assert_cmpint(writen, ==, expected_size);

  g_assert_cmpint(memcmp(serialized, expected_pubkey, sizeof(expected_pubkey)), ==, 0);
  
  int comp = memcmp(serialized+sizeof(expected_pubkey), expected, sizeof(expected));
  g_assert_cmpint(comp, ==, 0);

  user_profile_free(profile);
}

void
test_user_profile_deserializes() {
  user_profile_t *profile = user_profile_get_or_create_for("h@c.com");
  uint8_t serialized[1000] = { 0 };

  cs_keypair_t keypair;
  cs_generate_keypair(keypair);
  profile->pub_key = keypair->pub; 
  
  user_profile_serialize(serialized, profile);
  
  user_profile_t *deserialized = malloc(sizeof(user_profile_t));
  deserialized->pub_key = malloc(sizeof(cs_public_key_t));
  g_assert_cmpint(user_profile_deserialize(deserialized, serialized, sizeof(serialized)), ==, 0);

  otrv4_assert_point_equals(deserialized->pub_key->c, profile->pub_key->c);
  otrv4_assert_point_equals(deserialized->pub_key->d, profile->pub_key->d);
  otrv4_assert_point_equals(deserialized->pub_key->h, profile->pub_key->h);

  otrv4_assert_cmpmem(deserialized->versions, profile->versions, strlen(profile->versions));

  g_assert_cmpuint(deserialized->expires, ==, profile->expires);

  otrv4_assert_cmpmem(deserialized->signature, profile->signature, EC_SIGNATURE_BYTES);

  user_profile_free(profile);
  user_profile_free(deserialized);
}
