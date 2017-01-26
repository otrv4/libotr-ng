#include <glib.h>
#include <string.h>

#include "../dake.h"
#include "../serialize.h"
#include "../cramer_shoup.h"
#include "../str.h"

void
test_dake_pre_key_new() {
  dake_pre_key_t *pre_key = dake_pre_key_new("handler@service.net", NULL);
  dake_pre_key_free(pre_key);
  pre_key = NULL;
}

void
test_dake_pre_key_serializes() {
  dh_init();

  ec_keypair_t ecdh;
  dh_keypair_t dh;
  cs_keypair_t cs;

  ec_gen_keypair(ecdh);
  dh_gen_keypair(dh);
  cs_generate_keypair(cs);

  user_profile_t *profile = user_profile_new();
  cs_public_key_copy(profile->pub_key, cs->pub);
  profile->versions = otrv4_strdup("4");

  dake_pre_key_t *pre_key = dake_pre_key_new("handler@service.net", profile);
  pre_key->sender_instance_tag = 1;
  ec_public_key_copy(pre_key->Y, ecdh->pub);
  pre_key->B = dh->pub;

  uint8_t serialized[1000] = { 0 };

  dake_pre_key_serialize(serialized, pre_key);

  char expected[] = {
    0x0, 0x04, // version
    0x0f,      //message type
    0x0, 0x0, 0x0, 0x1, // sender instance tag
    0x0, 0x0, 0x0, 0x0, // receiver instance tag
  };

  uint8_t *cursor = serialized;
  otrv4_assert_cmpmem(cursor, expected, 11); //sizeof(expected));
  cursor += 11;

  uint8_t user_profile_serialized[340] = {0};
  int user_profile_len = user_profile_serialize(user_profile_serialized, pre_key->sender_profile);
  otrv4_assert_cmpmem(cursor, user_profile_serialized, user_profile_len);
  cursor += user_profile_len;

  uint8_t serialized_y[sizeof(ec_public_key_t)+2] = {0};
  ec_public_key_serialize(serialized_y, sizeof(ec_public_key_t), pre_key->Y);
  otrv4_assert_cmpmem(cursor, serialized_y, sizeof(ec_public_key_t));
  cursor += sizeof(ec_public_key_t);

  uint8_t serialized_b[DH3072_MOD_LEN_BYTES] = {0};
  size_t mpi_len = dh_mpi_serialize(serialized_b, DH3072_MOD_LEN_BYTES, pre_key->B);
  //Skip first 4 because they are the size (mpi_len)
  otrv4_assert_cmpmem(cursor+4, serialized_b, mpi_len);

  dh_keypair_destroy(dh);
  ec_keypair_destroy(ecdh);
  dake_pre_key_free(pre_key);
  user_profile_free(profile);
}

void
test_dake_pre_key_deserializes() {
  dh_init();

  ec_keypair_t ecdh;
  dh_keypair_t dh;
  cs_keypair_t cs;

  ec_gen_keypair(ecdh);
  dh_gen_keypair(dh);
  cs_generate_keypair(cs);

  user_profile_t *profile = user_profile_new();
  cs_public_key_copy(profile->pub_key, cs->pub);
  profile->versions = otrv4_strdup("4");

  dake_pre_key_t *pre_key = dake_pre_key_new("handler@service.net", profile);
  ec_public_key_copy(pre_key->Y, ecdh->pub);
  pre_key->B = dh->pub;

  uint8_t serialized[10000] = { 0 };
  dake_pre_key_serialize(serialized, pre_key);

  dake_pre_key_t *deserialized = malloc(sizeof(dake_pre_key_t));
  memset(deserialized, 0, sizeof(dake_pre_key_t));
  otrv4_assert(dake_pre_key_deserialize(deserialized, serialized, sizeof(serialized)));

  g_assert_cmpuint(deserialized->sender_instance_tag, ==, pre_key->sender_instance_tag);
  g_assert_cmpuint(deserialized->receiver_instance_tag, ==, pre_key->receiver_instance_tag);

  //TODO: USER PROFILE
  //TODO: Y
  //TODO: B

  dh_keypair_destroy(dh);
  ec_keypair_destroy(ecdh);
  dake_pre_key_free(pre_key);
  dake_pre_key_free(deserialized);
  user_profile_free(profile);
}

void
test_dake_protocol() {
  dh_init();

  //alice_cramer_shoup, bob_cramer_shoup;
  ec_keypair_t alice_ecdh, bob_ecdh;
  dh_keypair_t alice_dh, bob_dh;

  // Alice
  ec_gen_keypair(alice_ecdh);
  dh_gen_keypair(alice_dh);

  // Bob
  ec_gen_keypair(bob_ecdh);
  dh_gen_keypair(bob_dh);

  // Alice send pre key
  dake_pre_key_t *pre_key = dake_pre_key_new("", NULL);
  ec_public_key_copy(pre_key->Y, alice_ecdh->pub);
  pre_key->B = alice_dh->pub;

  //TODO: continue
  // Bob receives pre key
  // Bob sends DRE-auth
  // Alice receives DRE-auth

  dh_keypair_destroy(bob_dh);
  ec_keypair_destroy(bob_ecdh);
  dh_keypair_destroy(alice_dh);
  ec_keypair_destroy(alice_ecdh);
}

void
test_dake_pre_key_valid() {
  dake_pre_key_t *pre_key = dake_pre_key_new("handler@service.net", NULL);

  int valid = dake_pre_key_validate(pre_key);

  g_assert_cmpint(valid, ==, 0);

  dake_pre_key_free(pre_key);
}

void
test_dake_pre_key_Y_doesnt_belong_to_curve() {
  dake_pre_key_t *pre_key = dake_pre_key_new("handler@service.net", NULL);

  int valid = dake_pre_key_validate(pre_key);

  g_assert_cmpint(valid, ==, 0);

  dake_pre_key_free(pre_key);
}

void
test_dake_dre_auth_new() {
  //dake_dre_auth_t *dre_auth = dake_dre_auth_new();
}

void
test_dake_dre_auth_serialize() {
  dake_dre_auth_t *dre_auth = dake_dre_auth_new();
  uint8_t serialized[1000] = { 0 };

  dake_dre_auth_serialize(serialized, dre_auth);

  uint8_t expected[] = {
    0x0, 0x04, // protocol version
    0x0, // message type
    0x0, 0x0, 0x0, 0x0, // sender instance tag
    0x0, 0x0, 0x0, 0x0, // receiver instance tag
    //user profile goes here
    
  };

  otrv4_assert_cmpmem(serialized, expected, 11); //sizeof(expected));
  
  dake_dre_auth_free(dre_auth);
}

void
test_dake_dre_auth_deserialize() {
  dake_dre_auth_t *dre_auth = dake_dre_auth_new();
  uint8_t ser_dre[1000];
  dake_dre_auth_serialize(ser_dre, dre_auth);

  dake_dre_auth_t *des_dre = malloc(sizeof(dake_dre_auth_t));
  dake_dre_auth_deserialize(des_dre, ser_dre);

  g_assert_cmpuint(des_dre->version_protocol, ==, dre_auth->version_protocol);
  g_assert_cmpuint(des_dre->type, ==, dre_auth->type);
  g_assert_cmpuint(des_dre->sender_instance_tag, ==, dre_auth->sender_instance_tag);
  g_assert_cmpuint(des_dre->receiver_instance_tag, ==, dre_auth->receiver_instance_tag);
  // g_assert_cmpuint(des_dre->sender_profile, ==, dre_auth->sender_profile);
  // g_assert_cmpint(des_dre->X, ==, dre_auth->X);
  // g_assert_cmpint(des_dre->A, ==, dre_auth->A);
  // g_assert_cmpint(des_dre->gamma, ==, dre_auth->gamma);
  // g_assert_cmpint(des_dre->sigma, ==, dre_auth->sigma);

  dake_dre_auth_free(dre_auth);
  dake_dre_auth_free(des_dre);
}
