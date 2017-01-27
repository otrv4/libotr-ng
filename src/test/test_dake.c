#include <glib.h>
#include <string.h>

#include "../dake.h"
#include "../serialize.h"
#include "../cramer_shoup.h"
#include "../str.h"

void
test_dake_protocol() {
  dh_init();

  cs_keypair_t alice_cramer_shoup, bob_cramer_shoup;
  ec_keypair_t alice_ecdh, bob_ecdh;
  dh_keypair_t alice_dh, bob_dh;

  // Alice
  cs_generate_keypair(alice_cramer_shoup);
  ec_gen_keypair(alice_ecdh);
  dh_gen_keypair(alice_dh);

  // Bob
  cs_generate_keypair(bob_cramer_shoup);
  ec_gen_keypair(bob_ecdh);
  dh_gen_keypair(bob_dh);

  // Alice send pre key
  user_profile_t *alice_profile = user_profile_new("4");
  user_profile_sign(alice_profile, alice_cramer_shoup);
  dake_pre_key_t *pre_key = dake_pre_key_new("", alice_profile);

  ec_public_key_copy(pre_key->Y, alice_ecdh->pub);
  pre_key->B = alice_dh->pub;

  //dake_pre_key_serialize()

  //TODO: continue
  // Bob receives pre key
  // dake_pre_key_deserialize()

  // Bob sends DRE-auth
  // Alice receives DRE-auth

  dh_keypair_destroy(bob_dh);
  ec_keypair_destroy(bob_ecdh);
  dh_keypair_destroy(alice_dh);
  ec_keypair_destroy(alice_ecdh);
  //cs_keypair_desctroy(alice_cramer_shoup);
  //cs_keypair_desctroy(bob_cramer_shoup);
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
