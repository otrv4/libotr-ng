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
  dake_pre_key_t *pre_key = dake_pre_key_new(alice_profile);

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
  dh_init();

  cs_keypair_t sender_cramer_shoup, our_cramer_shoup;
  cs_generate_keypair(our_cramer_shoup);
  cs_generate_keypair(sender_cramer_shoup);

  ec_keypair_t our_ecdh;
  ec_gen_keypair(our_ecdh);
  dh_keypair_t our_dh;
  dh_gen_keypair(our_dh);
  
  user_profile_t *our_profile = user_profile_new("4");
  user_profile_sign(our_profile, our_cramer_shoup);

  user_profile_t *sender_profile = user_profile_new("4");
  user_profile_sign(sender_profile, sender_cramer_shoup);

  dake_dre_auth_t *dre_auth = dake_dre_auth_new(our_profile, sender_profile);
  ec_public_key_copy(dre_auth->X, our_ecdh->pub);
  dre_auth->A = dh_mpi_copy(our_dh->pub);
  printf("got a dre auth\n");

  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
  bool ok = dake_dre_auth_aprint(&serialized, &serialized_len, dre_auth);

  g_assert_cmpint(ok, ==, true);
  g_assert_cmpint(serialized_len, ==, DRE_AUTH_MIN_BYTES);

  uint8_t expected[] = {
    0x0, 0x04, // protocol version
    0x0, // message type
    0x0, 0x0, 0x0, 0x0, // sender instance tag
    0x0, 0x0, 0x0, 0x0, // receiver instance tag
    //user profile goes here    
  };

  uint8_t *cursor = serialized;
  otrv4_assert_cmpmem(serialized, expected, 11); //sizeof(expected));
  cursor += 11;

  size_t user_profile_len = 0;
  uint8_t *user_profile_serialized = NULL;
  otrv4_assert(user_profile_aprint(&user_profile_serialized, &user_profile_len, dre_auth->our_profile));
  otrv4_assert_cmpmem(user_profile_serialized, serialized+11, user_profile_len);
  free(user_profile_serialized);

  cursor += user_profile_len;

  ec_public_key_t serialized_x = { 0 };
  ec_public_key_serialize(serialized_x, sizeof(ec_public_key_t), dre_auth->X);
  otrv4_assert_cmpmem(cursor, serialized_x, sizeof(ec_public_key_t));
  cursor += sizeof(ec_public_key_t);

  uint8_t serialized_a[DH3072_MOD_LEN_BYTES] = { 0 };
  size_t mpi_len = dh_mpi_serialize(serialized_a, DH3072_MOD_LEN_BYTES, dre_auth->A);
  //Skip first 4 because they are the size (mpi_len)
  otrv4_assert_cmpmem(cursor + 4, serialized_a, mpi_len);

  cursor += mpi_len+4;

  //TODO: check gamma
  //dr_cs_decrypt(k);
  //xsalsa_decrypt(k, msg);
  
  dake_dre_auth_free(dre_auth);
  free(serialized);
}

void
test_dake_dre_auth_deserialize() {
  dake_dre_auth_t *dre_auth = dake_dre_auth_new();

  uint8_t *serialized = NULL;
  otrv4_assert(dake_dre_auth_aprint(&serialized, NULL, dre_auth));

  dake_dre_auth_t *des_dre = malloc(sizeof(dake_dre_auth_t));
  dake_dre_auth_deserialize(des_dre, serialized);

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
  free(serialized);
}
