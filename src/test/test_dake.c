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
test_dake_generate_gamma_phi_sigma() {
  bool ok = false;

  dh_init();

  cs_keypair_t their_cramer_shoup, our_cramer_shoup;
  cs_generate_keypair(our_cramer_shoup);
  cs_generate_keypair(their_cramer_shoup);

  ec_keypair_t our_ecdh, their_ecdh;
  ec_gen_keypair(our_ecdh);
  ec_gen_keypair(their_ecdh);

  dh_keypair_t our_dh, their_dh;
  dh_gen_keypair(our_dh);
  dh_gen_keypair(their_dh);
  
  user_profile_t *our_profile = user_profile_new("4");
  user_profile_sign(our_profile, our_cramer_shoup);

  user_profile_t *their_profile = user_profile_new("4");
  user_profile_sign(their_profile, their_cramer_shoup);

  //Generate DRE-AUTH to be serialized
  dake_dre_auth_t *dre_auth = dake_dre_auth_new(our_profile);
  ec_public_key_copy(dre_auth->X, our_ecdh->pub);
  dre_auth->A = dh_mpi_copy(our_dh->pub);

  //Generate gamma, sigma and phi
  ok = dake_dre_auth_generate_gamma_phi_sigma(our_cramer_shoup,
      their_cramer_shoup->pub, their_profile, their_ecdh->pub, their_dh->pub, dre_auth);
  otrv4_assert(ok);

  //1. validate sigma
  //2. check if gamma and phi can be decrypted
}

void
test_dake_dre_auth_serialize() {
  uint8_t *cursor = NULL;
  bool ok = false;

  dh_init();

  cs_keypair_t our_cramer_shoup;
  cs_generate_keypair(our_cramer_shoup);

  ec_keypair_t our_ecdh;
  ec_gen_keypair(our_ecdh);

  dh_keypair_t our_dh;
  dh_gen_keypair(our_dh);
  
  user_profile_t *our_profile = user_profile_new("4");
  user_profile_sign(our_profile, our_cramer_shoup);

  //Generate DRE-AUTH to be serialized
  dake_dre_auth_t *dre_auth = dake_dre_auth_new(our_profile);
  dre_auth->sender_instance_tag = 1;
  dre_auth->receiver_instance_tag = 2;
  ec_public_key_copy(dre_auth->X, our_ecdh->pub);
  dre_auth->A = dh_mpi_copy(our_dh->pub);

  memset(dre_auth->nonce, 0xA, NONCE_BYTES);
  memset(dre_auth->gamma, 0xB, sizeof(dr_cs_encrypted_symmetric_key_t));
  memset(dre_auth->sigma, 0xC, sizeof(rs_auth_t));

  uint8_t phi[] = {1, 2, 3, 4, 5};
  dre_auth->phi = phi;
  dre_auth->phi_len = 5;

  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
  ok = dake_dre_auth_aprint(&serialized, &serialized_len, dre_auth);
  otrv4_assert(ok);

  size_t user_profile_len = 0;
  uint8_t *user_profile_serialized = NULL;
  ok = user_profile_aprint(&user_profile_serialized, &user_profile_len, dre_auth->profile);
  otrv4_assert(ok);

  size_t expected_len = DRE_AUTH_MIN_BYTES+user_profile_len+dre_auth->phi_len;
  g_assert_cmpint(expected_len, ==, serialized_len);

  uint8_t expected_header[] = {
    0x0, 0x04,          // protocol version
    0x0,                // message type
    0x0, 0x0, 0x0, 0x01, // sender instance tag
    0x0, 0x0, 0x0, 0x02, // receiver instance tag
  };

  //assert header
  cursor = serialized;
  otrv4_assert_cmpmem(expected_header, cursor, sizeof(expected_header));
  cursor += sizeof(expected_header);

  //assert user profile
  otrv4_assert_cmpmem(user_profile_serialized, cursor, user_profile_len);
  free(user_profile_serialized);
  cursor += user_profile_len;

  //assert X
  ec_public_key_t expected_x = { 0 };
  ok = ec_public_key_serialize(expected_x, sizeof(ec_public_key_t), dre_auth->X);
  otrv4_assert(ok);
  otrv4_assert_cmpmem(expected_x, cursor, sizeof(ec_public_key_t));
  cursor += sizeof(ec_public_key_t);

  //assert A
  uint8_t expected_a[DH3072_MOD_LEN_BYTES] = { 0 };
  size_t mpi_len = dh_mpi_serialize(expected_a, DH3072_MOD_LEN_BYTES, dre_auth->A);
  //Skip first 4 because they are the size (mpi_len)
  otrv4_assert_cmpmem(expected_a, cursor+4, mpi_len);
  cursor += mpi_len+4;

  //assert gamma
  otrv4_assert_cmpmem(dre_auth->gamma, cursor, sizeof(dr_cs_encrypted_symmetric_key_t));
  cursor += sizeof(dr_cs_encrypted_symmetric_key_t);

  //assert sigma
  otrv4_assert_cmpmem(dre_auth->sigma, cursor, sizeof(rs_auth_t));
  cursor += sizeof(rs_auth_t);

  //assert nonce
  otrv4_assert_cmpmem(dre_auth->nonce, cursor, NONCE_BYTES);
  cursor += NONCE_BYTES;

  //assert phi
  otrv4_assert_cmpmem(phi, cursor, dre_auth->phi_len);

  dake_dre_auth_free(dre_auth);
  free(serialized);
}

void
test_dake_dre_auth_deserialize() {
  dh_init();

  cs_keypair_t our_cramer_shoup;
  cs_generate_keypair(our_cramer_shoup);

  user_profile_t *our_profile = user_profile_new("4");
  user_profile_sign(our_profile, our_cramer_shoup);
  dake_dre_auth_t *dre_auth = dake_dre_auth_new(our_profile);

  uint8_t *serialized = NULL;
  otrv4_assert(dake_dre_auth_aprint(&serialized, NULL, dre_auth));

  dake_dre_auth_t *des_dre = malloc(sizeof(dake_dre_auth_t));
  dake_dre_auth_deserialize(des_dre, serialized);

  g_assert_cmpuint(des_dre->sender_instance_tag, ==, dre_auth->sender_instance_tag);
  g_assert_cmpuint(des_dre->receiver_instance_tag, ==, dre_auth->receiver_instance_tag);
  // g_assert_cmpuint(des_dre->their_profile, ==, dre_auth->their_profile);
  // g_assert_cmpint(des_dre->X, ==, dre_auth->X);
  // g_assert_cmpint(des_dre->A, ==, dre_auth->A);
  // g_assert_cmpint(des_dre->gamma, ==, dre_auth->gamma);
  // g_assert_cmpint(des_dre->sigma, ==, dre_auth->sigma);

  dake_dre_auth_free(dre_auth);
  dake_dre_auth_free(des_dre);
  free(serialized);
}
