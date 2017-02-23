#include <glib.h>
#include <string.h>

#include "../dake.h"
#include "../serialize.h"
#include "../cramershoup_interface.h"
#include "../str.h"

void
test_dake_protocol() {
  dh_init();

  cs_keypair_t alice_cramershoup, bob_cramershoup;
  ec_keypair_t alice_ecdh, bob_ecdh;
  dh_keypair_t alice_dh, bob_dh;

  // Alice
  cs_keypair_generate(alice_cramershoup);
  ec_keypair_generate(alice_ecdh);
  dh_keypair_generate(alice_dh);

  // Bob
  cs_keypair_generate(bob_cramershoup);
  ec_keypair_generate(bob_ecdh);
  dh_keypair_generate(bob_dh);

  // Alice send pre key
  user_profile_t *alice_profile = user_profile_new("4");
  alice_profile->expires = time(NULL) + 60 * 60;
  user_profile_sign(alice_profile, alice_cramershoup);
  dake_identity_message_t *identity_message = dake_identity_message_new(alice_profile);

  ec_public_key_copy(identity_message->Y, alice_ecdh->pub);
  identity_message->B = dh_mpi_copy(alice_dh->pub);

  //dake_identity_message_serialize()

  //TODO: continue
  // Bob receives pre key
  // dake_identity_message_deserialize()

  // Bob sends DRE-auth
  // Alice receives DRE-auth

  dake_identity_message_free(identity_message);
  dh_keypair_destroy(bob_dh);
  ec_keypair_destroy(bob_ecdh);
  user_profile_free(alice_profile);
  dh_keypair_destroy(alice_dh);
  ec_keypair_destroy(alice_ecdh);
  dh_free();
}

void
test_dake_dre_auth_new() {
  //dake_dre_auth_t *dre_auth = dake_dre_auth_new();
}

void
test_dake_generate_gamma_phi_sigma() {
  bool ok = false;

  dh_init();

  cs_keypair_t cs_alice, cs_bob;
  cs_keypair_generate(cs_alice);
  cs_keypair_generate(cs_bob);

  ec_keypair_t ecdh_alice, ecdh_bob;
  ec_keypair_generate(ecdh_alice);
  ec_keypair_generate(ecdh_bob);

  dh_keypair_t dh_alice, dh_bob;
  dh_keypair_generate(dh_alice);
  dh_keypair_generate(dh_bob);

  ec_public_key_t received_ecdh_alice;
  dh_public_key_t received_dh_alice = NULL;

  user_profile_t *profile_alice = user_profile_new("4");
  profile_alice->expires = time(NULL) + 60 * 60;
  otrv4_assert(user_profile_sign(profile_alice, cs_alice));

  user_profile_t *profile_bob = user_profile_new("4");
  profile_bob->expires = time(NULL) + 60 * 60;
  otrv4_assert(user_profile_sign(profile_bob, cs_bob));

  //Generate DRE-AUTH to be serialized
  dake_dre_auth_t *dre_auth = dake_dre_auth_new(profile_alice);
  otrv4_assert(dre_auth);

  //Alice generates gamma, sigma and phi
  ok = dake_dre_auth_generate_gamma_phi_sigma(cs_alice, ecdh_alice->pub, dh_alice->pub,
      profile_bob, ecdh_bob->pub, dh_bob->pub, dre_auth);
  otrv4_assert(ok);

  // Bob will validate Alice's profile, ephemeral keys from DRE-AUTH, gamma,
  // sigma and phi
  ok = dake_dre_auth_validate(received_ecdh_alice, &received_dh_alice,
      profile_bob, cs_bob, ecdh_bob->pub, dh_bob->pub, dre_auth);
  otrv4_assert(ok);

  otrv4_assert_ec_public_key_eq(received_ecdh_alice, ecdh_alice->pub);
  otrv4_assert_dh_public_key_eq(received_dh_alice, dh_alice->pub);

  dh_mpi_release(received_dh_alice);
  user_profile_free(profile_alice);
  user_profile_free(profile_bob);
  dake_dre_auth_free(dre_auth);
  dh_keypair_destroy(dh_alice);
  dh_keypair_destroy(dh_bob);
  dh_free();
}

void
test_dake_dre_auth_serialize() {
  uint8_t *cursor = NULL;
  bool ok = false;

  dh_init();

  cs_keypair_t our_cramershoup;
  cs_keypair_generate(our_cramershoup);

  ec_keypair_t our_ecdh;
  ec_keypair_generate(our_ecdh);

  dh_keypair_t our_dh;
  dh_keypair_generate(our_dh);

  user_profile_t *our_profile = user_profile_new("4");
  our_profile->expires = time(NULL) + 60 * 60;
  user_profile_sign(our_profile, our_cramershoup);

  //Generate DRE-AUTH to be serialized
  dake_dre_auth_t *dre_auth = dake_dre_auth_new(our_profile);
  user_profile_free(our_profile);
  dre_auth->sender_instance_tag = 1;
  dre_auth->receiver_instance_tag = 2;

  memset(dre_auth->nonce, 0xA, NONCE_BYTES);
  memset(dre_auth->gamma, 0xB, sizeof(dr_cs_encrypted_symmetric_key_t));
  memset(dre_auth->sigma, 0xC, sizeof(rs_auth_t));

  uint8_t expected_phi[] = {0, 0, 0, 5, 1, 2, 3, 4, 5};
  dre_auth->phi = malloc(5);
  dre_auth->phi_len = 5;
  memcpy(dre_auth->phi, expected_phi+4, 5);

  uint8_t *serialized = NULL;
  size_t serialized_len = 0;
  ok = dake_dre_auth_aprint(&serialized, &serialized_len, dre_auth);
  otrv4_assert(ok);

  size_t user_profile_len = 0;
  uint8_t *user_profile_serialized = NULL;
  ok = user_profile_aprint(&user_profile_serialized, &user_profile_len, dre_auth->profile);
  otrv4_assert(ok);

  size_t expected_len = DRE_AUTH_MIN_BYTES+user_profile_len+dre_auth->phi_len+4;
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
  otrv4_assert_cmpmem(expected_phi, cursor, dre_auth->phi_len);

  dake_dre_auth_free(dre_auth);
  dh_keypair_destroy(our_dh);
  free(serialized);
  dh_free();
}

void
test_dake_dre_auth_deserialize() {
  dh_init();

  cs_keypair_t our_cramershoup;
  cs_keypair_generate(our_cramershoup);

  user_profile_t *our_profile = user_profile_new("4");
  our_profile->expires = time(NULL) + 60 * 60;
  user_profile_sign(our_profile, our_cramershoup);
  dake_dre_auth_t *dre_auth = dake_dre_auth_new(our_profile);

  uint8_t *serialized = NULL;
  otrv4_assert(dake_dre_auth_aprint(&serialized, NULL, dre_auth));

  dake_dre_auth_t *des_dre = malloc(sizeof(dake_dre_auth_t));
  dake_dre_auth_deserialize(des_dre, serialized, 0);

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
  dh_free();
}
