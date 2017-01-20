#include <glib.h>
#include <string.h>

#include "../dake.h"
#include "../serialize.h"

void
test_dake_pre_key_new() {
  dake_pre_key_t *pre_key = dake_pre_key_new("handler@service.net");

  g_assert_cmpint(pre_key->protocol_version, ==, 4);
  g_assert_cmpint(pre_key->message_type, ==, 15);
  g_assert_cmpint(pre_key->sender_instance_tag, >, 0);
  g_assert_cmpint(pre_key->receiver_instance_tag, ==, 0);
  // TODO: How to assert a pointer was set without using nonnull?
  // Comparing to 0 fires a warning on making a int from a pointer
  // even when NULL is a representation of 0
  // g_assert_cmpint(pre_key->Y, >, 0);
  // g_assert_cmpint(pre_key->B, >, 0);

  dake_pre_key_free(pre_key);
}

void
test_dake_pre_key_serializes() {
  dh_init();

  ec_keypair_t ecdh;
  dh_keypair_t dh;

  ec_gen_keypair(ecdh);
  dh_gen_keypair(dh);

  dake_pre_key_t *pre_key = dake_pre_key_new("handler@service.net");
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
  int comp = memcmp(cursor, expected, 11); //sizeof(expected));
  g_assert_cmpint(comp, ==, 0);
  cursor += 11;

  uint8_t user_profile_serialized[340] = {0};
  int user_profile_len = user_profile_serialize(user_profile_serialized, pre_key->sender_profile);
  g_assert_cmpint(memcmp(cursor, user_profile_serialized, user_profile_len), ==, 0);
  cursor += user_profile_len;

  uint8_t serialized_y[sizeof(ec_public_key_t)] = {0};
  ec_public_key_serialize(serialized_y, sizeof(ec_public_key_t), pre_key->Y);
  g_assert_cmpint(memcmp(cursor, serialized_y, sizeof(ec_public_key_t)), ==, 0);
  cursor += sizeof(ec_public_key_t);

  uint8_t serialized_b[DH3072_MOD_LEN_BYTES] = {0};
  size_t mpi_len = dh_mpi_serialize(serialized_b, DH3072_MOD_LEN_BYTES, pre_key->B);
  //Skip first 4 because they are the size (mpi_len)
  g_assert_cmpint(memcmp(cursor+4, serialized_b, mpi_len), ==, 0);

  dh_keypair_destroy(dh);
  ec_keypair_destroy(ecdh);
  dake_pre_key_free(pre_key);
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
  dake_pre_key_t *pre_key = dake_pre_key_new("");
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
