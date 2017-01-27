#include "../dake.h"
#include "../str.h"

#define PREKEY_BEFORE_PROFILE_BYTES 2+1+4+4

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

  user_profile_t *profile = user_profile_new("4");
  otrv4_assert(profile != NULL);
  user_profile_sign(profile, cs); 

  dake_pre_key_t *pre_key = dake_pre_key_new("handler@service.net", profile);
  pre_key->sender_instance_tag = 1;
  ec_public_key_copy(pre_key->Y, ecdh->pub);
  pre_key->B = dh->pub;

  uint8_t serialized[1000] = { 0 };
  dake_pre_key_serialize(serialized, pre_key);

  char expected[] = {
    0x0, 0x04,              // version
    0x0f,                   //message type
    0x0, 0x0, 0x0, 0x1,     // sender instance tag
    0x0, 0x0, 0x0, 0x0,     // receiver instance tag
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

  user_profile_t *profile = user_profile_new("4");
  otrv4_assert(profile != NULL);
  user_profile_sign(profile, cs); 

  dake_pre_key_t *pre_key = dake_pre_key_new("handler@service.net", profile);
  ec_public_key_copy(pre_key->Y, ecdh->pub);
  pre_key->B = dh->pub;
  user_profile_free(profile);

  uint8_t serialized[10000] = { 0 };
  dake_pre_key_serialize(serialized, pre_key);

  dake_pre_key_t *deserialized = malloc(sizeof(dake_pre_key_t));
  memset(deserialized, 0, sizeof(dake_pre_key_t));
  otrv4_assert(dake_pre_key_deserialize(deserialized, serialized, sizeof(serialized)));

  //assert prekey eq
  g_assert_cmpuint(deserialized->sender_instance_tag, ==, pre_key->sender_instance_tag);
  g_assert_cmpuint(deserialized->receiver_instance_tag, ==, pre_key->receiver_instance_tag);
  otrv4_assert_user_profile_eq(deserialized->sender_profile, pre_key->sender_profile);
  otrv4_assert_ec_public_key_eq(deserialized->Y, pre_key->Y);
  otrv4_assert_dh_public_key_eq(deserialized->B, pre_key->B);

  dh_keypair_destroy(dh);
  ec_keypair_destroy(ecdh);
  dake_pre_key_free(pre_key);
  free(deserialized);
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

