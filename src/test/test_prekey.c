#include "../dake.h"
#include "../str.h"

#define PREKEY_BEFORE_PROFILE_BYTES 2+1+4+4

void
test_dake_pre_key_new(pre_key_fixture_t *f, gconstpointer data) {
  dake_pre_key_t *pre_key = dake_pre_key_new(f->profile);
  dake_pre_key_free(pre_key);
  pre_key = NULL;
}

void
test_dake_pre_key_serializes(pre_key_fixture_t *f, gconstpointer data) {
  dh_init();

  ec_keypair_t ecdh;
  dh_keypair_t dh;
  cs_keypair_t cs;

  ec_keypair_generate(ecdh);
  dh_keypair_generate(dh);
  cs_keypair_generate(cs);

  dake_pre_key_t *pre_key = dake_pre_key_new(f->profile);
  pre_key->sender_instance_tag = 1;
  ec_public_key_copy(pre_key->Y, ecdh->pub);
  pre_key->B = dh_mpi_copy(dh->pub);

  uint8_t *serialized = NULL;
  otrv4_assert(dake_pre_key_aprint(&serialized, NULL, pre_key));

  char expected[] = {
    0x0, 0x04,              // version
    0x0f,                   //message type
    0x0, 0x0, 0x0, 0x1,     // sender instance tag
    0x0, 0x0, 0x0, 0x0,     // receiver instance tag
  };

  uint8_t *cursor = serialized;
  otrv4_assert_cmpmem(cursor, expected, 11); //sizeof(expected));
  cursor += 11;

  size_t user_profile_len = 0;
  uint8_t *user_profile_serialized = NULL;
  otrv4_assert(user_profile_aprint(&user_profile_serialized, &user_profile_len, pre_key->profile));
  otrv4_assert_cmpmem(cursor, user_profile_serialized, user_profile_len);
  free(user_profile_serialized);
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
  free(serialized);
}

void
test_dake_pre_key_deserializes(pre_key_fixture_t *f, gconstpointer data) {
  dh_init();

  ec_keypair_t ecdh;
  dh_keypair_t dh;

  ec_keypair_generate(ecdh);
  dh_keypair_generate(dh);

  dake_pre_key_t *pre_key = dake_pre_key_new(f->profile);
  ec_public_key_copy(pre_key->Y, ecdh->pub);
  pre_key->B = dh_mpi_copy(dh->pub);

  size_t serialized_len = 0;
  uint8_t *serialized = NULL;
  otrv4_assert(dake_pre_key_aprint(&serialized, &serialized_len, pre_key));

  dake_pre_key_t *deserialized = malloc(sizeof(dake_pre_key_t));
  memset(deserialized, 0, sizeof(dake_pre_key_t));
  otrv4_assert(dake_pre_key_deserialize(deserialized, serialized, serialized_len));

  //assert prekey eq
  g_assert_cmpuint(deserialized->sender_instance_tag, ==, pre_key->sender_instance_tag);
  g_assert_cmpuint(deserialized->receiver_instance_tag, ==, pre_key->receiver_instance_tag);
  otrv4_assert_user_profile_eq(deserialized->profile, pre_key->profile);
  otrv4_assert_ec_public_key_eq(deserialized->Y, pre_key->Y);
  otrv4_assert_dh_public_key_eq(deserialized->B, pre_key->B);

  dh_keypair_destroy(dh);
  ec_keypair_destroy(ecdh);
  dake_pre_key_free(pre_key);
  dake_pre_key_free(deserialized);
  free(serialized);
}

void
test_dake_pre_key_valid(pre_key_fixture_t *f, gconstpointer data) {
  dh_init();

  ec_keypair_t ecdh;
  dh_keypair_t dh;
  ec_keypair_generate(ecdh);
  dh_keypair_generate(dh);

  dake_pre_key_t *pre_key = dake_pre_key_new(f->profile);
  otrv4_assert(pre_key != NULL);

  ec_public_key_copy(pre_key->Y, ecdh->pub);
  pre_key->B = dh_mpi_copy(dh->pub);

  otrv4_assert(dake_pre_key_validate(pre_key));

  ec_keypair_destroy(ecdh);
  dh_keypair_destroy(dh);
  dake_pre_key_free(pre_key);
  dh_keypair_destroy(dh);
}

void
test_dake_pre_key_Y_doesnt_belong_to_curve(pre_key_fixture_t *f, gconstpointer data) {
  dake_pre_key_t *pre_key = dake_pre_key_new(f->profile);
  otrv4_assert(pre_key != NULL);

  otrv4_assert(dake_pre_key_validate(pre_key)); //TODO: boolean?
  dake_pre_key_free(pre_key);
}

