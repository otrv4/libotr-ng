#include "../constants.h"
#include "../dake.h"
#include "../str.h"

#define PREKEY_BEFORE_PROFILE_BYTES 2 + 1 + 4 + 4

void test_dake_prekey_message_serializes(prekey_message_fixture_t *f,
                                           gconstpointer data) {
  OTR4_INIT;

  ecdh_keypair_t ecdh[1];
  dh_keypair_t dh;

  uint8_t sym[ED448_PRIVATE_BYTES] = {0};
  ecdh_keypair_generate(ecdh, sym);
  otrv4_assert(dh_keypair_generate(dh) == OTR4_SUCCESS);

  dake_prekey_message_t *prekey_message =
      dake_prekey_message_new(f->profile);
  prekey_message->sender_instance_tag = 1;
  ec_point_copy(prekey_message->Y, ecdh->pub);
  prekey_message->B = dh_mpi_copy(dh->pub);

  uint8_t *serialized = NULL;
  otrv4_assert(dake_prekey_message_asprintf(
                   &serialized, NULL, prekey_message) == OTR4_SUCCESS);

  char expected[] = {
      0x0,
      0x04,                  // version
      OTR_PRE_KEY_MSG_TYPE, // message type
      0x0,
      0x0,
      0x0,
      0x1, // sender instance tag
      0x0,
      0x0,
      0x0,
      0x0, // receiver instance tag
  };

  uint8_t *cursor = serialized;
  otrv4_assert_cmpmem(cursor, expected, 11); // sizeof(expected));
  cursor += 11;

  size_t user_profile_len = 0;
  uint8_t *user_profile_serialized = NULL;
  otrv4_assert(
      user_profile_asprintf(&user_profile_serialized, &user_profile_len,
                            prekey_message->profile) == OTR4_SUCCESS);
  otrv4_assert_cmpmem(cursor, user_profile_serialized, user_profile_len);
  free(user_profile_serialized);
  cursor += user_profile_len;

  uint8_t serialized_y[ED448_POINT_BYTES + 2] = {0};
  ec_point_serialize(serialized_y, prekey_message->Y);
  otrv4_assert_cmpmem(cursor, serialized_y, sizeof(ec_public_key_t));
  cursor += sizeof(ec_public_key_t);

  uint8_t serialized_b[DH3072_MOD_LEN_BYTES] = {0};
  size_t mpi_len = 0;
  otr4_err_t err = dh_mpi_serialize(serialized_b, DH3072_MOD_LEN_BYTES,
                                    &mpi_len, prekey_message->B);
  otrv4_assert(!err);
  // Skip first 4 because they are the size (mpi_len)
  otrv4_assert_cmpmem(cursor + 4, serialized_b, mpi_len);

  dh_keypair_destroy(dh);
  ecdh_keypair_destroy(ecdh);
  dake_prekey_message_free(prekey_message);
  free(serialized);
  dh_free();
}
