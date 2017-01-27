#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dake.h"
#include "str.h"
#include "serialize.h"
#include "deserialize.h"
#include "user_profile.h"

dake_pre_key_t *
dake_pre_key_new(const char *sender, const user_profile_t *profile) {
  if (profile == NULL) {
    return NULL;
  }

  dake_pre_key_t *pre_key = malloc(sizeof(dake_pre_key_t));
  if (pre_key == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }

  pre_key->sender_instance_tag = 0;
  pre_key->receiver_instance_tag = 0;
  user_profile_copy(pre_key->sender_profile, profile);

  return pre_key;
}

void
dake_pre_key_free(dake_pre_key_t *pre_key) {
  free(pre_key);
}

void
dake_pre_key_serialize(uint8_t *target, const dake_pre_key_t *pre_key) {
  target += serialize_uint16(target, OTR_VERSION);
  target += serialize_uint8(target, PRE_KEY_MSG_TYPE);
  target += serialize_uint32(target, pre_key->sender_instance_tag);
  target += serialize_uint32(target, pre_key->receiver_instance_tag);
  target += user_profile_serialize(target, pre_key->sender_profile);
  target += serialize_ec_public_key(target, pre_key->Y);
  target += serialize_dh_public_key(target, pre_key->B);
}

bool
dake_pre_key_deserialize(dake_pre_key_t *dst, const uint8_t *src, size_t src_len) {
    const uint8_t *cursor = src;
    int64_t len = src_len;
    size_t read = 0;
    
    uint16_t protocol_version = 0;
    if(!deserialize_uint16(&protocol_version, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    if (protocol_version != OTR_VERSION) {
      return false;
    }

    uint8_t message_type = 0;
    if(!deserialize_uint8(&message_type, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    if (message_type != PRE_KEY_MSG_TYPE) {
      return false;
    }

    if(!deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    if(!deserialize_uint32(&dst->receiver_instance_tag, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    if (!user_profile_deserialize(dst->sender_profile, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    //TODO deserialize_ec_public_key()
    ec_public_key_copy(dst->Y, cursor);
    cursor += sizeof(ec_public_key_t);
    len -= sizeof(ec_public_key_t);

    otr_mpi_t b_mpi; // no need to free, because nothing is copied now
    if (!otr_mpi_deserialize_no_copy(b_mpi, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    if (!dh_mpi_deserialize(&dst->B, b_mpi->data, b_mpi->len, &read)) {
      return false;
    }

    return true;
}

dake_dre_auth_t *
dake_dre_auth_new() {
    return NULL;
}

void
dake_dre_auth_free(dake_dre_auth_t *dre_auth) {
}

bool
dake_dre_auth_serialize(uint8_t *target, const dake_dre_auth_t *dre_auth) {
    return false;
}

void
dake_dre_auth_deserialize(dake_dre_auth_t *target, uint8_t *data) {
}

bool
dake_pre_key_validate(const dake_pre_key_t *pre_key) {
  return user_profile_verify_signature(pre_key->sender_profile);
}

dake_pre_key_t *
dake_compute_pre_key() {
  return NULL; //TODO
}
