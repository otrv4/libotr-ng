#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dake.h"
#include "str.h"
#include "serialize.h"
#include "deserialize.h"
#include "user_profile.h"

dake_pre_key_t *
dake_pre_key_new(const char *sender) {
  dake_pre_key_t *pre_key = malloc(sizeof(dake_pre_key_t));
  if (pre_key == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }

  pre_key->protocol_version = 4;
  pre_key->message_type = 0x0f;
  pre_key->sender_instance_tag = 1; // TODO: actually compute this value.
  pre_key->receiver_instance_tag = 0;
  pre_key->sender_profile = user_profile_get_or_create_for(sender);

  memset(pre_key->Y, 0, sizeof(ec_public_key_t));

  return pre_key;
}

void
dake_pre_key_free(dake_pre_key_t *pre_key) {
  user_profile_free(pre_key->sender_profile);
  pre_key->sender_profile = NULL;

  free(pre_key);
}

void
dake_pre_key_serialize(uint8_t *target, const dake_pre_key_t *pre_key) {
  target += serialize_uint16(target, pre_key->protocol_version);
  target += serialize_uint8(target, pre_key->message_type);
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

    if(!deserialize_uint16(&dst->protocol_version, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

    if(!deserialize_uint8(&dst->message_type, cursor, len, &read)) {
      return false;
    }

    cursor += read;
    len -= read;

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

    //dst->sender_profile = malloc(sizeof(user_profile_t));
    //if (dst->sender_profile == NULL) {
    //    return false;
    //}

    //if (!user_profile_deserialize(dst->sender_profile, cursor, len)) {
    //  return false;
    //}

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

int
dake_pre_key_validate(const dake_pre_key_t *pre_key) {
  return user_profile_signature_validate(pre_key->sender_profile->signature);
}

dake_pre_key_t *
dake_compute_pre_key() {
  return  dake_pre_key_new("handler@service.net");
}
