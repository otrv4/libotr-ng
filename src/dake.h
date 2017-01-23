#include "dh.h"
#include "ed448.h"
#include "user_profile.h"

#ifndef DAKE_H
#define DAKE_H

typedef struct {
  uint16_t protocol_version;
  uint8_t message_type;
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  user_profile_t *sender_profile;
  ec_public_key_t Y;
  dh_public_key_t B;
} dake_pre_key_t;

dake_pre_key_t *
dake_pre_key_new();

void
dake_pre_key_free(dake_pre_key_t *pre_key);

void
dake_pre_key_serialize(uint8_t *target, const dake_pre_key_t *pre_key);

void
dake_pre_key_deserialize(dake_pre_key_t *dst, const uint8_t *src, size_t src_len);

dake_pre_key_t *
dake_compute_pre_key();

#endif
