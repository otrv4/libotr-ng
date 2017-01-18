#ifndef DAKE_H
#define DAKE_H

#include "data_types.h"
#include "user_profile.h"

typedef struct {
  uint16_t protocol_version;
  uint8_t message_type;
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  user_profile_t *sender_profile;
  ed448_point_t *Y;
  uint8_t B[80];
} dake_pre_key_t;

dake_pre_key_t *
dake_pre_key_new();

void
dake_pre_key_free(dake_pre_key_t *pre_key);

void
dake_pre_key_serialize(uint8_t *target, const dake_pre_key_t *pre_key);

dake_pre_key_t *
dake_compute_pre_key();

#endif
