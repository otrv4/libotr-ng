#include <stdbool.h>
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

typedef struct {
  ec_point_t U11;
  ec_point_t U21;
  ec_point_t E1;
  ec_point_t V1;
  ec_point_t U12;
  ec_point_t U22;
  ec_point_t E2;
  ec_point_t V2;
  //l
  //n1
  //n2
} dake_dre_message_t;

typedef struct {
  // c1
  // r1
  // c2
  // r2
  // c3
  // r3
} dake_dre_authentication_t;

typedef struct {
  uint8_t version_protocol;
  uint8_t type;
  uint8_t sender_instance_tag;
  uint8_t receiver_instance_tag;
  user_profile_t sender_profile[1];
  ec_point_t X;
  uint8_t A[80];
  dake_dre_message_t gamma;
  dake_dre_authentication_t sigma;
} dake_dre_auth_t;

dake_pre_key_t *
dake_pre_key_new();

void
dake_pre_key_free(dake_pre_key_t *pre_key);

void
dake_pre_key_serialize(uint8_t *target, const dake_pre_key_t *pre_key);

bool
dake_pre_key_deserialize(dake_pre_key_t *dst, const uint8_t *src, size_t src_len);

dake_dre_auth_t *
dake_dre_auth_new();

void
dake_dre_auth_free(dake_dre_auth_t *dre_auth);

bool
dake_dre_auth_serialize(uint8_t *target, const dake_dre_auth_t *dre_auth);

void
dake_dre_auth_deserialize(dake_dre_auth_t *target, uint8_t *data);

int
dake_pre_key_validate(const dake_pre_key_t *pre_key);

dake_pre_key_t *
dake_compute_pre_key();

#endif
