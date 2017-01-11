#include "data_types.c"
#include "user_profile.h"

typedef struct {
  short protocol_version;
  char message_type;
  int sender_instance_tag;
  int receiver_instance_tag;
  user_profile_t *sender_profile;
  ed448_point_t *Y;
  unsigned char B[80];
} dake_pre_key_t;

dake_pre_key_t *
dake_pre_key_new();

void
dake_pre_key_free(dake_pre_key_t *pre_key);

dake_pre_key_t *
dake_compute_pre_key();
