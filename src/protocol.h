#ifndef PROTOCOL_H
#define PROTOCOL_H

#define OTR4_INIT do { \
  dh_init(); \
} while (0);

#define OTR4_FREE do { \
  dh_free(); \
} while (0);

typedef enum {
  OTRV4_STATE_START = 1,
  OTRV4_STATE_AKE_IN_PROGRESS = 2,
  OTRV4_STATE_ENCRYPTED_MESSAGES = 3,
  OTRV4_STATE_FINISHED = 4
} otrv4_state;

typedef enum {
  OTRV4_ALLOW_NONE = 0,
  OTRV4_ALLOW_V3 = 1,
  OTRV4_ALLOW_V4 = 2
} otrv4_supported_version;

typedef struct {
  otrv4_state state;
  int supported_versions;
} otrv4_protocol_t;

otrv4_protocol_t *
protocol_start(int versions, ...);

#endif
