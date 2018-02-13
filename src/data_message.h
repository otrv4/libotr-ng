#ifndef OTRV4_DATA_MESSAGE_H
#define OTRV4_DATA_MESSAGE_H

#include <sodium.h>
#include <stdint.h>
#include <string.h>

#include "constants.h"
#include "key_management.h"
#include "shared.h"

typedef struct {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  uint8_t flags;
  uint32_t message_id;
  ec_point_t ecdh;
  dh_public_key_t dh;
  uint8_t nonce[DATA_MSG_NONCE_BYTES];
  uint8_t *enc_msg;
  size_t enc_msg_len;
  uint8_t mac[DATA_MSG_MAC_BYTES];
} data_message_t;

INTERNAL data_message_t *otrv4_data_message_new(void);

INTERNAL void otrv4_data_message_free(data_message_t *data_msg);

INTERNAL otrv4_err_t otrv4_data_message_body_asprintf(
    uint8_t **body, size_t *bodylen, const data_message_t *data_msg);

INTERNAL otrv4_err_t otrv4_data_message_deserialize(data_message_t *data_msg,
                                                    const uint8_t *buff,
                                                    size_t bufflen,
                                                    size_t *nread);

INTERNAL otrv4_bool_t otrv4_valid_data_message(m_mac_key_t mac_key,
                                               const data_message_t *data_msg);

#ifdef OTRV4_DATA_MESSAGE_PRIVATE
tstatic void data_message_destroy(data_message_t *data_msg);
#endif

#endif
