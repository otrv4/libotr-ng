#ifndef DATA_MESSAGE_H
#define DATA_MESSAGE_H

#include <sodium.h>
#include <stdint.h>
#include <string.h>

#include "constants.h"
#include "dh.h"
#include "ed448.h"
#include "key_management.h"

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

data_message_t *data_message_new();

void data_message_free(data_message_t *data_msg);

void data_message_destroy(data_message_t *data_msg);

otr4_err_t data_message_body_asprintf(uint8_t **body, size_t *bodylen,
                                      const data_message_t *data_msg);

otr4_err_t data_message_deserialize(data_message_t *data_msg,
                                    const uint8_t *buff, size_t bufflen,
                                    size_t *nread);

otrv4_bool_t valid_data_message(m_mac_key_t mac_key,
                                const data_message_t *data_msg);

otr4_err_t data_message_body_on_non_interactive_asprintf(
    uint8_t **body, size_t *bodylen,
    const dake_non_interactive_auth_message_t *auth);

otrv4_bool_t valid_data_message_on_non_interactive_auth(
    unsigned char *t, size_t t_len, m_mac_key_t mac_key,
    const dake_non_interactive_auth_message_t *auth);

#endif
