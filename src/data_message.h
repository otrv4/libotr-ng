#ifndef DATA_MESSAGE_H
#define DATA_MESSAGE_H

#include <stdint.h>
#include <sodium.h>

#include "ed448.h"
#include "dh.h"
#include "key_management.h"

#define DATA_MSG_NONCE_BYTES crypto_secretbox_NONCEBYTES
#define DATA_MSG_MAC_BYTES 64

#define DATA_MESSAGE_MIN_BYTES (2+1+4+4+1+4+4+sizeof(ec_public_key_t)+DH_MPI_BYTES+DATA_MSG_NONCE_BYTES)

typedef struct {
	uint32_t sender_instance_tag;
	uint32_t receiver_instance_tag;
	uint8_t flags;
	uint32_t ratchet_id;
	uint32_t message_id;
	ec_public_key_t our_ecdh;
	dh_public_key_t our_dh;
	uint8_t nonce[DATA_MSG_NONCE_BYTES];
	uint8_t *enc_msg;
	size_t enc_msg_len;
	uint8_t mac[DATA_MSG_MAC_BYTES];
	uint8_t *old_mac_keys;
	size_t old_mac_keys_len;
} data_message_t;

data_message_t *data_message_new();

void data_message_free(data_message_t * data_msg);

void data_message_destroy(data_message_t * data_msg);

bool
data_message_body_aprint(uint8_t ** body, size_t * bodylen,
			 const data_message_t * data_msg);

bool
data_message_deserialize(data_message_t * data_msg, uint8_t * buff,
			 size_t bufflen);

bool
data_message_validate(m_mac_key_t mac_key, const data_message_t * data_msg);

#endif
