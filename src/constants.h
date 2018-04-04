#ifndef OTRNG_CONSTANTS_H
#define OTRNG_CONSTANTS_H

#define VERSION 4
#define IDENTITY_MSG_TYPE 0x08
#define AUTH_R_MSG_TYPE 0x91
#define AUTH_I_MSG_TYPE 0x88
#define PRE_KEY_MSG_TYPE 0x0F
#define NON_INT_AUTH_MSG_TYPE 0x8D
#define DATA_MSG_TYPE 0x03

#define DAKE_HEADER_BYTES (2 + 1 + 4 + 4)
#define HASH_BYTES 64

/* size of PRE_KEY_MESSAGE without user_profile */
#define PRE_KEY_MIN_BYTES (DAKE_HEADER_BYTES + ED448_POINT_BYTES + DH_MPI_BYTES)

#define AUTH_R_MIN_BYTES                                                       \
  (DAKE_HEADER_BYTES + ED448_POINT_BYTES + DH_MPI_BYTES + SNIZKPK_BYTES)

#define NON_INT_AUTH_BYTES                                                     \
  (DAKE_HEADER_BYTES + ED448_POINT_BYTES + DH_MPI_BYTES + SNIZKPK_BYTES +      \
   HASH_BYTES)

#define DATA_MSG_NONCE_BYTES crypto_secretbox_NONCEBYTES
#define DATA_MSG_MAC_BYTES 64
#define MAC_KEY_BYTES 64
#define BRACE_KEY_BYTES 32
#define SHARED_SECRET_BYTES 64
#define CHAIN_KEY_BYTES 64
#define ROOT_KEY_BYTES 64

#define DATA_MESSAGE_MIN_BYTES                                                 \
  (DAKE_HEADER_BYTES + 1 + 4 + ED448_POINT_BYTES + DATA_MSG_NONCE_BYTES)

#define MSGFLAGS_IGNORE_UNREADABLE 0x01

#endif
