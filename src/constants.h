#ifndef CONSTANTS_H
#define CONSTANTS_H

#define OTR_VERSION 4
#define OTR_IDENTITY_MSG_TYPE 0x08
#define OTR_AUTH_R_MSG_TYPE 0x91
#define OTR_AUTH_I_MSG_TYPE 0x88
#define OTR_PRE_KEY_MSG_TYPE 0x0F
#define OTR_DATA_MSG_TYPE 0x03

#define DAKE_HEADER_BYTES (2+1+4+4)

//size of PRE_KEY_MESSAGE without user_profile
#define PRE_KEY_MIN_BYTES (DAKE_HEADER_BYTES \
                          + ED448_POINT_BYTES \
                          + DH_MPI_BYTES)

#define AUTH_R_MIN_BYTES (DAKE_HEADER_BYTES \
        + ED448_POINT_BYTES \
        + DH_MPI_BYTES \
        + SNIZKPK_BYTES)

#define DATA_MSG_NONCE_BYTES crypto_secretbox_NONCEBYTES
#define DATA_MSG_MAC_BYTES 64

#define DATA_MESSAGE_MIN_BYTES (\
                               + DAKE_HEADER_BYTES \
                               + 1+4+4 \
                               + ED448_POINT_BYTES \
                               + DATA_MSG_NONCE_BYTES )

#endif
