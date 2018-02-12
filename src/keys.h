#ifndef OTRV4_KEYS_H
#define OTRV4_KEYS_H

#include "shared.h"
#include "ed448.h"

#define ED448_PUBKEY_TYPE 0x0010
#define ED448_PUBKEY_BYTES 2 + ED448_POINT_BYTES
#define ED448_SHARED_PREKEY_TYPE 0x0011
#define ED448_SHARED_PREKEY_BYTES 2 + ED448_POINT_BYTES

typedef ec_point_t otrv4_public_key_t;
typedef ec_scalar_t otrv4_private_key_t;
typedef ec_point_t otrv4_shared_prekey_pub_t;
typedef ec_scalar_t otrv4_shared_prekey_priv_t;

typedef struct {
  /* the private key is this symmetric key, and not the scalar serialized */
  uint8_t sym[ED448_PRIVATE_BYTES];

  otrv4_public_key_t pub;
  otrv4_private_key_t priv;
} otrv4_keypair_t;

// TODO: implement correctly when the spec comes
typedef struct {
  /* the private key is this symmetric key, and not the scalar serialized */
  uint8_t sym[ED448_PRIVATE_BYTES];

  otrv4_shared_prekey_pub_t pub;
  otrv4_shared_prekey_priv_t priv;
} otrv4_shared_prekey_pair_t;

INTERNAL otrv4_keypair_t *otrv4_keypair_new(void);

INTERNAL void otrv4_keypair_generate(otrv4_keypair_t *keypair,
                            const uint8_t sym[ED448_PRIVATE_BYTES]);

INTERNAL void otrv4_keypair_free(otrv4_keypair_t *keypair);

INTERNAL otrv4_err_t otrv4_symmetric_key_serialize(char **buffer, size_t *buffer_size,
                                          uint8_t sym[ED448_PRIVATE_BYTES]);

INTERNAL otrv4_shared_prekey_pair_t *otrv4_shared_prekey_pair_new(void);

INTERNAL void otrv4_shared_prekey_pair_generate(otrv4_shared_prekey_pair_t *prekey_pair,
                                       const uint8_t sym[ED448_PRIVATE_BYTES]);


INTERNAL void otrv4_shared_prekey_pair_free(otrv4_shared_prekey_pair_t *prekey_pair);


#ifdef OTRV4_KEYS_PRIVATE

tstatic void otrv4_keypair_destroy(otrv4_keypair_t *keypair);

tstatic void otrv4_shared_prekey_pair_destroy(otrv4_shared_prekey_pair_t *prekey_pair);

#endif

#endif
