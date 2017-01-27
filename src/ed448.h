#include <stdbool.h>
#include <stdint.h>
#include <libdecaf/decaf_crypto.h>

#ifndef ED448_H
#define ED448_H

#define EC_SIGNATURE_BYTES DECAF_448_SER_BYTES + DECAF_448_SCALAR_BYTES

typedef decaf_448_private_key_t     ec_keypair_t;
typedef decaf_448_public_key_t      ec_public_key_t;
typedef decaf_448_signature_t       ec_signature_t;
typedef decaf_448_scalar_t          ec_scalar_t;
typedef decaf_448_point_t           ec_point_t;
typedef decaf_448_symmetric_key_t   ec_symmetric_key_t;

void
ec_gen_keypair(ec_keypair_t keypair);

void
ec_keypair_destroy(ec_keypair_t keypair);

bool
ec_public_key_serialize(uint8_t *dst, size_t dst_bytes, const ec_public_key_t pub);

void
ec_public_key_copy(ec_public_key_t dst, const ec_public_key_t src);

void
ec_point_copy(ec_point_t dst, const ec_point_t src);

void
ec_point_serialize(uint8_t *dst, size_t dst_len, const ec_point_t point);

bool
ec_point_deserialize(ec_point_t point, const uint8_t serialized[DECAF_448_SER_BYTES]);

bool
ecdh_shared_secret(uint8_t *shared, size_t shared_bytes, const ec_keypair_t our_priv, const ec_public_key_t their_pub);

static inline void
ec_sign(ec_signature_t dst, const ec_keypair_t keypair, const uint8_t *msg, size_t msg_len) {
  decaf_448_sign(dst, keypair, msg, msg_len);
};

static inline bool
ec_verify(const ec_signature_t sig, const ec_public_key_t pub, const uint8_t *msg, size_t msg_len) {
  if (DECAF_TRUE == decaf_448_verify(sig, pub, msg, msg_len)) {
    return true;
  }

  return false;
};

static inline void
ec_scalar_copy(ec_scalar_t dst, const ec_scalar_t src) {
  decaf_448_scalar_copy(dst, src);
}

#endif
