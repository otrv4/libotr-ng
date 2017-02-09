#ifndef ED448_H
#define ED448_H

#include <stdbool.h>
#include <stdint.h>
#include <libdecaf/decaf_crypto.h>

#include "random.h"

#define EC_SIGNATURE_BYTES DECAF_448_SER_BYTES + DECAF_448_SCALAR_BYTES

typedef decaf_448_private_key_t     ec_keypair_t;
typedef decaf_448_public_key_t      ec_public_key_t;
typedef decaf_448_signature_t       ec_signature_t;
typedef decaf_448_scalar_t          ec_scalar_t;
typedef decaf_448_point_t           ec_point_t;
typedef decaf_448_symmetric_key_t   ec_symmetric_key_t;

static inline void
ec_point_copy(ec_point_t dst, const ec_point_t src) {
  decaf_448_point_copy(dst, src);
}

static inline void
ec_gen_keypair(ec_keypair_t keypair) {
  random_bytes(keypair->sym, DECAF_448_SYMMETRIC_KEY_BYTES);
  decaf_448_derive_private_key(keypair, keypair->sym);
}

static inline void
ec_keypair_destroy(ec_keypair_t keypair) {
  decaf_448_destroy_private_key(keypair);
}

static inline bool
ecdh_shared_secret(
    uint8_t *shared,
    size_t shared_bytes,
    const ec_keypair_t our_priv,
    const ec_public_key_t their_pub
) {
  if (!decaf_448_shared_secret(shared, shared_bytes, our_priv, their_pub)) {
    return false;
  }

  return true;
}

static inline bool
ec_public_key_serialize(uint8_t *dst, size_t dst_bytes, const ec_public_key_t pub) {
  if (sizeof(ec_public_key_t) > dst_bytes) {
    return false;
  }

  memcpy(dst, pub, sizeof(ec_public_key_t));
  return true;
}

static inline void
ec_public_key_copy(ec_public_key_t dst, const ec_public_key_t src) {
  memcpy(dst, src, sizeof(ec_public_key_t));
}

static inline void
ec_point_serialize(uint8_t *dst, size_t dst_len, const ec_point_t point) {
  decaf_448_point_encode(dst, point);
}

static inline bool
ec_point_deserialize(ec_point_t point, const uint8_t serialized[DECAF_448_SER_BYTES]) {
  if (DECAF_TRUE != decaf_448_point_decode(point, serialized, DECAF_FALSE)) {
    return false;
  }
  
  return true;
}


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

static inline bool
ec_point_valid(ec_point_t point) {
  if (DECAF_TRUE == decaf_448_point_valid(point)){
    return true;
  }

  return false;
}

#endif
