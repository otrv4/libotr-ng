/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OTRNG_AUTH_H
#define OTRNG_AUTH_H

#include <stddef.h>

#include "ed448.h"
#include "keys.h"
#include "shared.h"

/* The size of the ring signature. */
#define RING_SIG_BYTES 6 * ED448_SCALAR_BYTES

typedef ec_scalar_t rsig_privkey_t;
typedef ec_point_t rsig_pubkey_t;
typedef otrng_keypair_t rsig_keypair_t;

/**
 * @brief The ring_sig_t structure represents the ring signature.
 *
 *  [c1] the scalar for the signature
 *  [r1] the scalar for the signature
 *  [c2] the scalar for the signature
 *  [r2] the scalar for the signature
 *  [c3] the scalar for the signature
 *  [r3] the scalar for the signature
 */
typedef struct {
  ec_scalar_t c1;
  ec_scalar_t r1;
  ec_scalar_t c2;
  ec_scalar_t r2;
  ec_scalar_t c3;
  ec_scalar_t r3;
} ring_sig_t;

/**
 * @brief Ring Sig keypair generation.
 *
 * @param [pub] The public key.
 * @param [priv] The private key.
 */
INTERNAL void otrng_generate_keypair(rsig_pubkey_t pub, rsig_privkey_t priv);

/**
 * @brief Ring Sig keypair generation.
 *
 * @param [keypair] The keypair.
 */
INTERNAL void otrng_rsig_keypair_generate(rsig_keypair_t *keypair);

/**
 * @brief The Authentication function of the Ring Sig.
 *
 * It produces a signature of knowledge, named sigma, bound to the
 * message msg, that demonstrates knowledge of a private key
 * corresponding to one of three public keys.
 *
 * @param [dst] The signature of knowledge
 * @param [keypair] The keypair with the known private key.
 * @param [A2] The second public key.
 * @param [A3] The thrid public key.
 * @param [msg] The message to "sign".
 * @param [msg_len] The length of the message.
 */
INTERNAL void otrng_rsig_authenticate(ring_sig_t *dst,
                                      const rsig_keypair_t *keypair,
                                      const rsig_pubkey_t A2,
                                      const rsig_pubkey_t A3,
                                      const unsigned char *msg, size_t msglen);

/**
 * @brief The Verification function of the Ring Sig.
 *
 * The verification function for the SoK sigma, created by rsig_authenticate.
 *
 * @param [src] The signature of knowledge
 * @param [A1] The first public key.
 * @param [A2] The second public key.
 * @param [A3] The thrid public key.
 * @param [msg] The message to "verify".
 * @param [msg_len] The length of the message.
 */
INTERNAL otrng_bool_t otrng_rsig_verify(
    const ring_sig_t *src, const rsig_pubkey_t A1, const rsig_pubkey_t A2,
    const rsig_pubkey_t A3, const unsigned char *msg, size_t msglen);

INTERNAL void otrng_ring_sig_destroy(ring_sig_t *src);

#ifdef OTRNG_AUTH_PRIVATE
#endif

#endif
