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

typedef ec_scalar_p rsig_privkey_p;
typedef ec_point_p rsig_pubkey_p;
typedef otrng_keypair_s rsig_keypair_s, rsig_keypair_p[1];

/**
 * @brief The ring_sig_s structure represents the ring signature.
 *
 *  [c1..r3] the scalars for the signature
 */
typedef struct ring_sig_s {
  ec_scalar_p c1;
  ec_scalar_p r1;
  ec_scalar_p c2;
  ec_scalar_p r2;
  ec_scalar_p c3;
  ec_scalar_p r3;
} ring_sig_s, ring_sig_p[1];

/**
 * @brief Ring Sig keypair generation.
 *
 * @param [pub] The public key.
 * @param [priv] The private key.
 */
INTERNAL void otrng_generate_keypair(rsig_pubkey_p pub, rsig_privkey_p priv);

/**
 * @brief Ring Sig keypair generation.
 *
 * @param [keypair] The keypair.
 */
INTERNAL void otrng_rsig_keypair_generate(rsig_keypair_s *keypair);

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
INTERNAL void otrng_rsig_authenticate(ring_sig_s *dst,
                                      const rsig_keypair_s *keypair,
                                      const rsig_pubkey_p A2,
                                      const rsig_pubkey_p A3,
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
INTERNAL otrng_bool otrng_rsig_verify(const ring_sig_s *src,
                                      const rsig_pubkey_p A1,
                                      const rsig_pubkey_p A2,
                                      const rsig_pubkey_p A3,
                                      const unsigned char *msg, size_t msglen);

INTERNAL void otrng_ring_sig_destroy(ring_sig_s *src);

#ifdef OTRNG_AUTH_PRIVATE
#endif

#endif
