#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>
#include <libdecaf/decaf.h>

typedef decaf_448_scalar_t snizkpk_privkey_t;
typedef decaf_448_point_t snizkpk_pubkey_t;

typedef struct {
    snizkpk_pubkey_t pub;
    snizkpk_privkey_t priv;
} snizkpk_keypair_t[1];

typedef struct {
    snizkpk_privkey_t c1;
    snizkpk_privkey_t r1;
    snizkpk_privkey_t c2;
    snizkpk_privkey_t r2;
    snizkpk_privkey_t c3;
    snizkpk_privkey_t r3;
} snizkpk_proof_t[1];

void
snizkpk_keypair_generate(snizkpk_keypair_t pair);

int
snizkpk_authenticate(snizkpk_proof_t dst, const snizkpk_keypair_t pair1, const snizkpk_pubkey_t A2, const snizkpk_pubkey_t A3, const unsigned char *msg, size_t msglen);

int
snizkpk_verify(const snizkpk_proof_t src, const snizkpk_pubkey_t A1, const snizkpk_pubkey_t A2, const snizkpk_pubkey_t A3, const unsigned char *msg, size_t msglen);

void
generate_keypair(snizkpk_pubkey_t pub, snizkpk_privkey_t priv);

#endif
