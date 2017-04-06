#ifndef KEYS_H
#define KEYS_H

typedef int otrv4_public_key_t;
typedef int otrv4_private_key_t;

typedef struct {
    otrv4_public_key_t pub[1];
    otrv4_private_key_t priv[1];
} otrv4_keypair_t;

void otrv4_keypair_destroy(otrv4_keypair_t *key_pair);

#endif
