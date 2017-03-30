#include "auth.h"
#include "random.h"

//TODO: This is duplicated
static void
ed448_random_scalar(decaf_448_scalar_t priv)
{
    unsigned char rand[DECAF_448_SCALAR_BYTES];

    do {
        random_bytes(rand, DECAF_448_SCALAR_BYTES);
        (void) decaf_448_scalar_decode(priv, rand);
    } while (DECAF_TRUE == decaf_448_scalar_eq(priv, decaf_448_scalar_zero));

    memset(rand, 0, DECAF_448_SCALAR_BYTES);
}

static void
generate_keypair(snizkpk_pubkey_t pub, snizkpk_privkey_t priv)
{
    ed448_random_scalar(priv);
    decaf_448_point_scalarmul(pub, decaf_448_point_base, priv);
}

void
snizkpk_keypair_generate(snizkpk_keypair_t pair)
{
    generate_keypair(pair->pub, pair->priv);
}

const unsigned char base_point_bytes_dup[DECAF_448_SER_BYTES] = {
 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
};

const unsigned char prime_order_bytes_dup[DECAF_448_SCALAR_BYTES] = {
 0x33, 0xec, 0x9e, 0x52, 0xb5, 0xf5, 0x1c, 0x72,
 0xab, 0xc2, 0xe9, 0xc8, 0x35, 0xf6, 0x4c, 0x7a,
 0xbf, 0x25, 0xa7, 0x44, 0xd9, 0x92, 0xc4, 0xee,
 0x58, 0x70, 0xd7, 0x0c, 0x02, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
};

int
snizkpk_authenticate(snizkpk_proof_t dst, const snizkpk_keypair_t pair1, const snizkpk_pubkey_t A2, const snizkpk_pubkey_t A3, const unsigned char *msg, size_t msglen)
{
    gcry_md_hd_t hd;
    unsigned char hash[64];
    unsigned char point_buff[DECAF_448_SER_BYTES];

    snizkpk_privkey_t t1;
    snizkpk_pubkey_t T1, T2, T3, A2c2, A3c3;

    generate_keypair(T1, t1);

    generate_keypair(T2, dst->r2);
    ed448_random_scalar(dst->c2);
    decaf_448_point_scalarmul(A2c2, A2, dst->c2);
    decaf_448_point_add(T2, T2, A2c2);

    generate_keypair(T3, dst->r3);
    ed448_random_scalar(dst->c3);
    decaf_448_point_scalarmul(A3c3, A3, dst->c3);
    decaf_448_point_add(T3, T3, A3c3);

    gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
    gcry_md_write(hd, base_point_bytes_dup, DECAF_448_SER_BYTES);
    gcry_md_write(hd, prime_order_bytes_dup, DECAF_448_SCALAR_BYTES);

    decaf_448_point_encode(point_buff, pair1->pub);
    gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

    decaf_448_point_encode(point_buff, A2);
    gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

    decaf_448_point_encode(point_buff, A3);
    gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

    decaf_448_point_encode(point_buff, T1);
    gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

    decaf_448_point_encode(point_buff, T2);
    gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

    decaf_448_point_encode(point_buff, T3);
    gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

    gcry_md_write(hd, msg, msglen);

    memcpy(hash, gcry_md_read(hd, 0), 64);
    gcry_md_close(hd);

    //TODO: Do we need anything else to hash from bytes to a scalar?
    snizkpk_privkey_t c, c1a1;
    (void) decaf_448_scalar_decode(c, hash);

    decaf_448_scalar_sub(dst->c1, c, dst->c2);
    decaf_448_scalar_sub(dst->c1, dst->c1, dst->c3);

    decaf_448_scalar_mul(c1a1, dst->c1, pair1->priv);
    decaf_448_scalar_sub(dst->r1, t1, c1a1);

    return 0;
}

int 
snizkpk_verify(const snizkpk_proof_t src, const snizkpk_pubkey_t A1, const snizkpk_pubkey_t A2, const snizkpk_pubkey_t A3, const unsigned char *msg, size_t msglen)
{
    gcry_md_hd_t hd;
    unsigned char hash[64];
    unsigned char point_buff[DECAF_448_SER_BYTES];

    snizkpk_pubkey_t gr1, gr2, gr3, A1c1, A2c2, A3c3;

    decaf_448_point_scalarmul(gr1, decaf_448_point_base, src->r1);
    decaf_448_point_scalarmul(gr2, decaf_448_point_base, src->r2);
    decaf_448_point_scalarmul(gr3, decaf_448_point_base, src->r3);

    decaf_448_point_scalarmul(A1c1, A1, src->c1);
    decaf_448_point_scalarmul(A2c2, A2, src->c2);
    decaf_448_point_scalarmul(A3c3, A3, src->c3);

    decaf_448_point_add(A1c1, A1c1, gr1);
    decaf_448_point_add(A2c2, A2c2, gr2);
    decaf_448_point_add(A3c3, A3c3, gr3);

    gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
    gcry_md_write(hd, base_point_bytes_dup, DECAF_448_SER_BYTES);
    gcry_md_write(hd, prime_order_bytes_dup, DECAF_448_SCALAR_BYTES);

    decaf_448_point_encode(point_buff, A1);
    gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

    decaf_448_point_encode(point_buff, A2);
    gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

    decaf_448_point_encode(point_buff, A3);
    gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

    decaf_448_point_encode(point_buff, A1c1);
    gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

    decaf_448_point_encode(point_buff, A2c2);
    gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

    decaf_448_point_encode(point_buff, A3c3);
    gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

    gcry_md_write(hd, msg, msglen);

    memcpy(hash, gcry_md_read(hd, 0), 64);
    gcry_md_close(hd);

    //TODO: Do we need anything else to hash from bytes to a scalar?
    snizkpk_privkey_t c, c1c2c3;
    (void) decaf_448_scalar_decode(c, hash);
    
    decaf_448_scalar_add(c1c2c3, src->c1, src->c2);
    decaf_448_scalar_add(c1c2c3, c1c2c3, src->c3);

    return DECAF_TRUE != decaf_448_scalar_eq(c, c1c2c3);
}
