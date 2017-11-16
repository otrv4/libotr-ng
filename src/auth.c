#include "auth.h"
#include "constants.h"
#include "random.h"
#include "shake.h"

void generate_keypair(snizkpk_pubkey_t pub, snizkpk_privkey_t priv) {
  ed448_random_scalar(priv);
  decaf_448_point_scalarmul(pub, decaf_448_point_base, priv);
}

void snizkpk_keypair_generate(snizkpk_keypair_t *pair) {
  generate_keypair(pair->pub, pair->priv);
}

// TODO: check this base point
/* in big endian */
const unsigned char base_point_bytes_dup[ED448_POINT_BYTES] = {
    0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98, 0xad, 0xc8, 0xd7, 0x4e,
    0x2c, 0x13, 0xbd, 0xfd, 0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
    0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87, 0x40, 0x98, 0xa3, 0x6c,
    0x73, 0x73, 0xea, 0x4b, 0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
    0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69, 0x00,
};

/* in big endian */
const unsigned char prime_order_bytes_dup[ED448_SCALAR_BYTES] = {
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x7c, 0xca, 0x23, 0xe9, 0xc4, 0x4e, 0xdb, 0x49,
    0xae, 0xd6, 0x36, 0x90, 0x21, 0x6c, 0xc2, 0x72, 0x8d, 0xc5, 0x8f, 0x55,
    0x23, 0x78, 0xc2, 0x92, 0xab, 0x58, 0x44, 0xf3,
};

void snizkpk_authenticate(snizkpk_proof_t *dst, const snizkpk_keypair_t *pair1,
                          const snizkpk_pubkey_t A2, const snizkpk_pubkey_t A3,
                          const unsigned char *msg, size_t msglen) {

  decaf_shake256_ctx_t hd;
  uint8_t hash[HASH_BYTES];
  unsigned char point_buff[ED448_POINT_BYTES];

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

  hash_init_with_dom(hd);
  hash_update(hd, base_point_bytes_dup, ED448_POINT_BYTES);
  hash_update(hd, prime_order_bytes_dup, ED448_SCALAR_BYTES);

  decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, pair1->pub);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, T1);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, T2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, T3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  hash_update(hd, msg, msglen);

  hash_final(hd, hash, sizeof(hash));
  hash_destroy(hd);

  snizkpk_privkey_t c, c1a1;
  decaf_448_scalar_decode_long(c, hash, ED448_SCALAR_BYTES);

  decaf_448_scalar_sub(dst->c1, c, dst->c2);
  decaf_448_scalar_sub(dst->c1, dst->c1, dst->c3);

  decaf_448_scalar_mul(c1a1, dst->c1, pair1->priv);
  decaf_448_scalar_sub(dst->r1, t1, c1a1);
}

otr4_err_t snizkpk_verify(const snizkpk_proof_t *src, const snizkpk_pubkey_t A1,
                          const snizkpk_pubkey_t A2, const snizkpk_pubkey_t A3,
                          const unsigned char *msg, size_t msglen) {

  decaf_shake256_ctx_t hd;
  uint8_t hash[HASH_BYTES];
  unsigned char point_buff[ED448_POINT_BYTES];

  hash_init_with_dom(hd);

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

  hash_update(hd, base_point_bytes_dup, ED448_POINT_BYTES);
  hash_update(hd, prime_order_bytes_dup, ED448_SCALAR_BYTES);

  decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A1);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A1c1);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A2c2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A3c3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  hash_update(hd, msg, msglen);

  hash_final(hd, hash, sizeof(hash));
  hash_destroy(hd);

  snizkpk_privkey_t c, c1c2c3;
  decaf_448_scalar_decode_long(c, hash, ED448_SCALAR_BYTES);

  decaf_448_scalar_add(c1c2c3, src->c1, src->c2);
  decaf_448_scalar_add(c1c2c3, c1c2c3, src->c3);

  if (DECAF_TRUE == decaf_448_scalar_eq(c, c1c2c3)) {
    return OTR4_SUCCESS;
  }

  return OTR4_ERROR;
}

void snizkpk_proof_destroy(snizkpk_proof_t *src) {
  ec_scalar_destroy(src->c1);
  ec_scalar_destroy(src->r1);
  ec_scalar_destroy(src->c2);
  ec_scalar_destroy(src->r2);
  ec_scalar_destroy(src->c3);
  ec_scalar_destroy(src->r3);
}

// TODO: move this to the correct place
void ecdh_shared_secret_from_prekey(uint8_t *shared,
                                    otrv4_shared_prekey_pair_t *shared_prekey,
                                    const ec_point_t their_pub) {
  decaf_448_point_t s;
  decaf_448_point_scalarmul(s, their_pub, shared_prekey->priv);

  ec_point_serialize(shared, s);
}

void ecdh_shared_secret_from_keypair(uint8_t *shared, otrv4_keypair_t *keypair,
                                     const ec_point_t their_pub) {
  decaf_448_point_t s;
  decaf_448_point_scalarmul(s, their_pub, keypair->priv);

  ec_point_serialize(shared, s);
}
