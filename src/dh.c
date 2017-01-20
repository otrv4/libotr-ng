#include <sodium.h>

#include "dh.h"

void
dh_init(void) {
  gcry_mpi_scan(&DH3072_MODULUS, GCRYMPI_FMT_HEX,
    (const unsigned char *)DH3072_MODULUS_S, 0, NULL);

  gcry_mpi_scan(&DH3072_GENERATOR, GCRYMPI_FMT_HEX,
    (const unsigned char *)DH3072_GENERATOR_S, 0, NULL);
}

int
dh_gen_keypair(dh_keypair_t keypair) {
  uint8_t *secbuf = malloc(DH_KEY_SIZE);
  if (secbuf == NULL) {
      return -1;
  }

  randombytes_buf(secbuf, DH_KEY_SIZE);
  gcry_error_t err = gcry_mpi_scan(&keypair->priv, GCRYMPI_FMT_USG, secbuf, DH_KEY_SIZE, NULL);
  gcry_free(secbuf);

  if (err) {
    return -1;
  }

  keypair->pub = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  gcry_mpi_powm(keypair->pub, DH3072_GENERATOR, keypair->priv, DH3072_MODULUS);

  return 0;
}

void
dh_keypair_destroy(dh_keypair_t keypair) {
  gcry_mpi_release(keypair->priv);
  gcry_mpi_release(keypair->pub);
}

int
dh_shared_secret(
    uint8_t *shared,
    size_t shared_bytes,
    const dh_private_key_t our_priv,
    const dh_public_key_t their_pub
) {
  gcry_mpi_t secret = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  gcry_mpi_powm(secret, their_pub, our_priv, DH3072_MODULUS);
  gcry_error_t err = gcry_mpi_print(GCRYMPI_FMT_USG, shared, shared_bytes, NULL, secret);
  gcry_mpi_release(secret);

  if (err) {
      return -1;
  }

  return 0;
}
