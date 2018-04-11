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

#define OTRNG_DH_PRIVATE

#include "dh.h"
#include "random.h"
#include "shake.h"

static const char *DH3072_MODULUS_S =
    "0x"
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

static const char *DH3072_MODULUS_SQ =
    "0x"
    "7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68"
    "948127044533E63A0105DF531D89CD9128A5043CC71A026E"
    "F7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122"
    "F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6"
    "F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9E"
    "E1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AF"
    "C1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36"
    "B3861AA7255E4C0278BA3604650C10BE19482F23171B671D"
    "F1CF3B960C074301CD93C1D17603D147DAE2AEF837A62964"
    "EF15E5FB4AAC0B8C1CCAA4BE754AB5728AE9130C4C7D0288"
    "0AB9472D45556216D6998B8682283D19D42A90D5EF8E5D32"
    "767DC2822C6DF785457538ABAE83063ED9CB87C2D370F263"
    "D5FAD7466D8499EB8F464A702512B0CEE771E9130D697735"
    "F897FD036CC504326C3B01399F643532290F958C0BBD9006"
    "5DF08BABBD30AEB63B84C4605D6CA371047127D03A72D598"
    "A1EDADFE707E884725C16890549D69657FFFFFFFFFFFFFFF";

static gcry_mpi_t DH3072_MODULUS = NULL;
static gcry_mpi_t DH3072_MODULUS_Q = NULL;
static gcry_mpi_t DH3072_MODULUS_MINUS_2 = NULL;
static const char *DH3072_GENERATOR_S = "0x02";
static gcry_mpi_t DH3072_GENERATOR = NULL;

static int dh_initialized = 0;

INTERNAL void otrng_dh_init(void) {
  if (dh_initialized)
    return;

  dh_initialized = 1;

  gcry_mpi_scan(&DH3072_MODULUS, GCRYMPI_FMT_HEX,
                (const unsigned char *)DH3072_MODULUS_S, 0, NULL);

  gcry_mpi_scan(&DH3072_MODULUS_Q, GCRYMPI_FMT_HEX,
                (const unsigned char *)DH3072_MODULUS_SQ, 0, NULL);

  gcry_mpi_scan(&DH3072_GENERATOR, GCRYMPI_FMT_HEX,
                (const unsigned char *)DH3072_GENERATOR_S, 0, NULL);

  DH3072_MODULUS_MINUS_2 = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  gcry_mpi_sub_ui(DH3072_MODULUS_MINUS_2, DH3072_MODULUS, 2);
}

INTERNAL void otrng_dh_free(void) {
  if (!dh_initialized)
    return;

  gcry_mpi_release(DH3072_MODULUS);
  DH3072_MODULUS = NULL;

  gcry_mpi_release(DH3072_MODULUS_Q);
  DH3072_MODULUS_Q = NULL;

  gcry_mpi_release(DH3072_GENERATOR);
  DH3072_GENERATOR = NULL;

  gcry_mpi_release(DH3072_MODULUS_MINUS_2);
  DH3072_MODULUS_MINUS_2 = NULL;

  dh_initialized = 0;
}

INTERNAL otrng_err_t otrng_dh_keypair_generate(dh_keypair_t keypair) {
  uint8_t hash[DH_KEY_SIZE];
  gcry_mpi_t privkey = NULL;
  uint8_t *secbuf = NULL;

  secbuf = gcry_random_bytes_secure(DH_KEY_SIZE, GCRY_STRONG_RANDOM);
  shake_256_hash(hash, sizeof(hash), secbuf, DH_KEY_SIZE);

  gcry_error_t err =
      gcry_mpi_scan(&privkey, GCRYMPI_FMT_USG, hash, DH_KEY_SIZE, NULL);
  gcry_free(secbuf);

  if (err)
    return ERROR;

  keypair->priv = privkey;
  keypair->pub = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  gcry_mpi_powm(keypair->pub, DH3072_GENERATOR, privkey, DH3072_MODULUS);

  return SUCCESS;
}

tstatic void dh_pub_key_destroy(dh_keypair_t keypair) {
  gcry_mpi_release(keypair->pub);
  keypair->pub = NULL;
}

INTERNAL void otrng_dh_priv_key_destroy(dh_keypair_t keypair) {
  gcry_mpi_release(keypair->priv);
  keypair->priv = NULL;
}

INTERNAL void otrng_dh_keypair_destroy(dh_keypair_t keypair) {
  otrng_dh_priv_key_destroy(keypair);
  dh_pub_key_destroy(keypair);
}

INTERNAL otrng_err_t otrng_dh_shared_secret(uint8_t *shared,
                                            size_t shared_bytes,
                                            const dh_private_key_t our_priv,
                                            const dh_public_key_t their_pub) {
  gcry_mpi_t secret = gcry_mpi_snew(DH3072_MOD_LEN_BITS);
  gcry_mpi_powm(secret, their_pub, our_priv, DH3072_MODULUS);
  size_t written;
  uint8_t buffer[shared_bytes];
  gcry_error_t err =
      gcry_mpi_print(GCRYMPI_FMT_USG, buffer, shared_bytes, &written, secret);

  gcry_mpi_release(secret);

  // Replace removed leading zeroes to ensure size is 384
  // TODO: this is memsetting a uint8_t *
  memset(shared, 0, shared_bytes);
  memcpy(shared + shared_bytes - written, buffer, written);

  if (err)
    return ERROR;

  return SUCCESS;
}

INTERNAL otrng_err_t otrng_dh_mpi_serialize(uint8_t *dst, size_t dst_len,
                                            size_t *written,
                                            const dh_mpi_t src) {
  gcry_error_t err =
      gcry_mpi_print(GCRYMPI_FMT_USG, dst, dst_len, written, src);
  if (err)
    return ERROR;

  return SUCCESS;
}

INTERNAL otrng_err_t otrng_dh_mpi_deserialize(dh_mpi_t *dst,
                                              const uint8_t *buffer,
                                              size_t buflen, size_t *nread) {
  if (gcry_mpi_scan(dst, GCRYMPI_FMT_USG, buffer, buflen, nread))
    return ERROR;

  return SUCCESS;
}

INTERNAL otrng_bool_t otrng_dh_mpi_valid(dh_mpi_t mpi) {
  /* Check that pub is in range */
  if (mpi == NULL)
    return otrng_false;

  /* mpi >= 2 and <= dh_p - 2 */
  if ((gcry_mpi_cmp_ui(mpi, 2) < 0 ||
       gcry_mpi_cmp(mpi, DH3072_MODULUS_MINUS_2) > 0))
    return otrng_false;

  /* slower: x ^ q mod p
  gcry_mpi_t tmp = gcry_mpi_new(DH3072_MOD_LEN_BYTES);
  gcry_mpi_powm(tmp, mpi, DH3072_MODULUS_Q, DH3072_MODULUS);

  if (gcry_mpi_cmp_ui(tmp, 1) == 0)
    return ERROR;
  */

  return otrng_true;
}

INTERNAL dh_mpi_t otrng_dh_mpi_copy(const dh_mpi_t src) {
  return gcry_mpi_copy(src);
}

INTERNAL void otrng_dh_mpi_release(dh_mpi_t mpi) { gcry_mpi_release(mpi); }
