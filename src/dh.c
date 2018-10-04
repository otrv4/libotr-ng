/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
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

#include <assert.h>

#define OTRNG_DH_PRIVATE

#include "dh.h"
#include "key_management.h"
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

INTERNAL otrng_result otrng_dh_init(otrng_bool die) {
  gcry_error_t err;

  if (dh_initialized) {
    return OTRNG_SUCCESS;
  }

  dh_initialized = 1;

  err = gcry_mpi_scan(&DH3072_MODULUS, GCRYMPI_FMT_HEX,
                      (const unsigned char *)DH3072_MODULUS_S, 0, NULL);
  if (err) {
    fprintf(stderr, "dh - s - initialization failed\n");
    if (die) {
      exit(EXIT_FAILURE);
    }
    return OTRNG_ERROR;
  }

  err = gcry_mpi_scan(&DH3072_MODULUS_Q, GCRYMPI_FMT_HEX,
                      (const unsigned char *)DH3072_MODULUS_SQ, 0, NULL);
  if (err) {
    gcry_mpi_release(DH3072_MODULUS);
    fprintf(stderr, "dh - sq - initialization failed\n");
    if (die) {
      exit(EXIT_FAILURE);
    }
    return OTRNG_ERROR;
  }

  err = gcry_mpi_scan(&DH3072_GENERATOR, GCRYMPI_FMT_HEX,
                      (const unsigned char *)DH3072_GENERATOR_S, 0, NULL);
  if (err) {
    gcry_mpi_release(DH3072_MODULUS);
    gcry_mpi_release(DH3072_MODULUS_Q);
    fprintf(stderr, "dh - gen s - initialization failed\n");
    if (die) {
      exit(EXIT_FAILURE);
    }
    return OTRNG_ERROR;
  }

  DH3072_MODULUS_MINUS_2 = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  if (!DH3072_MODULUS_MINUS_2) {
    gcry_mpi_release(DH3072_MODULUS);
    gcry_mpi_release(DH3072_MODULUS_Q);
    gcry_mpi_release(DH3072_GENERATOR);
    fprintf(stderr, "dh - minus 2 - initialization failed\n");
    if (die) {
      exit(EXIT_FAILURE);
    }
    return OTRNG_ERROR;
  }

  gcry_mpi_sub_ui(DH3072_MODULUS_MINUS_2, DH3072_MODULUS, 2);

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_dh_free(void) {
  if (!dh_initialized) {
    return;
  }

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

INTERNAL dh_mpi_t otrng_dh_mpi_generator(void) { return DH3072_GENERATOR; }

INTERNAL void otrng_dh_calculate_public_key(dh_public_key_t pub,
                                            const dh_private_key_t priv) {
  gcry_mpi_powm(pub, DH3072_GENERATOR, priv, DH3072_MODULUS);
}

INTERNAL otrng_result otrng_dh_keypair_generate(dh_keypair_s *keypair) {
  uint8_t *hash = otrng_secure_alloc(DH_KEY_SIZE);
  gcry_mpi_t privkey = NULL;
  uint8_t *sec_buffer = NULL;
  gcry_error_t err;

  sec_buffer = gcry_random_bytes_secure(DH_KEY_SIZE, GCRY_STRONG_RANDOM);
  shake_256_hash(hash, DH_KEY_SIZE, sec_buffer, DH_KEY_SIZE);

  err = gcry_mpi_scan(&privkey, GCRYMPI_FMT_USG, hash, DH_KEY_SIZE, NULL);
  otrng_secure_wipe(hash, DH_KEY_SIZE);
  free(hash);
  otrng_secure_wipe(sec_buffer, DH_KEY_SIZE);
  gcry_free(sec_buffer);

  if (err) {
    return OTRNG_ERROR;
  }

  keypair->priv = privkey;
  keypair->pub = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  gcry_mpi_powm(keypair->pub, DH3072_GENERATOR, privkey, DH3072_MODULUS);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_dh_keypair_generate_from_shared_secret(
    uint8_t ss[SHARED_SECRET_BYTES], dh_keypair_s *keypair,
    const char participant) {
  gcry_mpi_t privkey = NULL;
  uint8_t *random_buffer = otrng_secure_alloc(DH_KEY_SIZE);
  uint8_t usage_DH_first_ephemeral = 0x12;
  gcry_error_t err;

  shake_256_kdf1(random_buffer, DH_KEY_SIZE, usage_DH_first_ephemeral, ss,
                 SHARED_SECRET_BYTES);

  err = gcry_mpi_scan(&privkey, GCRYMPI_FMT_USG, random_buffer, DH_KEY_SIZE,
                      NULL);

  otrng_secure_wipe(random_buffer, DH_KEY_SIZE);
  free(random_buffer);

  if (err) {
    return OTRNG_ERROR;
  }

  assert(participant == 'u' || participant == 't');

  if (participant == 'u') {
    keypair->priv = privkey;
    keypair->pub = gcry_mpi_new(DH3072_MOD_LEN_BITS);
    gcry_mpi_powm(keypair->pub, DH3072_GENERATOR, privkey, DH3072_MODULUS);
  } else if (participant == 't') {
    keypair->pub = gcry_mpi_new(DH3072_MOD_LEN_BITS);
    gcry_mpi_powm(keypair->pub, DH3072_GENERATOR, privkey, DH3072_MODULUS);
    gcry_mpi_release(privkey);
  }

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_dh_priv_key_destroy(dh_keypair_s *keypair) {
  gcry_mpi_release(keypair->priv);
  keypair->priv = NULL;
}

INTERNAL void otrng_dh_keypair_destroy(dh_keypair_s *keypair) {
  otrng_dh_priv_key_destroy(keypair);
  gcry_mpi_release(keypair->pub);
  keypair->pub = NULL;
}

INTERNAL otrng_result otrng_dh_shared_secret(dh_shared_secret_t buffer,
                                             size_t *written,
                                             const dh_private_key_t our_priv,
                                             const dh_public_key_t their_pub) {
  gcry_error_t err;
  gcry_mpi_t secret = gcry_mpi_snew(DH3072_MOD_LEN_BITS);
  if (!secret) {
    return OTRNG_ERROR;
  }

  gcry_mpi_powm(secret, their_pub, our_priv, DH3072_MODULUS);
  err = gcry_mpi_print(GCRYMPI_FMT_USG, buffer, DH3072_MOD_LEN_BYTES, written,
                       secret);

  gcry_mpi_release(secret);

  if (err) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_dh_mpi_serialize(uint8_t *dst, size_t dst_len,
                                             size_t *written,
                                             const dh_mpi_t src) {
  gcry_error_t err;
  if (!src) {
    if (written) {
      *written = 0;
    }

    return OTRNG_SUCCESS;
  }

  err = gcry_mpi_print(GCRYMPI_FMT_USG, dst, dst_len, written, src);
  if (err) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_dh_mpi_deserialize(dh_mpi_t *dst,
                                               const uint8_t *buffer,
                                               size_t buff_len, size_t *nread) {
  gcry_error_t err;

  if (!buff_len) {
    gcry_mpi_set_ui(*dst, 0); // TODO: can this fail?
    return OTRNG_SUCCESS;
  }

  err = gcry_mpi_scan(dst, GCRYMPI_FMT_USG, buffer, buff_len, nread);
  if (err) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

API otrng_bool otrng_dh_mpi_valid(dh_mpi_t mpi) {
  /* Check that pub is in range */
  if (mpi == NULL) {
    return otrng_false;
  }

  /* mpi >= 2 and <= dh_p - 2 */
  if ((gcry_mpi_cmp_ui(mpi, 2) < 0 ||
       gcry_mpi_cmp(mpi, DH3072_MODULUS_MINUS_2) > 0)) {
    return otrng_false;
  }

  /* slower: x ^ q mod p
  gcry_mpi_t tmp = gcry_mpi_new(DH3072_MOD_LEN_BYTES);
  gcry_mpi_powm(tmp, mpi, DH3072_MODULUS_Q, DH3072_MODULUS);

  if (gcry_mpi_cmp_ui(tmp, 1) == 0)
    return OTRNG_ERROR;
  */

  return otrng_true;
}

// TODO: check the return
INTERNAL dh_mpi_t otrng_dh_mpi_copy(const dh_mpi_t src) {
  return gcry_mpi_copy(src);
}

INTERNAL void otrng_dh_mpi_release(dh_mpi_t mpi) { gcry_mpi_release(mpi); }

INTERNAL dh_mpi_t otrng_dh_modulus_p() { return DH3072_MODULUS; }

INTERNAL dh_mpi_t otrng_dh_modulus_q() { return DH3072_MODULUS_Q; }

#ifdef DEBUG_API

#include "debug.h"

API void otrng_dh_keypair_debug_print(FILE *f, int indent, dh_keypair_s *k) {
  if (otrng_debug_print_should_ignore("dh_keypair")) {
    return;
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "dh_keypair {\n");

  if (otrng_debug_print_should_ignore("dh_keypair->pub")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "pub = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "pub = ");
    otrng_dh_public_key_debug_print(f, k->pub);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore("dh_keypair->priv")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "pub = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "priv = ");
    otrng_dh_private_key_debug_print(f, k->priv);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "} // dh_keypair\n");
}

API void otrng_dh_public_key_debug_print(FILE *f, dh_public_key_t k) {
  uint8_t buf[DH3072_MOD_LEN_BYTES] = {0};
  size_t w = 0;

  if (otrng_debug_print_should_ignore("dh_public_key")) {
    return;
  }

  otrng_dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, &w, k);
  otrng_debug_print_data(f, buf, w);
}

API void otrng_dh_private_key_debug_print(FILE *f, dh_private_key_t k) {
  uint8_t buf[DH_KEY_SIZE] = {0};
  size_t w = 0;

  if (otrng_debug_print_should_ignore("dh_private_key")) {
    return;
  }

  otrng_dh_mpi_serialize(buf, DH_KEY_SIZE, &w, k);
  otrng_debug_print_data(f, buf, w);
}

#endif /* DEBUG */
