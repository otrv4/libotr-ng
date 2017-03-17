#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stdbool.h>
#include <gcrypt.h>

static inline bool
sha3_512 (uint8_t * dst, size_t dst_len, const uint8_t * src, size_t src_len)
{
  if (gcry_md_get_algo_dlen (GCRY_MD_SHA3_512) != dst_len)
    {
      return false;
    }

  gcry_md_hash_buffer (GCRY_MD_SHA3_512, dst, src, src_len);
  return true;
}

static inline bool
sha3_256 (uint8_t * dst, size_t dst_len, const uint8_t * src, size_t src_len)
{
  if (gcry_md_get_algo_dlen (GCRY_MD_SHA3_256) != dst_len)
    {
      return false;
    }

  gcry_md_hash_buffer (GCRY_MD_SHA3_256, dst, src, src_len);
  return true;
}

static bool
sha3_kkdf (int algo, uint8_t * dst, size_t dstlen, const uint8_t * key,
	   size_t keylen, const uint8_t * secret, size_t secretlen)
{
  if (gcry_md_get_algo_dlen (algo) != dstlen)
    {
      return false;
    }

  gcry_md_hd_t hd;
  gcry_md_open (&hd, algo, GCRY_MD_FLAG_SECURE);
  gcry_md_write (hd, key, keylen);
  gcry_md_write (hd, secret, secretlen);
  memcpy (dst, gcry_md_read (hd, 0), dstlen);
  gcry_md_close (hd);
  return true;
}

static inline bool
sha3_512_mac (uint8_t * dst, size_t dstlen, const uint8_t * key,
	      size_t keylen, const uint8_t * msg, size_t msglen)
{
  return sha3_kkdf (GCRY_MD_SHA3_512, dst, dstlen, key, keylen, msg, msglen);
}

static inline bool
sha3_256_kdf (uint8_t * key, size_t keylen, const uint8_t magic[1],
	      const uint8_t * secret, size_t secretlen)
{
  return sha3_kkdf (GCRY_MD_SHA3_256, key, keylen, magic, 1, secret,
		    secretlen);
}

static inline bool
sha3_512_kdf (uint8_t * key, size_t keylen, const uint8_t magic[1],
	      const uint8_t * secret, size_t secretlen)
{
  return sha3_kkdf (GCRY_MD_SHA3_512, key, keylen, magic, 1, secret,
		    secretlen);
}

#endif
