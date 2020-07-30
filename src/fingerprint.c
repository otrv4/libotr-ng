/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
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

#define OTRNG_FINGERPRINT_PRIVATE

#include <assert.h>

#include "alloc.h"
#include "client.h"
#include "fingerprint.h"
#include "serialize.h"
#include "shake.h"

/* Convert a 56-byte hash value to a 126-byte human-readable value */
/* The 126-byte output INCLUDES a terminating zero byte. The actual content */
/* is only 125 bytes */
API otrng_result otrng_fingerprint_hash_to_human(char *human,
                                                 const unsigned char *hash,
                                                 size_t hash_size) {
  int word, byte;
  char *p = human;

  if (hash_size != FPRINT_LEN_BYTES) {
    return OTRNG_ERROR;
  }

  for (word = 0; word < 14; ++word) {
    for (byte = 0; byte < 4; ++byte) {
      if (snprintf(p, 3, "%02X", (unsigned int)hash[word * 4 + byte]) < 0) {
        return OTRNG_ERROR;
      }
      p += 2;
    }
    *(p++) = ' ';
  }

  /* Change that last ' ' to a '\0' */
  --p;
  *p = '\0';

  if (strlen(human) != OTRNG_FPRINT_HUMAN_LEN - 1) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_serialize_fingerprint(
    otrng_fingerprint fp, const otrng_public_key long_term_pub_key,
    const otrng_public_key long_term_forging_pub_key) {
  uint8_t long_term_pub_ser[ED448_PUBKEY_BYTES];
  uint8_t long_term_forging_pub_ser[ED448_PUBKEY_BYTES];
  uint8_t usage_fingerprint = 0x00;
  goldilocks_shake256_ctx_p hd;

  memset(long_term_pub_ser, 0, ED448_POINT_BYTES);
  memset(long_term_forging_pub_ser, 0, ED448_POINT_BYTES);

  if (fp == NULL) {
    return OTRNG_ERROR;
  }

  if (otrng_serialize_public_key(long_term_pub_ser, long_term_pub_key) !=
      ED448_PUBKEY_BYTES) {
    return OTRNG_ERROR;
  }
  printf("\n INSIDE FAIL 1 \n");

  if (otrng_serialize_forging_key(long_term_forging_pub_ser,
                                  long_term_forging_pub_key) !=
      ED448_PUBKEY_BYTES) {
    return OTRNG_ERROR;
  }
  printf("\n INSIDE FAIL 1 \n");

  /* HWC(usage_fingerprint || byte(H) || byte(F), 56) */
  if (!hash_init_with_usage(hd, usage_fingerprint)) {
    return OTRNG_ERROR;
  }

  if (hash_update(hd, long_term_pub_ser, ED448_PUBKEY_BYTES) ==
      GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, long_term_forging_pub_ser, ED448_PUBKEY_BYTES) ==
      GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  hash_final(hd, fp, FPRINT_LEN_BYTES);
  hash_destroy(hd);

  return OTRNG_SUCCESS;
}

tstatic void otrng_known_fingerprint_free(otrng_known_fingerprint_s *kf) {
  otrng_free(kf->username);
  otrng_free(kf);
}

static void free_fp_proxy(void *kf) { otrng_known_fingerprint_free(kf); }

API void otrng_known_fingerprints_free(otrng_known_fingerprints_s *kf) {
  if (kf == NULL) {
    return;
  }
  otrng_list_free(kf->fps, free_fp_proxy);
  otrng_free(kf);
}

API /*@null@*/ otrng_known_fingerprint_s *
otrng_fingerprint_get_by_fp(const otrng_client_s *client,
                            const otrng_fingerprint fp) {
  list_element_s *c;
  assert(client != NULL);

  if (client->fingerprints == NULL) {
    return NULL;
  }

  for (c = client->fingerprints->fps; c; c = c->next) {
    otrng_known_fingerprint_s *kf = c->data;
    if (memcmp(fp, kf->fp, FPRINT_LEN_BYTES) == 0) {
      return kf;
    }
  }

  return NULL;
}

API /*@null@*/ otrng_known_fingerprint_s *
otrng_fingerprint_get_by_username(const otrng_client_s *client,
                                  const char *username) {
  list_element_s *c;
  assert(client != NULL);

  if (client->fingerprints == NULL) {
    return NULL;
  }

  for (c = client->fingerprints->fps; c; c = c->next) {
    otrng_known_fingerprint_s *kf = c->data;
    if (strcmp(username, kf->username) == 0) {
      return kf;
    }
  }

  return NULL;
}

API otrng_known_fingerprint_s *otrng_fingerprint_add(otrng_client_s *client,
                                                     const otrng_fingerprint fp,
                                                     const char *peer,
                                                     otrng_bool trusted) {
  otrng_known_fingerprint_s *nfp;
  assert(client != NULL);

  if (client->fingerprints == NULL) {
    client->fingerprints = otrng_xmalloc_z(sizeof(otrng_known_fingerprints_s));
  }

  nfp = otrng_xmalloc_z(sizeof(otrng_known_fingerprint_s));
  nfp->username = otrng_xstrdup(peer);
  nfp->trusted = trusted;
  memcpy(nfp->fp, fp, FPRINT_LEN_BYTES);

  client->fingerprints->fps = otrng_list_add(nfp, client->fingerprints->fps);

  return nfp;
}

API void otrng_fingerprints_do_all(const struct otrng_client_s *client,
                                   void (*fn)(const otrng_client_s *,
                                              otrng_known_fingerprint_s *,
                                              void *),
                                   void *context) {
  list_element_s *c;
  assert(client != NULL);

  if (client->fingerprints == NULL) {
    return;
  }

  for (c = client->fingerprints->fps; c; c = c->next) {
    fn(client, c->data, context);
  }
}

API void otrng_fingerprint_forget(const otrng_client_s *client,
                                  otrng_known_fingerprint_s *fp) {
  list_element_s *prev = NULL, *c, *work;
  assert(client != NULL);

  if (client->fingerprints == NULL) {
    return;
  }

  for (c = client->fingerprints->fps; c;) {
    otrng_known_fingerprint_s *kf = c->data;
    if (memcmp(fp->fp, kf->fp, FPRINT_LEN_BYTES) == 0 &&
        strcmp(fp->username, kf->username) == 0) {
      work = c;
      c = work->next;
      if (prev) {
        prev->next = c;
      } else {
        client->fingerprints->fps = c;
      }
      otrng_known_fingerprint_free(kf);
      otrng_free(work);
    } else {
      prev = c;
      c = c->next;
    }
  }
}

/* This returns the fingerprint of the peer, not the self.
 It only works properly if it's a v4 connection. */
API /*@null@*/ otrng_known_fingerprint_s *
otrng_fingerprint_get_current(const otrng_s *conn) {
  otrng_fingerprint fp;
  assert(conn != NULL);

  if (conn->their_client_profile == NULL) {
    return NULL;
  }

  if (otrng_failed(otrng_serialize_fingerprint(
          fp, conn->their_client_profile->long_term_pub_key,
          conn->their_client_profile->forging_pub_key))) {
    return NULL;
  }

  return otrng_fingerprint_get_by_fp(conn->client, fp);
}
