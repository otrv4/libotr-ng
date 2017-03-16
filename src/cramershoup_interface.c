#include "cramershoup_interface.h"

#include "b64.h"
#include "ed448.h"

void
cs_public_key_copy(cs_public_key_t *dst, const cs_public_key_t *src) {
  ec_point_copy(dst->c, src->c);
  ec_point_copy(dst->d, src->d);
  ec_point_copy(dst->h, src->h);
}

int
cs_serialize_private_key(char **dst, size_t *len, const cs_private_key_t *priv) {
    size_t s = 4*6 + 5*(((DECAF_448_SCALAR_BYTES+2)/3)*4);
    char *buff = malloc(s);
    if (!buff)
        return -1;

    unsigned char scalar[DECAF_448_SCALAR_BYTES] = {0};
    char *cursor = buff;

    memcpy(cursor, "x1: ", 4);
    cursor += 4;

    memset(scalar, 0, DECAF_448_SCALAR_BYTES);
    decaf_448_scalar_encode(scalar, priv->x1);
    cursor += otrl_base64_encode(cursor, scalar, sizeof(scalar));
    *(cursor++) = '\n';

    memcpy(cursor, "x2: ", 4);
    cursor += 4;

    memset(scalar, 0, DECAF_448_SCALAR_BYTES);
    decaf_448_scalar_encode(scalar, priv->x2);
    cursor += otrl_base64_encode(cursor, scalar, sizeof(scalar));
    *(cursor++) = '\n';

    memcpy(cursor, "y1: ", 4);
    cursor += 4;

    memset(scalar, 0, DECAF_448_SCALAR_BYTES);
    decaf_448_scalar_encode(scalar, priv->y1);
    cursor += otrl_base64_encode(cursor, scalar, sizeof(scalar));
    *(cursor++) = '\n';

    memcpy(cursor, "y2: ", 4);
    cursor += 4;

    memset(scalar, 0, DECAF_448_SCALAR_BYTES);
    decaf_448_scalar_encode(scalar, priv->y2);
    cursor += otrl_base64_encode(cursor, scalar, sizeof(scalar));
    *(cursor++) = '\n';

    memcpy(cursor, "z: ", 3);
    cursor += 3;

    memset(scalar, 0, DECAF_448_SCALAR_BYTES);
    decaf_448_scalar_encode(scalar, priv->z);
    cursor += otrl_base64_encode(cursor, scalar, sizeof(scalar));
    *(cursor++) = '\n';

    *dst = buff;
    *len = cursor - buff;
    return 0;
}
