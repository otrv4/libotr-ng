#include <stdlib.h>

#include "deserialize.h"
#include "tlv.h"

static
tlv_t *extract_tlv(const uint8_t * src, size_t len, size_t * written)
{
	size_t w = 0;
	tlv_t *tlv = NULL;
	const uint8_t *cursor = src;

	do {
		tlv = malloc(sizeof(tlv_t));
		if (!tlv)
			continue;

		if (!deserialize_uint16(&tlv->type, cursor, len, &w))
			continue;

		len -= w;
		cursor += w;

		if (!deserialize_uint16(&tlv->len, cursor, len, &w))
			continue;

		len -= w;
		cursor += w;

		if (len < tlv->len)
			continue;

		tlv->data = malloc(tlv->len);
		if (!tlv->data)
			continue;

		memcpy(tlv->data, cursor, tlv->len);
		len -= tlv->len;
		cursor += tlv->len;

		if (written)
			*written = cursor - src;

		tlv->next = NULL;
		return tlv;
	} while (0);

	free(tlv);
	return NULL;
}

tlv_t *otrv4_parse_tlvs(const uint8_t * src, size_t len)
{
	size_t written = 0;
	tlv_t *tlv = NULL, *ret = NULL;

	while (len > 0) {
		tlv = extract_tlv(src + written, len, &written);
		if (!tlv)
			break;

		len -= written;

		if (ret)
			ret->next = tlv;
		else
			ret = tlv;
	}

	return ret;
}

tlv_t *otrv4_tlv_free(tlv_t * tlv)
{
	if (!tlv)
		return NULL;

	free(tlv->data);
	tlv->data = NULL;
	free(tlv);

	//TODO: free nexts

	return NULL;
}

tlv_t *otrv4_tlv_new(uint16_t type, uint16_t len, uint8_t * data)
{
	tlv_t *tlv = malloc(sizeof(tlv_t));
	if (!tlv)
		return NULL;

	tlv->type = type;
	tlv->len = len;
	tlv->next = NULL;
	tlv->data = malloc(tlv->len);

	if (!tlv->data)
		return otrv4_tlv_free(tlv);

	memcpy(tlv->data, data, tlv->len);
	return tlv;
}

tlv_t *otrv4_padding_tlv_new(size_t len)
{
	uint8_t *data = malloc(len);
	if (!data)
		return NULL;

	tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_PADDING, len, data);
	free(data);

	return tlv;
}

tlv_t *otrv4_disconnected_tlv_new(void)
{
	return otrv4_tlv_new(OTRV4_TLV_DISCONNECTED, 0, NULL);
}
