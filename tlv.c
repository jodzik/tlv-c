#include "tlv.h"

#include "../serdes/serdes.h"
#include "../safe-c/safe_c.h"

#include <stdlib.h>
#include <string.h>

int tlv__scan_init(struct TlvScan* const scan, uint8_t const* const buf, uint16_t const size) {
    if (size < TLV_MIN_SIZE) {
        return -1;
    }

    scan->buf = buf;
    scan->pos = 0;
    scan->size = size;

    return 0;
}

Tlv const* tlv__next(struct TlvScan* const scan) {
    if (scan->size - scan->pos < TLV_MIN_SIZE) {
        return NULL;
    }

    scan->tlv.tag = scan->buf[scan->pos];
    scan->tlv.len = scan->buf[scan->pos+1];
    scan->tlv.data = &scan->buf[scan->pos+2];

    if (scan->pos + scan->tlv.len + 2 > scan->size) {
        return NULL;
    }

    scan->pos += scan->tlv.len + 2;

    return &scan->tlv;
}

void tlv__reset_scan(struct TlvScan* const scan) {
    scan->pos = 0;
}

struct Tlv const* tlv__find(struct TlvScan* scan, uint8_t const tag) {
    struct Tlv const* tlv = NULL;

    tlv__reset_scan(scan);

    while (tlv = tlv__next(scan)) {
        if (tlv->tag == tag) {
            return tlv;
        }
    }

    return NULL;
}

int tlv__to_u8(struct TlvScan* const scan, uint8_t const tag, uint8_t* const val) {
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    ASSERTs(sizeof(*val) == tlv->len, ER_INVAL);
    *val = tlv->data[0];
    return 0;
}

int tlv__to_bool(struct TlvScan* const scan, uint8_t const tag, bool* const val) {
    uint8_t val_raw = 0;
    TRYs(tlv__to_u8(scan, tag, &val_raw));
    *val = val_raw > 0 ? true : false;
    return 0;
}

int tlv__to_u16(struct TlvScan* const scan, uint8_t const tag, uint16_t* const val) {
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    ASSERTs(sizeof(*val) == tlv->len, ER_INVAL);
    *val = u16_from_be(tlv->data);
    return 0;
}

int tlv__to_u32(struct TlvScan* const scan, uint8_t const tag, uint32_t* const val) {
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    ASSERTs(sizeof(*val) == tlv->len, ER_INVAL);
    *val = u32_from_be(tlv->data);
    return 0;
}

int tlv__to_data(struct TlvScan* const scan, uint8_t const tag, uint8_t* const data, uint8_t const data_size) {
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    ASSERTs(tlv->len <= data_size, ER_OVERFLOW);
    memcpy(data, tlv->data, tlv->len);
    return 0;
}

int tlv__to_data_exact(struct TlvScan* const scan, uint8_t const tag, uint8_t* const data, uint8_t const data_size) {
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    ASSERTs(tlv->len == data_size, ER_INVAL);
    memcpy(data, tlv->data, tlv->len);
    return 0;
}

int tlv__to_str(struct TlvScan* scan, uint8_t tag, char* str, uint8_t str_size) {
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    ASSERTs(tlv->len < str_size, ER_OVERFLOW);
    memset(str, 0, str_size);
    memcpy(str, tlv->data, tlv->len);
    return 0;
}


int tlv__creator_init(struct TlvCreator* creator, uint8_t* buf, uint16_t size) {
    if (NULL == creator) {
        return ER_1;
    }
    if (size < TLV_MIN_SIZE) {
        return ER_2;
    }
    creator->buf = buf;
    creator->size = size;
    creator->pos = 0;

    return 0;
}

uint8_t* tlv__add_tag(struct TlvCreator* creator, uint8_t tag, uint8_t len) {
    if (creator->pos + TLV_MIN_SIZE + len > creator->size) {
        return NULL;
    }
    creator->buf[creator->pos] = tag;
    creator->pos++;
    creator->buf[creator->pos] = len;
    creator->pos++;
    creator->pos += len;
    return &creator->buf[creator->pos - len];
}

int tlv__add_tag_u8(struct TlvCreator* const creator, uint8_t const tag, uint8_t const val) {
    uint8_t* const tlv_data = tlv__add_tag(creator, tag, sizeof(val));
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    tlv_data[0] = val;

    return 0;
}

int tlv__add_tag_bool(struct TlvCreator* const creator, uint8_t const tag, bool const val) {
    TRYs(tlv__add_tag_u8(creator, tag, val ? 1 : 0));

    return 0;
}

int tlv__add_tag_u16(struct TlvCreator* const creator, uint8_t const tag, uint16_t const val) {
    uint8_t* const tlv_data = tlv__add_tag(creator, tag, sizeof(val));
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    u16_to_be(tlv_data, val);

    return 0;
}

int tlv__add_tag_u32(struct TlvCreator* const creator, uint8_t const tag, uint32_t const val) {
    uint8_t* const tlv_data = tlv__add_tag(creator, tag, sizeof(val));
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    u32_to_be(tlv_data, val);

    return 0;
}

int tlv__add_tag_data(
    struct TlvCreator* const creator,
    uint8_t const tag,
    uint8_t const* const data,
    uint8_t const data_size)
{
    uint8_t* const tlv_data = tlv__add_tag(creator, tag, data_size);
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    memcpy(tlv_data, data, data_size);

    return 0;
}

int tlv__add_tag_str(
    struct TlvCreator* const creator,
    uint8_t const tag,
    char const* const str,
    uint8_t const str_size)
{
    uint8_t const str_len = (uint8_t)strnlen(str, str_size - 1);
    uint8_t* const tlv_data = tlv__add_tag(creator, tag, str_len);
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    memcpy(tlv_data, str, str_len);

    return 0;
}

uint16_t tlv__get_real_buf_size(struct TlvCreator const* creator) {
    return creator->pos;
}
