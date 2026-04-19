#include "tlv.h"

#include <byteorder.h>
#include <safe_c.h>

#include <stdlib.h>
#include <string.h>

#ifdef __ZEPHYR__
LOG_MODULE_REGISTER(tlv_c);
#endif

int tlv__scan_init(struct TlvScan* const scan, uint8_t const* const buf, uint16_t const size) {
    ASSERT(NULL != scan, ER_INVAL);
    ASSERT(NULL != buf, ER_INVAL);
    ASSERT(size >= TLV_MIN_SIZE, ER_INVAL);

    scan->buf = buf;
    scan->pos = 0;
    scan->size = size;

    return 0;
}

struct Tlv const* tlv__next(struct TlvScan* const scan) {
    int rc = 0;
    ASSERT_EX(NULL != scan, ER_INVAL);

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

 finally:

    return 0 == rc ? &scan->tlv : NULL;
}

int tlv__reset_scan(struct TlvScan* const scan) {
    ASSERT(NULL != scan, ER_INVAL);
    scan->pos = 0;
    return 0;
}

struct Tlv const* tlv__find(struct TlvScan* scan, uint8_t const tag) {
    int rc = 0;

    ASSERT_EX(NULL != scan, ER_INVAL);
    TRY_EX(tlv__reset_scan(scan));

    while (true) {
        struct Tlv const* const tlv = tlv__next(scan);
        if (NULL == tlv) {
            break;
        }
        if (tlv->tag == tag) {
            return tlv;
        }
    }

 finally:

 	UNUSED(rc);
    return NULL;
}

struct Tlv const* tlv__find_subtag(struct TlvScan* scan, uint8_t tag, uint8_t subtag) {
    return NULL;
}

int tlv__to_u8(struct Tlv const* tlv, uint8_t* val) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != val, ER_INVAL);
    ASSERTs(sizeof(*val) == tlv->len, ER_INVAL);
    *val = tlv->data[0];
    return 0;
}

int tlv__to_bool(struct Tlv const* tlv, bool* val) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != val, ER_INVAL);
    ASSERTs(sizeof(uint8_t) == tlv->len, ER_INVAL);
    *val = (bool)tlv->data[0];
    return 0;
}

int tlv__to_u16(struct Tlv const* tlv, uint16_t* val) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != val, ER_INVAL);
    ASSERTs(sizeof(*val) == tlv->len, ER_INVAL);
    *val = u16_from_be(tlv->data);
    return 0;
}

int tlv__to_u32(struct Tlv const* tlv, uint32_t* val) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != val, ER_INVAL);
    ASSERTs(sizeof(*val) == tlv->len, ER_INVAL);
    *val = u32_from_be(tlv->data);
    return 0;
}

int tlv__to_data(struct Tlv const* tlv, uint8_t* data, uint8_t data_size) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != data, ER_INVAL);
    ASSERTs(data_size >= tlv->len, ER_INVAL);
    memcpy(data, tlv->data, tlv->len);
    return 0;
}

int tlv__to_data_exact(struct Tlv const* tlv, uint8_t* data, uint8_t data_size) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != data, ER_INVAL);
    ASSERTs(data_size == tlv->len, ER_INVAL);
    memcpy(data, tlv->data, tlv->len);
    return 0;
}

int tlv__to_str(struct Tlv const* tlv, char* str, uint8_t str_size) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != str, ER_INVAL);
    {
        uint8_t tlv_str_len = 0;
        if (tlv->len > 0 && '\0' == tlv->data[tlv->len - 1]) {
            tlv_str_len = tlv->len - 1;
        } else {
            tlv_str_len = tlv->len;
        }
        ASSERTs(str_size > tlv_str_len, ER_INVAL);
        strlcpy(str, tlv->data, str_size);
    }

    return 0;
}

int tlv__to_u8_subtag(struct Tlv const* tlv, uint8_t* val, uint8_t* subtag) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != val, ER_INVAL);
    ASSERT(NULL != subtag, ER_INVAL);
    ASSERTs(sizeof(*val) + 1 == tlv->len, ER_INVAL);
    *subtag = tlv->data[0];
    *val = tlv->data[1];
    return 0;
}

int tlv__to_bool_subtag(struct Tlv const* tlv, bool* val, uint8_t* subtag) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != val, ER_INVAL);
    ASSERT(NULL != subtag, ER_INVAL);
    ASSERTs(sizeof(uint8_t) + 1 == tlv->len, ER_INVAL);
    *subtag = tlv->data[0];
    *val = (bool)tlv->data[1];
    return 0;
}

int tlv__to_u16_subtag(struct Tlv const* tlv, uint16_t* val, uint8_t* subtag) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != val, ER_INVAL);
    ASSERT(NULL != subtag, ER_INVAL);
    ASSERTs(sizeof(*val) + 1 == tlv->len, ER_INVAL);
    *subtag = tlv->data[0];
    *val = u16_from_be(&tlv->data[1]);
    return 0;
}

int tlv__to_u32_subtag(struct Tlv const* tlv, uint32_t* val, uint8_t* subtag) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != val, ER_INVAL);
    ASSERT(NULL != subtag, ER_INVAL);
    ASSERTs(sizeof(*val) + 1 == tlv->len, ER_INVAL);
    *subtag = tlv->data[0];
    *val = u32_from_be(&tlv->data[1]);
    return 0;
}

int tlv__to_data_subtag(struct Tlv const* tlv, uint8_t* data, uint8_t data_size, uint8_t* subtag) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != data, ER_INVAL);
    ASSERT(NULL != subtag, ER_INVAL);
    ASSERTs(data_size + 1 >= tlv->len, ER_INVAL);
    *subtag = tlv->data[0];
    memcpy(data, &tlv->data[1], tlv->len - 1);
    return 0;
}

int tlv__to_data_exact_subtag(struct Tlv const* tlv, uint8_t* data, uint8_t data_size, uint8_t* subtag) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != data, ER_INVAL);
    ASSERT(NULL != subtag, ER_INVAL);
    ASSERTs(data_size + 1 == tlv->len, ER_INVAL);
    *subtag = tlv->data[0];
    memcpy(data, &tlv->data[1], tlv->len - 1);
    return 0;
}

int tlv__to_str_subtag(struct Tlv const* tlv, char* str, uint8_t str_size, uint8_t* subtag) {
    ASSERT(NULL != tlv, ER_INVAL);
    ASSERT(NULL != str, ER_INVAL);
    ASSERT(NULL != subtag, ER_INVAL);
    ASSERT(tlv->len > 0, ER_INVAL);

    {
        uint8_t tlv_str_len = 0;
        if (tlv->len > 1 && '\0' == tlv->data[tlv->len - 1]) {
            tlv_str_len = tlv->len - 2;
        } else {
            tlv_str_len = tlv->len - 1;
        }
        ASSERTs(str_size > tlv_str_len, ER_INVAL);
        strlcpy(str, &tlv->data[1], str_size);
    }

    return 0;
}

int tlv__find_u8(struct TlvScan* const scan, uint8_t const tag, uint8_t* const val) {
    ASSERT(NULL != scan, ER_INVAL);
    ASSERT(NULL != val, ER_INVAL);
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    return tlv__to_u8(tlv, val);
}

int tlv__find_bool(struct TlvScan* const scan, uint8_t const tag, bool* const val) {
    ASSERT(NULL != scan, ER_INVAL);
    ASSERT(NULL != val, ER_INVAL);
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    return tlv__to_bool(tlv, val);
}

int tlv__find_u16(struct TlvScan* const scan, uint8_t const tag, uint16_t* const val) {
    ASSERT(NULL != scan, ER_INVAL);
    ASSERT(NULL != val, ER_INVAL);
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    return tlv__to_u16(tlv, val);
}

int tlv__find_u32(struct TlvScan* const scan, uint8_t const tag, uint32_t* const val) {
    ASSERT(NULL != scan, ER_INVAL);
    ASSERT(NULL != val, ER_INVAL);
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    return tlv__to_u32(tlv, val);
}

int tlv__find_data(struct TlvScan* const scan, uint8_t const tag, uint8_t* const data, uint8_t const data_size) {
    ASSERT(NULL != scan, ER_INVAL);
    ASSERT(NULL != data, ER_INVAL);
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    return tlv__to_data(tlv, data, data_size);
}

int tlv__find_data_exact(struct TlvScan* const scan, uint8_t const tag, uint8_t* const data, uint8_t const data_size) {
    ASSERT(NULL != scan, ER_INVAL);
    ASSERT(NULL != data, ER_INVAL);
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    return tlv__to_data_exact(tlv, data, data_size);
}

int tlv__find_str(struct TlvScan* scan, uint8_t tag, char* str, uint8_t str_size) {
    ASSERT(NULL != scan, ER_INVAL);
    ASSERT(NULL != str, ER_INVAL);
    struct Tlv const* const tlv = tlv__find(scan, tag);
    ASSERTs(NULL != tlv, ER_NO_ENT);
    return tlv__to_str(tlv, str, str_size);
}


int tlv__creator_init(struct TlvCreator* creator, uint8_t* buf, uint16_t size) {
    ASSERT(NULL != creator, ER_INVAL);
    ASSERT(size >= TLV_MIN_SIZE, ER_INVAL);

    creator->buf = buf;
    creator->size = size;
    creator->pos = 0;

    return 0;
}

uint8_t* tlv__add_tag(struct TlvCreator* creator, uint8_t tag, uint8_t len) {
    int rc = 0;
    ASSERT_EX(NULL != creator, ER_INVAL);
    if (creator->pos + TLV_MIN_SIZE + len > creator->size) {
        return NULL;
    }
    creator->buf[creator->pos] = tag;
    creator->pos++;
    creator->buf[creator->pos] = len;
    creator->pos++;
    creator->pos += len;

 finally:

    return 0 == rc ? &creator->buf[creator->pos - len] : NULL;
}

uint8_t* tlv__add_tag_subtag(
    struct TlvCreator* creator,
    uint8_t const tag,
    uint8_t const subtag,
    uint8_t const len)
{
    int rc = 0;
    ASSERT_EX(NULL != creator, ER_INVAL);
    uint8_t* const data = tlv__add_tag(creator, tag, len + 1);
    if (NULL == data) {
        return NULL;
    }
    data[0] = subtag;

    return &data[1];

 finally:

 	UNUSED(rc);
    return NULL;
}

int tlv__add_tag_i8(struct TlvCreator* const creator, uint8_t const tag, int8_t const val) {
    ASSERT(NULL != creator, ER_INVAL);
    uint8_t* const tlv_data = tlv__add_tag(creator, tag, sizeof(val));
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    memcpy(tlv_data, &val, sizeof(val));

    return 0;
}

int tlv__add_tag_u8(struct TlvCreator* const creator, uint8_t const tag, uint8_t const val) {
    ASSERT(NULL != creator, ER_INVAL);
    uint8_t* const tlv_data = tlv__add_tag(creator, tag, sizeof(val));
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    tlv_data[0] = val;

    return 0;
}

int tlv__add_tag_u8_subtag(
    struct TlvCreator* const creator,
    uint8_t const tag,
    uint8_t const subtag,
    uint8_t const val)
{
    ASSERT(NULL != creator, ER_INVAL);
    uint8_t* const tlv_data = tlv__add_tag_subtag(creator, tag, subtag, sizeof(val));
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    tlv_data[0] = val;

    return 0;
}

int tlv__add_tag_bool(struct TlvCreator* const creator, uint8_t const tag, bool const val) {
    ASSERT(NULL != creator, ER_INVAL);

    TRYs(tlv__add_tag_u8(creator, tag, val ? 1 : 0));

    return 0;
}

int tlv__add_tag_bool_subtag(struct TlvCreator* const creator, uint8_t const tag, uint8_t subtag, bool const val) {
    ASSERT(NULL != creator, ER_INVAL);

    TRYs(tlv__add_tag_u8_subtag(creator, tag, subtag, val ? 1 : 0));

    return 0;
}

int tlv__add_tag_u16(struct TlvCreator* const creator, uint8_t const tag, uint16_t const val) {
    ASSERT(NULL != creator, ER_INVAL);ASSERT(NULL != creator, ER_INVAL);
    uint8_t* const tlv_data = tlv__add_tag(creator, tag, sizeof(val));
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    u16_to_be(tlv_data, val);

    return 0;
}

int tlv__add_tag_u16_subtag(
    struct TlvCreator* const creator,
    uint8_t const tag,
    uint8_t const subtag,
    uint16_t const val)
{
    ASSERT(NULL != creator, ER_INVAL);
    uint8_t* const tlv_data = tlv__add_tag_subtag(creator, tag, subtag, sizeof(val));
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    u16_to_be(tlv_data, val);

    return 0;
}

int tlv__add_tag_u32(struct TlvCreator* const creator, uint8_t const tag, uint32_t const val) {
    ASSERT(NULL != creator, ER_INVAL);
    uint8_t* const tlv_data = tlv__add_tag(creator, tag, sizeof(val));
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    u32_to_be(tlv_data, val);

    return 0;
}

int tlv__add_tag_u32_subtag(
    struct TlvCreator* const creator,
    uint8_t const tag,
    uint8_t const subtag,
    uint32_t const val)
{
    ASSERT(NULL != creator, ER_INVAL);
    uint8_t* const tlv_data = tlv__add_tag_subtag(creator, tag, subtag, sizeof(val));
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
    ASSERT(NULL != creator, ER_INVAL);
    uint8_t* const tlv_data = tlv__add_tag(creator, tag, data_size);
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    memcpy(tlv_data, data, data_size);

    return 0;
}

int tlv__add_tag_data_subtag(
    struct TlvCreator* const creator,
    uint8_t const tag,
    uint8_t const subtag,
    uint8_t const* const data,
    uint8_t const data_size)
{
    ASSERT(NULL != creator, ER_INVAL);
    uint8_t* const tlv_data = tlv__add_tag_subtag(creator, tag, subtag, data_size);
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
    ASSERT(NULL != creator, ER_INVAL);
    ASSERT(NULL != str, ER_INVAL);
    uint8_t const str_len = (uint8_t)strnlen(str, str_size - 1);
    uint8_t* const tlv_data = tlv__add_tag(creator, tag, str_len);
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    memcpy(tlv_data, str, str_len);

    return 0;
}

int tlv__add_tag_str_subtag(
    struct TlvCreator* const creator,
    uint8_t const tag,
    uint8_t const subtag,
    char const* const str,
    uint8_t const str_size)
{
    ASSERT(NULL != creator, ER_INVAL);
    ASSERT(NULL != str, ER_INVAL);
    uint8_t const str_len = (uint8_t)strnlen(str, str_size - 1);
    uint8_t* const tlv_data = tlv__add_tag_subtag(creator, tag, subtag, str_len);
    ASSERTs(tlv_data != NULL, ER_OVERFLOW);
    memcpy(tlv_data, str, str_len);

    return 0;
}

uint16_t tlv__get_real_buf_size(struct TlvCreator const* creator) {
    return creator ? creator->pos : 0;
}
