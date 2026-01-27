#ifndef TLV_H_
#define TLV_H_

#include <stdint.h>
#include <stdbool.h>

enum {
    TLV_MIN_SIZE = 2,
};

typedef struct Tlv {
    uint8_t tag;
    uint8_t len;
    uint8_t const* data;
} Tlv;

typedef struct TlvScan {
    uint8_t const* buf;
    uint16_t pos;
    uint16_t size;
    struct Tlv tlv;
} TlvScan;

typedef struct TlvCreator {
    uint8_t* buf;
    uint16_t size;
    uint16_t pos;
} TlvCreator;


int tlv__scan_init(struct TlvScan* scan, uint8_t const* buf, uint16_t size);
struct Tlv const* tlv__next(struct TlvScan* scan);
int tlv__reset_scan(struct TlvScan* scan);
struct Tlv const* tlv__find(struct TlvScan* scan, uint8_t tag);
struct Tlv const* tlv__find_subtag(struct TlvScan* scan, uint8_t tag, uint8_t subtag);

int tlv__to_u8(struct Tlv const* tlv, uint8_t* val);
int tlv__to_bool(struct Tlv const* tlv, bool* val);
int tlv__to_u16(struct Tlv const* tlv, uint16_t* val);
int tlv__to_u32(struct Tlv const* tlv, uint32_t* val);
int tlv__to_data(struct Tlv const* tlv, uint8_t* data, uint8_t data_size);
int tlv__to_data_exact(struct Tlv const* tlv, uint8_t* data, uint8_t data_size);
int tlv__to_str(struct Tlv const* tlv, char* str, uint8_t str_size);
int tlv__to_u8_subtag(struct Tlv const* tlv, uint8_t* val, uint8_t* subtag);
int tlv__to_bool_subtag(struct Tlv const* tlv, bool* val, uint8_t* subtag);
int tlv__to_u16_subtag(struct Tlv const* tlv, uint16_t* val, uint8_t* subtag);
int tlv__to_u32_subtag(struct Tlv const* tlv, uint32_t* val, uint8_t* subtag);
int tlv__to_data_subtag(struct Tlv const* tlv, uint8_t* data, uint8_t data_size, uint8_t* subtag);
int tlv__to_data_exact_subtag(struct Tlv const* tlv, uint8_t* data, uint8_t data_size, uint8_t* subtag);
int tlv__to_str_subtag(struct Tlv const* tlv, char* str, uint8_t str_size, uint8_t* subtag);

int tlv__find_u8(struct TlvScan* scan, uint8_t tag, uint8_t* val);
int tlv__find_bool(struct TlvScan* scan, uint8_t tag, bool* val);
int tlv__find_u16(struct TlvScan* scan, uint8_t tag, uint16_t* val);
int tlv__find_u32(struct TlvScan* scan, uint8_t tag, uint32_t* val);
int tlv__find_data(struct TlvScan* scan, uint8_t tag, uint8_t* data, uint8_t data_size);
int tlv__find_data_exact(struct TlvScan* scan, uint8_t tag, uint8_t* data, uint8_t data_size);
int tlv__find_str(struct TlvScan* scan, uint8_t tag, char* str, uint8_t str_size);
int tlv__find_u8_subtag(struct TlvScan* scan, uint8_t tag, uint8_t subtag, uint8_t* val);
int tlv__find_bool_subtag(struct TlvScan* scan, uint8_t tag, uint8_t subtag, bool* val);
int tlv__find_u16_subtag(struct TlvScan* scan, uint8_t tag, uint8_t subtag, uint16_t* val);
int tlv__find_u32_subtag(struct TlvScan* scan, uint8_t tag, uint8_t subtag, uint32_t* val);
int tlv__find_data_subtag(struct TlvScan* scan, uint8_t tag, uint8_t subtag, uint8_t* data, uint8_t data_size);
int tlv__find_data_exact_subtag(struct TlvScan* scan, uint8_t tag, uint8_t subtag, uint8_t* data, uint8_t data_size);
int tlv__find_str_subtag(struct TlvScan* scan, uint8_t tag, uint8_t subtag, char* str, uint8_t str_size);

int tlv__creator_init(struct TlvCreator* creator, uint8_t* buf, uint16_t size);
uint8_t* tlv__add_tag(struct TlvCreator* creator, uint8_t tag, uint8_t len);
uint8_t* tlv__add_tag_subtag(struct TlvCreator* creator, uint8_t tag, uint8_t subtag, uint8_t len);
int tlv__add_tag_i8(struct TlvCreator* creator, uint8_t tag, int8_t val);
int tlv__add_tag_u8(struct TlvCreator* creator, uint8_t tag, uint8_t val);
int tlv__add_tag_u8_subtag(struct TlvCreator* creator, uint8_t tag, uint8_t subtag, uint8_t val);
int tlv__add_tag_bool(struct TlvCreator* creator, uint8_t tag, bool val);
int tlv__add_tag_bool_subtag(struct TlvCreator* creator, uint8_t tag, uint8_t subtag, bool val);
int tlv__add_tag_u16(struct TlvCreator* creator, uint8_t tag, uint16_t val);
int tlv__add_tag_u16_subtag(struct TlvCreator* creator, uint8_t tag, uint8_t subtag, uint16_t val);
int tlv__add_tag_u32(struct TlvCreator* creator, uint8_t tag, uint32_t val);
int tlv__add_tag_u32_subtag(struct TlvCreator* creator, uint8_t tag, uint8_t subtag, uint32_t val);
int tlv__add_tag_data(struct TlvCreator* creator, uint8_t tag, uint8_t const* data, uint8_t data_size);
int tlv__add_tag_data_subtag(struct TlvCreator* creator, uint8_t tag, uint8_t subtag, uint8_t const* data, uint8_t data_size);
int tlv__add_tag_str(struct TlvCreator* creator, uint8_t tag, char const* str, uint8_t str_size);
int tlv__add_tag_str_subtag(struct TlvCreator* creator, uint8_t tag, uint8_t subtag, char const* str, uint8_t str_size);
uint16_t tlv__get_real_buf_size(struct TlvCreator const* creator);

#endif
