/*
 * HTTP/3 Implementation (RFC 9114)
 * Common header file with frame types, error codes, and utilities
 */

#ifndef HTTP3_H
#define HTTP3_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* HTTP/3 Frame Types (Section 7.2) */
#define H3_FRAME_DATA           0x00
#define H3_FRAME_HEADERS        0x01
#define H3_FRAME_CANCEL_PUSH    0x03
#define H3_FRAME_SETTINGS       0x04
#define H3_FRAME_PUSH_PROMISE   0x05
#define H3_FRAME_GOAWAY         0x07
#define H3_FRAME_MAX_PUSH_ID    0x0D

/* HTTP/3 Settings Parameters (Section 7.2.4.1) */
#define H3_SETTINGS_MAX_FIELD_SECTION_SIZE  0x06
#define H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY 0x01
#define H3_SETTINGS_QPACK_BLOCKED_STREAMS   0x07

/* HTTP/3 Stream Types (Section 6.2) */
#define H3_STREAM_TYPE_CONTROL      0x00
#define H3_STREAM_TYPE_PUSH         0x01
#define H3_STREAM_TYPE_QPACK_ENCODER 0x02
#define H3_STREAM_TYPE_QPACK_DECODER 0x03

/* HTTP/3 Error Codes (Section 8.1) */
#define H3_NO_ERROR                 0x0100
#define H3_GENERAL_PROTOCOL_ERROR   0x0101
#define H3_INTERNAL_ERROR           0x0102
#define H3_STREAM_CREATION_ERROR    0x0103
#define H3_CLOSED_CRITICAL_STREAM   0x0104
#define H3_FRAME_UNEXPECTED         0x0105
#define H3_FRAME_ERROR              0x0106
#define H3_EXCESSIVE_LOAD           0x0107
#define H3_ID_ERROR                 0x0108
#define H3_SETTINGS_ERROR           0x0109
#define H3_MISSING_SETTINGS         0x010A
#define H3_REQUEST_REJECTED         0x010B
#define H3_REQUEST_CANCELLED        0x010C
#define H3_REQUEST_INCOMPLETE       0x010D
#define H3_MESSAGE_ERROR            0x010E
#define H3_CONNECT_ERROR            0x010F
#define H3_VERSION_FALLBACK         0x0110

/* Maximum sizes */
#define H3_MAX_FRAME_SIZE           (16 * 1024)
#define H3_MAX_HEADER_SIZE          (8 * 1024)
#define H3_DEFAULT_MAX_FIELD_SECTION_SIZE 16384

/* Logging levels */
#define LOG_LEVEL_DEBUG     0
#define LOG_LEVEL_INFO      1
#define LOG_LEVEL_WARN      2
#define LOG_LEVEL_ERROR     3

/* HTTP/3 Frame structure */
typedef struct {
    uint64_t type;
    uint64_t length;
    uint8_t *payload;
} h3_frame_t;

/* HTTP/3 Settings */
typedef struct {
    uint64_t max_field_section_size;
    uint64_t qpack_max_table_capacity;
    uint64_t qpack_blocked_streams;
} h3_settings_t;

/* HTTP/3 Header field */
typedef struct {
    char *name;
    char *value;
} h3_header_t;

/* HTTP/3 Request/Response */
typedef struct {
    /* Pseudo-headers for request */
    char *method;
    char *scheme;
    char *authority;
    char *path;

    /* Pseudo-header for response */
    int status;

    /* Regular headers */
    h3_header_t *headers;
    size_t header_count;

    /* Body */
    uint8_t *body;
    size_t body_length;
} h3_message_t;

/* Variable-length integer encoding/decoding (QUIC style) */
size_t h3_encode_varint(uint64_t value, uint8_t *buf, size_t buf_size);
size_t h3_decode_varint(const uint8_t *buf, size_t buf_size, uint64_t *value);

/* Frame encoding/decoding */
size_t h3_encode_frame(const h3_frame_t *frame, uint8_t *buf, size_t buf_size);
size_t h3_decode_frame(const uint8_t *buf, size_t buf_size, h3_frame_t *frame);

/* Settings frame helpers */
size_t h3_encode_settings_frame(const h3_settings_t *settings, uint8_t *buf, size_t buf_size);
int h3_decode_settings_frame(const uint8_t *payload, size_t length, h3_settings_t *settings);

/* Simple QPACK-like header encoding (simplified for demonstration) */
size_t h3_encode_headers(const h3_message_t *msg, uint8_t *buf, size_t buf_size, bool is_response);
int h3_decode_headers(const uint8_t *buf, size_t buf_size, h3_message_t *msg, bool is_response);

/* Logging */
void h3_log(int level, const char *component, const char *format, ...);
void h3_set_log_level(int level);

/* Utility functions */
const char *h3_frame_type_name(uint64_t type);
const char *h3_error_name(uint64_t error);
const char *h3_settings_id_name(uint64_t id);
const char *h3_stream_type_name(uint64_t type);
void h3_message_init(h3_message_t *msg);
void h3_message_free(h3_message_t *msg);
int h3_message_add_header(h3_message_t *msg, const char *name, const char *value);

/* Debug logging helpers (RFC 9114 terminology) */
void h3_dump_frame_hex(const char *component, const char *direction,
                       const uint8_t *data, size_t len);
void h3_dump_frame_translated(const char *component, const char *direction,
                              const h3_frame_t *frame, int64_t stream_id);
void h3_dump_headers_translated(const char *component, const h3_message_t *msg,
                                bool is_response);
void h3_dump_settings_translated(const char *component, const h3_settings_t *settings);

#endif /* HTTP3_H */
