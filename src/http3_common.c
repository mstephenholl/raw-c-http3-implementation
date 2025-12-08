/*
 * HTTP/3 Implementation (RFC 9114)
 * Common utilities for frame handling, encoding, and logging
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include "http3.h"

static int g_log_level = LOG_LEVEL_DEBUG;

void h3_set_log_level(int level) {
    g_log_level = level;
}

void h3_log(int level, const char *component, const char *format, ...) {
    if (level < g_log_level) return;

    const char *level_str;
    switch (level) {
        case LOG_LEVEL_DEBUG: level_str = "DEBUG"; break;
        case LOG_LEVEL_INFO:  level_str = "INFO "; break;
        case LOG_LEVEL_WARN:  level_str = "WARN "; break;
        case LOG_LEVEL_ERROR: level_str = "ERROR"; break;
        default: level_str = "?????"; break;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(stderr, "[%s] [%s] [HTTP/3-%s] ", time_buf, level_str, component);

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fprintf(stderr, "\n");
    fflush(stderr);
}

const char *h3_frame_type_name(uint64_t type) {
    switch (type) {
        case H3_FRAME_DATA:         return "DATA";
        case H3_FRAME_HEADERS:      return "HEADERS";
        case H3_FRAME_CANCEL_PUSH:  return "CANCEL_PUSH";
        case H3_FRAME_SETTINGS:     return "SETTINGS";
        case H3_FRAME_PUSH_PROMISE: return "PUSH_PROMISE";
        case H3_FRAME_GOAWAY:       return "GOAWAY";
        case H3_FRAME_MAX_PUSH_ID:  return "MAX_PUSH_ID";
        default:                    return "UNKNOWN";
    }
}

const char *h3_error_name(uint64_t error) {
    switch (error) {
        case H3_NO_ERROR:               return "H3_NO_ERROR";
        case H3_GENERAL_PROTOCOL_ERROR: return "H3_GENERAL_PROTOCOL_ERROR";
        case H3_INTERNAL_ERROR:         return "H3_INTERNAL_ERROR";
        case H3_STREAM_CREATION_ERROR:  return "H3_STREAM_CREATION_ERROR";
        case H3_CLOSED_CRITICAL_STREAM: return "H3_CLOSED_CRITICAL_STREAM";
        case H3_FRAME_UNEXPECTED:       return "H3_FRAME_UNEXPECTED";
        case H3_FRAME_ERROR:            return "H3_FRAME_ERROR";
        case H3_EXCESSIVE_LOAD:         return "H3_EXCESSIVE_LOAD";
        case H3_ID_ERROR:               return "H3_ID_ERROR";
        case H3_SETTINGS_ERROR:         return "H3_SETTINGS_ERROR";
        case H3_MISSING_SETTINGS:       return "H3_MISSING_SETTINGS";
        case H3_REQUEST_REJECTED:       return "H3_REQUEST_REJECTED";
        case H3_REQUEST_CANCELLED:      return "H3_REQUEST_CANCELLED";
        case H3_REQUEST_INCOMPLETE:     return "H3_REQUEST_INCOMPLETE";
        case H3_MESSAGE_ERROR:          return "H3_MESSAGE_ERROR";
        case H3_CONNECT_ERROR:          return "H3_CONNECT_ERROR";
        case H3_VERSION_FALLBACK:       return "H3_VERSION_FALLBACK";
        default:                        return "UNKNOWN_ERROR";
    }
}

/*
 * Variable-length integer encoding (RFC 9000 Section 16)
 * Used extensively in QUIC and HTTP/3
 */
size_t h3_encode_varint(uint64_t value, uint8_t *buf, size_t buf_size) {
    if (value <= 63 && buf_size >= 1) {
        buf[0] = (uint8_t)value;
        return 1;
    } else if (value <= 16383 && buf_size >= 2) {
        buf[0] = (uint8_t)(0x40 | (value >> 8));
        buf[1] = (uint8_t)(value & 0xFF);
        return 2;
    } else if (value <= 1073741823 && buf_size >= 4) {
        buf[0] = (uint8_t)(0x80 | (value >> 24));
        buf[1] = (uint8_t)((value >> 16) & 0xFF);
        buf[2] = (uint8_t)((value >> 8) & 0xFF);
        buf[3] = (uint8_t)(value & 0xFF);
        return 4;
    } else if (buf_size >= 8) {
        buf[0] = (uint8_t)(0xC0 | (value >> 56));
        buf[1] = (uint8_t)((value >> 48) & 0xFF);
        buf[2] = (uint8_t)((value >> 40) & 0xFF);
        buf[3] = (uint8_t)((value >> 32) & 0xFF);
        buf[4] = (uint8_t)((value >> 24) & 0xFF);
        buf[5] = (uint8_t)((value >> 16) & 0xFF);
        buf[6] = (uint8_t)((value >> 8) & 0xFF);
        buf[7] = (uint8_t)(value & 0xFF);
        return 8;
    }
    return 0;
}

size_t h3_decode_varint(const uint8_t *buf, size_t buf_size, uint64_t *value) {
    if (buf_size < 1) return 0;

    uint8_t prefix = buf[0] >> 6;
    size_t length = 1 << prefix;

    if (buf_size < length) return 0;

    *value = buf[0] & 0x3F;
    for (size_t i = 1; i < length; i++) {
        *value = (*value << 8) | buf[i];
    }

    return length;
}

/*
 * HTTP/3 Frame encoding (Section 7.1)
 * Frame format: Type (varint) | Length (varint) | Payload
 */
size_t h3_encode_frame(const h3_frame_t *frame, uint8_t *buf, size_t buf_size) {
    size_t offset = 0;
    size_t n;

    /* Encode frame type */
    n = h3_encode_varint(frame->type, buf + offset, buf_size - offset);
    if (n == 0) return 0;
    offset += n;

    /* Encode frame length */
    n = h3_encode_varint(frame->length, buf + offset, buf_size - offset);
    if (n == 0) return 0;
    offset += n;

    /* Copy payload if present */
    if (frame->length > 0 && frame->payload) {
        if (offset + frame->length > buf_size) return 0;
        memcpy(buf + offset, frame->payload, frame->length);
        offset += frame->length;
    }

    return offset;
}

size_t h3_decode_frame(const uint8_t *buf, size_t buf_size, h3_frame_t *frame) {
    size_t offset = 0;
    size_t n;

    /* Decode frame type */
    n = h3_decode_varint(buf + offset, buf_size - offset, &frame->type);
    if (n == 0) return 0;
    offset += n;

    /* Decode frame length */
    n = h3_decode_varint(buf + offset, buf_size - offset, &frame->length);
    if (n == 0) return 0;
    offset += n;

    /* Point to payload */
    if (frame->length > 0) {
        if (offset + frame->length > buf_size) return 0;
        frame->payload = (uint8_t *)(buf + offset);
        offset += frame->length;
    } else {
        frame->payload = NULL;
    }

    return offset;
}

/*
 * Settings frame encoding (Section 7.2.4)
 */
size_t h3_encode_settings_frame(const h3_settings_t *settings, uint8_t *buf, size_t buf_size) {
    uint8_t payload[256];
    size_t payload_len = 0;
    size_t n;

    /* Encode SETTINGS_MAX_FIELD_SECTION_SIZE */
    n = h3_encode_varint(H3_SETTINGS_MAX_FIELD_SECTION_SIZE, payload + payload_len, sizeof(payload) - payload_len);
    if (n == 0) return 0;
    payload_len += n;
    n = h3_encode_varint(settings->max_field_section_size, payload + payload_len, sizeof(payload) - payload_len);
    if (n == 0) return 0;
    payload_len += n;

    /* Encode QPACK settings (set to 0 for simplified implementation) */
    n = h3_encode_varint(H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, payload + payload_len, sizeof(payload) - payload_len);
    if (n == 0) return 0;
    payload_len += n;
    n = h3_encode_varint(settings->qpack_max_table_capacity, payload + payload_len, sizeof(payload) - payload_len);
    if (n == 0) return 0;
    payload_len += n;

    n = h3_encode_varint(H3_SETTINGS_QPACK_BLOCKED_STREAMS, payload + payload_len, sizeof(payload) - payload_len);
    if (n == 0) return 0;
    payload_len += n;
    n = h3_encode_varint(settings->qpack_blocked_streams, payload + payload_len, sizeof(payload) - payload_len);
    if (n == 0) return 0;
    payload_len += n;

    /* Create frame */
    h3_frame_t frame = {
        .type = H3_FRAME_SETTINGS,
        .length = payload_len,
        .payload = payload
    };

    return h3_encode_frame(&frame, buf, buf_size);
}

int h3_decode_settings_frame(const uint8_t *payload, size_t length, h3_settings_t *settings) {
    size_t offset = 0;

    /* Initialize with defaults */
    settings->max_field_section_size = H3_DEFAULT_MAX_FIELD_SECTION_SIZE;
    settings->qpack_max_table_capacity = 0;
    settings->qpack_blocked_streams = 0;

    while (offset < length) {
        uint64_t id, value;
        size_t n;

        n = h3_decode_varint(payload + offset, length - offset, &id);
        if (n == 0) return -1;
        offset += n;

        n = h3_decode_varint(payload + offset, length - offset, &value);
        if (n == 0) return -1;
        offset += n;

        switch (id) {
            case H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
                settings->max_field_section_size = value;
                break;
            case H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
                settings->qpack_max_table_capacity = value;
                break;
            case H3_SETTINGS_QPACK_BLOCKED_STREAMS:
                settings->qpack_blocked_streams = value;
                break;
            default:
                /* Unknown settings are ignored per RFC */
                break;
        }
    }

    return 0;
}

/*
 * Simplified header encoding (not full QPACK, but demonstrates the concept)
 * Real QPACK would use Huffman encoding and dynamic tables
 * Format: Required Insert Count (0) | S bit + Delta Base (0) | then literal headers
 */
size_t h3_encode_headers(const h3_message_t *msg, uint8_t *buf, size_t buf_size, bool is_response) {
    size_t offset = 0;

    /* QPACK encoded field section prefix (simplified) */
    /* Required Insert Count = 0, Delta Base = 0 */
    if (offset + 2 > buf_size) return 0;
    buf[offset++] = 0x00;  /* Required Insert Count */
    buf[offset++] = 0x00;  /* S=0, Delta Base = 0 */

    /* Helper macro for encoding literal header with name */
    #define ENCODE_HEADER(name, value) do { \
        size_t name_len = strlen(name); \
        size_t value_len = strlen(value); \
        /* Literal with name reference = 0x20 | N bit (never indexed) */ \
        /* For simplicity, use literal without name reference (0x20) */ \
        if (offset + 1 + 1 + name_len + 1 + value_len > buf_size) return 0; \
        buf[offset++] = 0x20 | 0x08; /* Literal, never indexed, no name ref */ \
        buf[offset++] = (uint8_t)name_len; \
        memcpy(buf + offset, name, name_len); \
        offset += name_len; \
        buf[offset++] = (uint8_t)value_len; \
        memcpy(buf + offset, value, value_len); \
        offset += value_len; \
    } while(0)

    if (is_response) {
        /* Encode :status pseudo-header */
        char status_str[16];
        snprintf(status_str, sizeof(status_str), "%d", msg->status);
        ENCODE_HEADER(":status", status_str);
    } else {
        /* Encode request pseudo-headers */
        if (msg->method) ENCODE_HEADER(":method", msg->method);
        if (msg->scheme) ENCODE_HEADER(":scheme", msg->scheme);
        if (msg->authority) ENCODE_HEADER(":authority", msg->authority);
        if (msg->path) ENCODE_HEADER(":path", msg->path);
    }

    /* Encode regular headers */
    for (size_t i = 0; i < msg->header_count; i++) {
        ENCODE_HEADER(msg->headers[i].name, msg->headers[i].value);
    }

    #undef ENCODE_HEADER

    return offset;
}

int h3_decode_headers(const uint8_t *buf, size_t buf_size, h3_message_t *msg, bool is_response) {
    size_t offset = 0;

    h3_message_init(msg);

    /* Skip QPACK prefix (2 bytes minimum) */
    if (buf_size < 2) return -1;
    offset += 2;

    while (offset < buf_size) {
        /* Read header encoding byte */
        uint8_t first = buf[offset++];

        /* Simplified parsing - handle literal with literal name (0x2x) */
        if ((first & 0xF0) == 0x20) {
            if (offset >= buf_size) return -1;

            /* Name length */
            size_t name_len = buf[offset++];
            if (offset + name_len > buf_size) return -1;

            char *name = malloc(name_len + 1);
            memcpy(name, buf + offset, name_len);
            name[name_len] = '\0';
            offset += name_len;

            if (offset >= buf_size) { free(name); return -1; }

            /* Value length */
            size_t value_len = buf[offset++];
            if (offset + value_len > buf_size) { free(name); return -1; }

            char *value = malloc(value_len + 1);
            memcpy(value, buf + offset, value_len);
            value[value_len] = '\0';
            offset += value_len;

            /* Handle pseudo-headers */
            if (name[0] == ':') {
                if (strcmp(name, ":status") == 0) {
                    msg->status = atoi(value);
                    free(value);
                } else if (strcmp(name, ":method") == 0) {
                    msg->method = value;
                } else if (strcmp(name, ":scheme") == 0) {
                    msg->scheme = value;
                } else if (strcmp(name, ":authority") == 0) {
                    msg->authority = value;
                } else if (strcmp(name, ":path") == 0) {
                    msg->path = value;
                } else {
                    free(value);
                }
                free(name);
            } else {
                /* Regular header */
                h3_message_add_header(msg, name, value);
                free(name);
                free(value);
            }
        } else {
            /* Unknown encoding, skip */
            break;
        }
    }

    return 0;
}

void h3_message_init(h3_message_t *msg) {
    memset(msg, 0, sizeof(*msg));
}

void h3_message_free(h3_message_t *msg) {
    free(msg->method);
    free(msg->scheme);
    free(msg->authority);
    free(msg->path);

    for (size_t i = 0; i < msg->header_count; i++) {
        free(msg->headers[i].name);
        free(msg->headers[i].value);
    }
    free(msg->headers);
    free(msg->body);

    memset(msg, 0, sizeof(*msg));
}

int h3_message_add_header(h3_message_t *msg, const char *name, const char *value) {
    msg->headers = realloc(msg->headers, (msg->header_count + 1) * sizeof(h3_header_t));
    if (!msg->headers) return -1;

    msg->headers[msg->header_count].name = strdup(name);
    msg->headers[msg->header_count].value = strdup(value);
    msg->header_count++;

    return 0;
}

/*
 * Get human-readable name for SETTINGS parameter (RFC 9114 Section 7.2.4.1)
 */
const char *h3_settings_id_name(uint64_t id) {
    switch (id) {
        case H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
            return "SETTINGS_QPACK_MAX_TABLE_CAPACITY";
        case H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
            return "SETTINGS_MAX_FIELD_SECTION_SIZE";
        case H3_SETTINGS_QPACK_BLOCKED_STREAMS:
            return "SETTINGS_QPACK_BLOCKED_STREAMS";
        default:
            return "UNKNOWN_SETTING";
    }
}

/*
 * Get human-readable name for unidirectional stream type (RFC 9114 Section 6.2)
 */
const char *h3_stream_type_name(uint64_t type) {
    switch (type) {
        case H3_STREAM_TYPE_CONTROL:
            return "Control Stream";
        case H3_STREAM_TYPE_PUSH:
            return "Push Stream";
        case H3_STREAM_TYPE_QPACK_ENCODER:
            return "QPACK Encoder Stream";
        case H3_STREAM_TYPE_QPACK_DECODER:
            return "QPACK Decoder Stream";
        default:
            return "Unknown Stream Type";
    }
}

/*
 * Dump raw frame data as hex (RFC 9114 Section 7.1 frame format)
 * Format: Type (i) | Length (i) | Frame Payload (..)
 */
void h3_dump_frame_hex(const char *component, const char *direction,
                       const uint8_t *data, size_t len) {
    if (len == 0) return;

    /* Build hex string - limit to reasonable size for logging */
    size_t dump_len = len > 128 ? 128 : len;
    char hex_buf[512];
    size_t hex_offset = 0;

    for (size_t i = 0; i < dump_len && hex_offset < sizeof(hex_buf) - 4; i++) {
        hex_offset += snprintf(hex_buf + hex_offset, sizeof(hex_buf) - hex_offset,
                               "%02x ", data[i]);
    }
    if (len > dump_len) {
        snprintf(hex_buf + hex_offset, sizeof(hex_buf) - hex_offset, "...");
    }

    h3_log(LOG_LEVEL_DEBUG, component,
           "[RFC 9114] %s Frame (raw hex, %zu bytes): %s",
           direction, len, hex_buf);
}

/*
 * Dump translated frame using RFC 9114 terminology
 */
void h3_dump_frame_translated(const char *component, const char *direction,
                              const h3_frame_t *frame, int64_t stream_id) {
    h3_log(LOG_LEVEL_DEBUG, component,
           "[RFC 9114 Section 7.2] %s Frame on Stream %lld:",
           direction, (long long)stream_id);
    h3_log(LOG_LEVEL_DEBUG, component,
           "  Frame Type: 0x%02llx (%s)",
           (unsigned long long)frame->type, h3_frame_type_name(frame->type));
    h3_log(LOG_LEVEL_DEBUG, component,
           "  Frame Length: %llu bytes (payload size per Section 7.1)",
           (unsigned long long)frame->length);

    /* Additional interpretation based on frame type */
    switch (frame->type) {
        case H3_FRAME_DATA:
            /* RFC 9114 Section 7.2.1 - DATA frames carry request/response body */
            h3_log(LOG_LEVEL_DEBUG, component,
                   "  Interpretation: DATA frame carries HTTP message body (Section 7.2.1)");
            if (frame->payload && frame->length > 0) {
                /* Show preview of body content */
                size_t preview_len = frame->length > 64 ? 64 : frame->length;
                char preview[128];
                size_t j = 0;
                for (size_t i = 0; i < preview_len && j < sizeof(preview) - 4; i++) {
                    if (frame->payload[i] >= 32 && frame->payload[i] < 127) {
                        preview[j++] = frame->payload[i];
                    } else {
                        preview[j++] = '.';
                    }
                }
                preview[j] = '\0';
                h3_log(LOG_LEVEL_DEBUG, component,
                       "  Body Preview: \"%s\"%s",
                       preview, frame->length > preview_len ? "..." : "");
            }
            break;

        case H3_FRAME_HEADERS:
            /* RFC 9114 Section 7.2.2 - HEADERS frames carry encoded field sections */
            h3_log(LOG_LEVEL_DEBUG, component,
                   "  Interpretation: HEADERS frame carries QPACK-encoded field section (Section 7.2.2)");
            break;

        case H3_FRAME_SETTINGS:
            /* RFC 9114 Section 7.2.4 - SETTINGS convey configuration parameters */
            h3_log(LOG_LEVEL_DEBUG, component,
                   "  Interpretation: SETTINGS frame conveys configuration parameters (Section 7.2.4)");
            if (frame->payload && frame->length > 0) {
                h3_settings_t settings;
                if (h3_decode_settings_frame(frame->payload, frame->length, &settings) == 0) {
                    h3_dump_settings_translated(component, &settings);
                }
            }
            break;

        case H3_FRAME_GOAWAY:
            /* RFC 9114 Section 7.2.6 - GOAWAY initiates graceful shutdown */
            h3_log(LOG_LEVEL_DEBUG, component,
                   "  Interpretation: GOAWAY frame initiates graceful connection shutdown (Section 7.2.6)");
            if (frame->payload && frame->length > 0) {
                uint64_t stream_id_val;
                if (h3_decode_varint(frame->payload, frame->length, &stream_id_val) > 0) {
                    h3_log(LOG_LEVEL_DEBUG, component,
                           "  Last Stream ID: %llu", (unsigned long long)stream_id_val);
                }
            }
            break;

        case H3_FRAME_CANCEL_PUSH:
            /* RFC 9114 Section 7.2.3 */
            h3_log(LOG_LEVEL_DEBUG, component,
                   "  Interpretation: CANCEL_PUSH frame cancels server push (Section 7.2.3)");
            break;

        case H3_FRAME_PUSH_PROMISE:
            /* RFC 9114 Section 7.2.5 */
            h3_log(LOG_LEVEL_DEBUG, component,
                   "  Interpretation: PUSH_PROMISE frame reserves server push (Section 7.2.5)");
            break;

        case H3_FRAME_MAX_PUSH_ID:
            /* RFC 9114 Section 7.2.7 */
            h3_log(LOG_LEVEL_DEBUG, component,
                   "  Interpretation: MAX_PUSH_ID frame controls server push (Section 7.2.7)");
            break;

        default:
            h3_log(LOG_LEVEL_DEBUG, component,
                   "  Interpretation: Unknown/reserved frame type (Section 7.2.8)");
            break;
    }
}

/*
 * Dump decoded headers using RFC 9114 terminology
 */
void h3_dump_headers_translated(const char *component, const h3_message_t *msg,
                                bool is_response) {
    h3_log(LOG_LEVEL_DEBUG, component,
           "[RFC 9114 Section 4.1] Decoded Header Field Section:");

    if (is_response) {
        /* Response pseudo-headers (Section 4.1.2) */
        h3_log(LOG_LEVEL_DEBUG, component,
               "  Message Type: Response (Section 4.1.2)");
        h3_log(LOG_LEVEL_DEBUG, component,
               "  :status = %d (required response pseudo-header)", msg->status);
    } else {
        /* Request pseudo-headers (Section 4.1.1) */
        h3_log(LOG_LEVEL_DEBUG, component,
               "  Message Type: Request (Section 4.1.1)");
        if (msg->method) {
            h3_log(LOG_LEVEL_DEBUG, component,
                   "  :method = %s (required request pseudo-header)", msg->method);
        }
        if (msg->scheme) {
            h3_log(LOG_LEVEL_DEBUG, component,
                   "  :scheme = %s (required for non-CONNECT requests)", msg->scheme);
        }
        if (msg->authority) {
            h3_log(LOG_LEVEL_DEBUG, component,
                   "  :authority = %s (target URI authority)", msg->authority);
        }
        if (msg->path) {
            h3_log(LOG_LEVEL_DEBUG, component,
                   "  :path = %s (target URI path)", msg->path);
        }
    }

    /* Regular headers */
    if (msg->header_count > 0) {
        h3_log(LOG_LEVEL_DEBUG, component,
               "  Regular Header Fields (%zu total):", msg->header_count);
        for (size_t i = 0; i < msg->header_count; i++) {
            h3_log(LOG_LEVEL_DEBUG, component,
                   "    %s: %s", msg->headers[i].name, msg->headers[i].value);
        }
    }
}

/*
 * Dump SETTINGS parameters using RFC 9114 Section 7.2.4.1 terminology
 */
void h3_dump_settings_translated(const char *component, const h3_settings_t *settings) {
    h3_log(LOG_LEVEL_DEBUG, component,
           "[RFC 9114 Section 7.2.4.1] SETTINGS Parameters:");
    h3_log(LOG_LEVEL_DEBUG, component,
           "  SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01) = %llu",
           (unsigned long long)settings->qpack_max_table_capacity);
    h3_log(LOG_LEVEL_DEBUG, component,
           "    -> Maximum dynamic table capacity for QPACK encoder");
    h3_log(LOG_LEVEL_DEBUG, component,
           "  SETTINGS_MAX_FIELD_SECTION_SIZE (0x06) = %llu",
           (unsigned long long)settings->max_field_section_size);
    h3_log(LOG_LEVEL_DEBUG, component,
           "    -> Maximum size of a field section the peer will accept");
    h3_log(LOG_LEVEL_DEBUG, component,
           "  SETTINGS_QPACK_BLOCKED_STREAMS (0x07) = %llu",
           (unsigned long long)settings->qpack_blocked_streams);
    h3_log(LOG_LEVEL_DEBUG, component,
           "    -> Maximum number of streams that can be blocked on QPACK");
}
