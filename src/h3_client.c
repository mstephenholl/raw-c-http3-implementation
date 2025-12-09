/*
 * HTTP/3 Client Implementation (RFC 9114)
 * Uses ngtcp2 for QUIC transport and implements HTTP/3 framing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/select.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#if __has_include(<ngtcp2/ngtcp2_crypto_quictls.h>)
#include <ngtcp2/ngtcp2_crypto_quictls.h>
#else
#include <ngtcp2/ngtcp2_crypto_openssl.h>
#endif

#include "http3.h"

#define DEFAULT_PORT 4433
#define MAX_DATAGRAM_SIZE 1350
#define MAX_STREAMS 100
#define CONNECTION_TIMEOUT 10

static volatile sig_atomic_t running = 1;

/* Client context */
typedef struct {
    int fd;
    SSL_CTX *ssl_ctx;
    ngtcp2_conn *conn;
    SSL *ssl;
    struct sockaddr_storage server_addr;
    socklen_t server_addrlen;
    ngtcp2_crypto_conn_ref conn_ref;

    /* HTTP/3 state */
    h3_settings_t settings;
    int64_t control_stream_id;
    int64_t qpack_encoder_stream_id;
    int64_t qpack_decoder_stream_id;
    bool control_stream_opened;
    bool settings_sent;
    bool settings_received;
    bool handshake_completed;

    /* Request/Response state */
    int64_t request_stream_id;
    bool request_sent;
    bool response_received;
    h3_message_t response;

    /* Configuration */
    const char *host;
    const char *path;
    const char *method;

    /* Receive buffer */
    uint8_t recv_buf[65536];
    size_t recv_buf_len;
} client_ctx_t;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

static uint64_t get_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

static void rand_bytes(uint8_t *data, size_t len) {
    RAND_bytes(data, (int)len);
}

/* ngtcp2 callbacks */

static int client_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                                   int64_t stream_id, uint64_t offset,
                                   const uint8_t *data, size_t datalen,
                                   void *user_data, void *stream_user_data) {
    (void)conn;
    (void)flags;
    (void)offset;
    (void)stream_user_data;
    client_ctx_t *ctx = user_data;

    h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Received %zu bytes on stream %ld",
           datalen, stream_id);

    /* Dump raw hex at debug level */
    h3_dump_frame_hex("CLIENT", "Received", data, datalen);

    /* Check if this is a unidirectional stream from the server */
    bool is_uni = (stream_id & 0x2) != 0;
    bool is_server_initiated = (stream_id & 0x1) != 0;

    if (is_uni && is_server_initiated) {
        /* Server-initiated unidirectional stream - control or QPACK stream */
        if (datalen > 0) {
            uint64_t stream_type;
            size_t consumed = h3_decode_varint(data, datalen, &stream_type);
            if (consumed > 0) {
                h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Server unidirectional stream type: 0x%lx (%s)",
                       (unsigned long)stream_type, h3_stream_type_name(stream_type));
                h3_log(LOG_LEVEL_DEBUG, "CLIENT",
                       "[RFC 9114 Section 6.2] Unidirectional Stream Type: %s (0x%02lx)",
                       h3_stream_type_name(stream_type), (unsigned long)stream_type);

                if (stream_type == H3_STREAM_TYPE_CONTROL) {
                    h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Received server CONTROL stream");
                    h3_log(LOG_LEVEL_DEBUG, "CLIENT",
                           "[RFC 9114 Section 6.2.1] Control stream carries frames affecting entire connection");

                    /* Parse SETTINGS frame */
                    if (datalen > consumed) {
                        h3_frame_t frame;
                        size_t frame_len = h3_decode_frame(data + consumed, datalen - consumed, &frame);
                        if (frame_len > 0 && frame.type == H3_FRAME_SETTINGS) {
                            h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Received SETTINGS frame (len=%lu)",
                                   (unsigned long)frame.length);

                            /* Debug: dump frame details */
                            h3_dump_frame_translated("CLIENT", "Received", &frame, stream_id);

                            h3_settings_t server_settings;
                            h3_decode_settings_frame(frame.payload, frame.length, &server_settings);
                            ctx->settings_received = true;
                            h3_log(LOG_LEVEL_INFO, "CLIENT",
                                   "[HTTP/3] Server settings: max_field_section_size=%lu",
                                   (unsigned long)server_settings.max_field_section_size);
                        }
                    }
                } else if (stream_type == H3_STREAM_TYPE_QPACK_ENCODER) {
                    h3_log(LOG_LEVEL_DEBUG, "CLIENT", "[HTTP/3] Received server QPACK encoder stream");
                    h3_log(LOG_LEVEL_DEBUG, "CLIENT",
                           "[RFC 9114 Section 6.2.3] QPACK encoder stream for dynamic table updates");
                } else if (stream_type == H3_STREAM_TYPE_QPACK_DECODER) {
                    h3_log(LOG_LEVEL_DEBUG, "CLIENT", "[HTTP/3] Received server QPACK decoder stream");
                    h3_log(LOG_LEVEL_DEBUG, "CLIENT",
                           "[RFC 9114 Section 6.2.3] QPACK decoder stream for acknowledgments");
                }
            }
        }
    } else if (stream_id == ctx->request_stream_id) {
        /* Response on our request stream */
        h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Processing response on stream %ld", stream_id);
        h3_log(LOG_LEVEL_DEBUG, "CLIENT",
               "[RFC 9114 Section 4.1] Request stream %lld carries HTTP response message",
               (long long)stream_id);

        /* Parse HTTP/3 frames */
        size_t offset_local = 0;

        while (offset_local < datalen) {
            h3_frame_t frame;
            size_t frame_len = h3_decode_frame(data + offset_local, datalen - offset_local, &frame);
            if (frame_len == 0) break;

            h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Frame: type=%s (0x%lx), length=%lu",
                   h3_frame_type_name(frame.type), (unsigned long)frame.type, (unsigned long)frame.length);

            /* Debug: dump raw frame hex and translation */
            h3_dump_frame_hex("CLIENT", "Received", data + offset_local, frame_len);
            h3_dump_frame_translated("CLIENT", "Received", &frame, stream_id);

            if (frame.type == H3_FRAME_HEADERS) {
                h3_decode_headers(frame.payload, frame.length, &ctx->response, true);
                h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Response status: %d", ctx->response.status);

                /* Debug: dump decoded headers with RFC terminology */
                h3_dump_headers_translated("CLIENT", &ctx->response, true);

                /* Log response headers */
                for (size_t i = 0; i < ctx->response.header_count; i++) {
                    h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Header: %s: %s",
                           ctx->response.headers[i].name, ctx->response.headers[i].value);
                }
            } else if (frame.type == H3_FRAME_DATA) {
                h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Response body (%zu bytes):",
                       (size_t)frame.length);

                /* Store body */
                ctx->response.body = realloc(ctx->response.body,
                                             ctx->response.body_length + frame.length + 1);
                memcpy(ctx->response.body + ctx->response.body_length, frame.payload, frame.length);
                ctx->response.body_length += frame.length;
                ctx->response.body[ctx->response.body_length] = '\0';

                /* Print body content (use length-limited format to avoid reading past buffer) */
                printf("\n========== Response Body ==========\n");
                printf("%.*s", (int)frame.length, (char *)frame.payload);
                printf("\n===================================\n\n");

                ctx->response_received = true;
            }

            offset_local += frame_len;
        }
    }

    return 0;
}

static int client_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                           uint64_t offset, uint64_t datalen,
                                           void *user_data, void *stream_user_data) {
    (void)conn;
    (void)stream_id;
    (void)offset;
    (void)datalen;
    (void)user_data;
    (void)stream_user_data;
    return 0;
}

static int client_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    (void)conn;
    client_ctx_t *ctx = user_data;

    bool is_bidi = (stream_id & 0x2) == 0;
    bool is_client = (stream_id & 0x1) == 0;

    h3_log(LOG_LEVEL_DEBUG, "CLIENT", "Stream opened: %ld (%s, %s-initiated)",
           stream_id,
           is_bidi ? "bidirectional" : "unidirectional",
           is_client ? "client" : "server");

    return 0;
}

static int client_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                               uint64_t app_error_code, void *user_data,
                               void *stream_user_data) {
    (void)conn;
    (void)flags;
    (void)stream_user_data;
    client_ctx_t *ctx = user_data;

    h3_log(LOG_LEVEL_DEBUG, "CLIENT", "Stream %ld closed with error code %lu",
           stream_id, (unsigned long)app_error_code);

    if (stream_id == ctx->request_stream_id) {
        h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Request stream closed");
        if (ctx->response.status > 0) {
            ctx->response_received = true;
        }
    }

    return 0;
}

static void client_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    (void)rand_ctx;
    rand_bytes(dest, destlen);
}

static int client_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                        uint8_t *token, size_t cidlen,
                                        void *user_data) {
    (void)conn;
    (void)user_data;
    rand_bytes(cid->data, cidlen);
    cid->datalen = cidlen;
    rand_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}


static int client_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data, void *user_data) {
    (void)conn;
    (void)user_data;
    rand_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN);
    return 0;
}

static int client_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    client_ctx_t *ctx = user_data;

    h3_log(LOG_LEVEL_INFO, "CLIENT", "[QUIC] Handshake completed!");
    h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Connection established via QUIC");
    ctx->handshake_completed = true;

    return 0;
}

static ngtcp2_conn *get_conn_from_ref(ngtcp2_crypto_conn_ref *ref) {
    client_ctx_t *ctx = (client_ctx_t *)ref->user_data;
    return ctx->conn;
}



static void setup_ssl_ctx(client_ctx_t *ctx) {
    ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx->ssl_ctx) {
        h3_log(LOG_LEVEL_ERROR, "CLIENT", "Failed to create SSL_CTX");
        exit(1);
    }

    /* Configure SSL context for QUIC using ngtcp2 helper.
     * This sets up SSL_QUIC_METHOD with callbacks that handle encryption secrets. */
    if (ngtcp2_crypto_quictls_configure_client_context(ctx->ssl_ctx) != 0) {
        h3_log(LOG_LEVEL_ERROR, "CLIENT", "Failed to configure SSL context for QUIC");
        exit(1);
    }

    /* Allow self-signed certificates for testing */
    SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);

    h3_log(LOG_LEVEL_INFO, "CLIENT", "SSL context initialized");
}

static int open_client_streams(client_ctx_t *ctx) {
    int rv;

    /* Open control stream (client-initiated unidirectional) */
    rv = ngtcp2_conn_open_uni_stream(ctx->conn, &ctx->control_stream_id, NULL);
    if (rv != 0) {
        h3_log(LOG_LEVEL_ERROR, "CLIENT", "Failed to open control stream: %d", rv);
        return rv;
    }
    h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Opened control stream: %ld", ctx->control_stream_id);

    /* Open QPACK encoder stream */
    rv = ngtcp2_conn_open_uni_stream(ctx->conn, &ctx->qpack_encoder_stream_id, NULL);
    if (rv != 0) {
        h3_log(LOG_LEVEL_ERROR, "CLIENT", "Failed to open QPACK encoder stream: %d", rv);
        return rv;
    }
    h3_log(LOG_LEVEL_DEBUG, "CLIENT", "[HTTP/3] Opened QPACK encoder stream: %ld",
           ctx->qpack_encoder_stream_id);

    /* Open QPACK decoder stream */
    rv = ngtcp2_conn_open_uni_stream(ctx->conn, &ctx->qpack_decoder_stream_id, NULL);
    if (rv != 0) {
        h3_log(LOG_LEVEL_ERROR, "CLIENT", "Failed to open QPACK decoder stream: %d", rv);
        return rv;
    }
    h3_log(LOG_LEVEL_DEBUG, "CLIENT", "[HTTP/3] Opened QPACK decoder stream: %ld",
           ctx->qpack_decoder_stream_id);

    ctx->control_stream_opened = true;
    return 0;
}

static int send_settings(client_ctx_t *ctx) {
    if (ctx->settings_sent) return 0;

    /* Prepare control stream data: stream type + SETTINGS frame */
    uint8_t control_data[256];
    size_t offset = 0;

    /* Stream type */
    offset += h3_encode_varint(H3_STREAM_TYPE_CONTROL, control_data + offset,
                               sizeof(control_data) - offset);

    /* SETTINGS frame */
    ctx->settings.max_field_section_size = H3_DEFAULT_MAX_FIELD_SECTION_SIZE;
    ctx->settings.qpack_max_table_capacity = 0;
    ctx->settings.qpack_blocked_streams = 0;
    offset += h3_encode_settings_frame(&ctx->settings, control_data + offset,
                                       sizeof(control_data) - offset);

    h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Sending SETTINGS frame on control stream");

    /* Debug: dump outgoing SETTINGS */
    h3_dump_frame_hex("CLIENT", "Sending", control_data, offset);
    h3_log(LOG_LEVEL_DEBUG, "CLIENT",
           "[RFC 9114 Section 6.2.1] Control stream type 0x00 followed by SETTINGS frame");
    h3_dump_settings_translated("CLIENT", &ctx->settings);

    /* Write control stream data (stream type + SETTINGS) */
    ngtcp2_vec control_vec = { .base = control_data, .len = offset };
    int64_t control_written;
    uint8_t pktbuf[MAX_DATAGRAM_SIZE];

    ngtcp2_ssize pktlen = ngtcp2_conn_writev_stream(ctx->conn, NULL, NULL, pktbuf,
                                                    sizeof(pktbuf), &control_written,
                                                    NGTCP2_WRITE_STREAM_FLAG_NONE,
                                                    ctx->control_stream_id, &control_vec, 1,
                                                    get_timestamp());
    if (pktlen > 0) {
        sendto(ctx->fd, pktbuf, pktlen, 0,
               (struct sockaddr *)&ctx->server_addr, ctx->server_addrlen);
        h3_log(LOG_LEVEL_DEBUG, "CLIENT", "[HTTP/3] Control stream data sent: %zu bytes", offset);
    }

    /* Send QPACK encoder stream type */
    uint8_t qpack_enc_data[8];
    size_t enc_len = h3_encode_varint(H3_STREAM_TYPE_QPACK_ENCODER, qpack_enc_data, sizeof(qpack_enc_data));

    ngtcp2_vec enc_vec = { .base = qpack_enc_data, .len = enc_len };
    int64_t enc_written;
    pktlen = ngtcp2_conn_writev_stream(ctx->conn, NULL, NULL, pktbuf,
                                       sizeof(pktbuf), &enc_written,
                                       NGTCP2_WRITE_STREAM_FLAG_NONE,
                                       ctx->qpack_encoder_stream_id, &enc_vec, 1,
                                       get_timestamp());
    if (pktlen > 0) {
        sendto(ctx->fd, pktbuf, pktlen, 0,
               (struct sockaddr *)&ctx->server_addr, ctx->server_addrlen);
    }

    /* Send QPACK decoder stream type */
    uint8_t qpack_dec_data[8];
    size_t dec_len = h3_encode_varint(H3_STREAM_TYPE_QPACK_DECODER, qpack_dec_data, sizeof(qpack_dec_data));

    ngtcp2_vec dec_vec = { .base = qpack_dec_data, .len = dec_len };
    int64_t dec_written;
    pktlen = ngtcp2_conn_writev_stream(ctx->conn, NULL, NULL, pktbuf,
                                       sizeof(pktbuf), &dec_written,
                                       NGTCP2_WRITE_STREAM_FLAG_NONE,
                                       ctx->qpack_decoder_stream_id, &dec_vec, 1,
                                       get_timestamp());
    if (pktlen > 0) {
        sendto(ctx->fd, pktbuf, pktlen, 0,
               (struct sockaddr *)&ctx->server_addr, ctx->server_addrlen);
    }

    ctx->settings_sent = true;
    return 0;
}

static int send_request(client_ctx_t *ctx) {
    if (ctx->request_sent) return 0;

    int rv;

    /* Open request stream (client-initiated bidirectional) */
    rv = ngtcp2_conn_open_bidi_stream(ctx->conn, &ctx->request_stream_id, NULL);
    if (rv != 0) {
        h3_log(LOG_LEVEL_ERROR, "CLIENT", "Failed to open request stream: %d", rv);
        return rv;
    }
    h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Opened request stream: %ld", ctx->request_stream_id);

    /* Build HTTP/3 request */
    h3_message_t request;
    h3_message_init(&request);
    request.method = strdup(ctx->method);
    request.scheme = strdup("https");
    request.authority = strdup(ctx->host);
    request.path = strdup(ctx->path);
    h3_message_add_header(&request, "user-agent", "http3-c-client/1.0");
    h3_message_add_header(&request, "accept", "*/*");

    h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Sending request: %s https://%s%s",
           request.method, request.authority, request.path);

    /* Debug: dump request headers with RFC terminology */
    h3_dump_headers_translated("CLIENT", &request, false);

    /* Encode HEADERS frame */
    uint8_t headers_payload[1024];
    size_t headers_len = h3_encode_headers(&request, headers_payload, sizeof(headers_payload), false);

    uint8_t frame_buf[2048];
    size_t frame_offset = 0;

    /* HEADERS frame */
    h3_frame_t headers_frame = {
        .type = H3_FRAME_HEADERS,
        .length = headers_len,
        .payload = headers_payload
    };
    frame_offset += h3_encode_frame(&headers_frame, frame_buf + frame_offset,
                                    sizeof(frame_buf) - frame_offset);

    /* Debug: dump outgoing frame */
    h3_dump_frame_hex("CLIENT", "Sending", frame_buf, frame_offset);
    h3_dump_frame_translated("CLIENT", "Sending", &headers_frame, ctx->request_stream_id);

    /* Write request to stream */
    ngtcp2_vec vec = { .base = frame_buf, .len = frame_offset };
    int64_t written;
    uint8_t pktbuf[MAX_DATAGRAM_SIZE];

    ngtcp2_ssize pktlen = ngtcp2_conn_writev_stream(ctx->conn, NULL, NULL, pktbuf,
                                                    sizeof(pktbuf), &written,
                                                    NGTCP2_WRITE_STREAM_FLAG_FIN,
                                                    ctx->request_stream_id, &vec, 1,
                                                    get_timestamp());
    if (pktlen > 0) {
        ssize_t sent = sendto(ctx->fd, pktbuf, pktlen, 0,
                              (struct sockaddr *)&ctx->server_addr, ctx->server_addrlen);
        if (sent < 0) {
            h3_log(LOG_LEVEL_ERROR, "CLIENT", "sendto() failed: %s", strerror(errno));
        } else {
            h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Request sent: %zu bytes", frame_offset);
        }
    }

    h3_message_free(&request);
    ctx->request_sent = true;
    return 0;
}

static int resolve_host(const char *host, int port, struct sockaddr_storage *addr,
                        socklen_t *addrlen) {
    struct addrinfo hints = {0};
    struct addrinfo *res;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int rv = getaddrinfo(host, port_str, &hints, &res);
    if (rv != 0) {
        h3_log(LOG_LEVEL_ERROR, "CLIENT", "getaddrinfo(%s) failed: %s", host, gai_strerror(rv));
        return -1;
    }

    memcpy(addr, res->ai_addr, res->ai_addrlen);
    *addrlen = res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}

static int create_client_socket(struct sockaddr_storage *addr, socklen_t addrlen) {
    int fd = socket(addr->ss_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        h3_log(LOG_LEVEL_ERROR, "CLIENT", "socket() failed: %s", strerror(errno));
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options] <host> [path]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p <port>     Server port (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  -m <method>   HTTP method (default: GET)\n");
    fprintf(stderr, "  -h            Show this help\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  %s localhost /\n", prog);
    fprintf(stderr, "  %s -p 4433 server.example.com /api/test\n", prog);
}

int main(int argc, char **argv) {
    const char *host = NULL;
    const char *path = "/";
    const char *method = "GET";
    int port = DEFAULT_PORT;

    int opt;
    while ((opt = getopt(argc, argv, "p:m:h")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'm':
                method = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: host is required\n");
        print_usage(argv[0]);
        return 1;
    }

    host = argv[optind];
    if (optind + 1 < argc) {
        path = argv[optind + 1];
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    h3_log(LOG_LEVEL_INFO, "CLIENT", "========================================");
    h3_log(LOG_LEVEL_INFO, "CLIENT", "HTTP/3 Client (RFC 9114) starting...");
    h3_log(LOG_LEVEL_INFO, "CLIENT", "========================================");
    h3_log(LOG_LEVEL_INFO, "CLIENT", "Host: %s", host);
    h3_log(LOG_LEVEL_INFO, "CLIENT", "Port: %d", port);
    h3_log(LOG_LEVEL_INFO, "CLIENT", "Path: %s", path);
    h3_log(LOG_LEVEL_INFO, "CLIENT", "Method: %s", method);

    client_ctx_t ctx = {0};
    ctx.control_stream_id = -1;
    ctx.qpack_encoder_stream_id = -1;
    ctx.qpack_decoder_stream_id = -1;
    ctx.request_stream_id = -1;
    ctx.host = host;
    ctx.path = path;
    ctx.method = method;
    h3_message_init(&ctx.response);

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Note: ngtcp2_crypto_quictls_init() is deprecated in newer versions
     * The crypto callbacks are set up automatically by ngtcp2_crypto_quictls_configure_client_context() */

    /* Setup SSL context */
    setup_ssl_ctx(&ctx);

    /* Resolve server address */
    if (resolve_host(host, port, &ctx.server_addr, &ctx.server_addrlen) < 0) {
        return 1;
    }

    /* Create UDP socket */
    ctx.fd = create_client_socket(&ctx.server_addr, ctx.server_addrlen);
    if (ctx.fd < 0) {
        return 1;
    }

    h3_log(LOG_LEVEL_INFO, "CLIENT", "[QUIC] Connecting to %s:%d", host, port);

    /* Setup ngtcp2 connection - use built-in crypto callbacks */
    ngtcp2_callbacks callbacks = {
        .client_initial = ngtcp2_crypto_client_initial_cb,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
        .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb,
        .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .recv_retry = ngtcp2_crypto_recv_retry_cb,
        .recv_stream_data = client_recv_stream_data,
        .acked_stream_data_offset = client_acked_stream_data_offset,
        .stream_open = client_stream_open,
        .stream_close = client_stream_close,
        .rand = client_rand,
        .get_new_connection_id = client_get_new_connection_id,
        .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .get_path_challenge_data = client_get_path_challenge_data,
        .handshake_completed = client_handshake_completed,
    };

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = get_timestamp();
    settings.log_printf = NULL;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = MAX_STREAMS;
    params.initial_max_streams_uni = MAX_STREAMS;
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_data = 1024 * 1024;
    params.max_idle_timeout = 30 * NGTCP2_SECONDS;

    /* Generate connection IDs */
    ngtcp2_cid scid, dcid;
    rand_bytes(scid.data, NGTCP2_MAX_CIDLEN);
    scid.datalen = NGTCP2_MAX_CIDLEN;
    rand_bytes(dcid.data, NGTCP2_MAX_CIDLEN);
    dcid.datalen = NGTCP2_MAX_CIDLEN;

    /* Get local address */
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen = sizeof(local_addr);

    /* Bind to get local address - match the server's address family */
    if (ctx.server_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 local_bind = {0};
        local_bind.sin6_family = AF_INET6;
        local_bind.sin6_addr = in6addr_any;
        local_bind.sin6_port = 0;
        bind(ctx.fd, (struct sockaddr *)&local_bind, sizeof(local_bind));
    } else {
        struct sockaddr_in local_bind = {0};
        local_bind.sin_family = AF_INET;
        local_bind.sin_addr.s_addr = INADDR_ANY;
        local_bind.sin_port = 0;
        bind(ctx.fd, (struct sockaddr *)&local_bind, sizeof(local_bind));
    }
    getsockname(ctx.fd, (struct sockaddr *)&local_addr, &local_addrlen);

    ngtcp2_path path_obj = {
        .local = { .addr = (struct sockaddr *)&local_addr, .addrlen = local_addrlen },
        .remote = { .addr = (struct sockaddr *)&ctx.server_addr, .addrlen = ctx.server_addrlen }
    };

    /* Create ngtcp2 connection FIRST (following official examples order) */
    int rv = ngtcp2_conn_client_new(&ctx.conn, &dcid, &scid, &path_obj,
                                    NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                    &params, NULL, &ctx);
    if (rv != 0) {
        h3_log(LOG_LEVEL_ERROR, "CLIENT", "ngtcp2_conn_client_new failed: %d", rv);
        return 1;
    }

    /* Create SSL object AFTER ngtcp2 connection */
    ctx.ssl = SSL_new(ctx.ssl_ctx);
    SSL_set_connect_state(ctx.ssl);
    SSL_set_tlsext_host_name(ctx.ssl, host);

    /* Set ALPN for HTTP/3 */
    static const unsigned char alpn[] = "\x02h3";
    SSL_set_alpn_protos(ctx.ssl, alpn, sizeof(alpn) - 1);

    /* Set up crypto connection reference
     * user_data points to our client context, and get_conn retrieves the ngtcp2_conn from it */
    ctx.conn_ref.get_conn = get_conn_from_ref;
    ctx.conn_ref.user_data = &ctx;
    SSL_set_app_data(ctx.ssl, &ctx.conn_ref);

    /* Link the TLS native handle to the ngtcp2 connection */
    ngtcp2_conn_set_tls_native_handle(ctx.conn, ctx.ssl);

    /* Note: Transport params are set by ngtcp2_crypto_client_initial_cb during first write_pkt */

    h3_log(LOG_LEVEL_INFO, "CLIENT", "[QUIC] Connection created, starting handshake...");

    /* Main event loop */
    uint8_t buf[MAX_DATAGRAM_SIZE];
    time_t start_time = time(NULL);

    while (running && !ctx.response_received) {
        /* Check for timeout */
        if (time(NULL) - start_time > CONNECTION_TIMEOUT && !ctx.handshake_completed) {
            h3_log(LOG_LEVEL_ERROR, "CLIENT", "Connection timeout");
            break;
        }

        /* Write packets (including Initial) */
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi = {0};

        for (;;) {
            ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(
                ctx.conn, &ps.path, &pi, buf, sizeof(buf), get_timestamp());

            if (nwrite < 0) {
                if (nwrite != NGTCP2_ERR_WRITE_MORE) {
                    if (nwrite != 0) {
                        h3_log(LOG_LEVEL_ERROR, "CLIENT", "ngtcp2_conn_write_pkt error: %s (%zd)",
                               ngtcp2_strerror((int)nwrite), nwrite);
                        /* Print OpenSSL error if any */
                        unsigned long ssl_err;
                        while ((ssl_err = ERR_get_error()) != 0) {
                            char err_buf[256];
                            ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
                            h3_log(LOG_LEVEL_ERROR, "CLIENT", "OpenSSL error: %s", err_buf);
                        }
                    }
                    break;
                }
                continue;
            }
            if (nwrite == 0) {
                break;  /* Nothing to send */
            }

            h3_log(LOG_LEVEL_INFO, "CLIENT", "[QUIC] Sending %zd bytes to server", nwrite);
            ssize_t sent = sendto(ctx.fd, buf, nwrite, 0,
                                  (struct sockaddr *)&ctx.server_addr, ctx.server_addrlen);
            if (sent < 0) {
                h3_log(LOG_LEVEL_ERROR, "CLIENT", "sendto() failed: %s", strerror(errno));
            } else {
                h3_log(LOG_LEVEL_INFO, "CLIENT", "[QUIC] Sent %zd bytes", sent);
            }
        }

        /* After handshake, open streams and send request */
        if (ctx.handshake_completed && !ctx.control_stream_opened) {
            open_client_streams(&ctx);
            send_settings(&ctx);
        }

        if (ctx.handshake_completed && ctx.control_stream_opened && !ctx.request_sent) {
            send_request(&ctx);
        }

        /* Wait for incoming data */
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx.fd, &rfds);

        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 }; /* 100ms */
        int nfds = select(ctx.fd + 1, &rfds, NULL, NULL, &tv);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (nfds > 0 && FD_ISSET(ctx.fd, &rfds)) {
            struct sockaddr_storage addr;
            socklen_t addrlen = sizeof(addr);

            ssize_t nread = recvfrom(ctx.fd, buf, sizeof(buf), 0,
                                     (struct sockaddr *)&addr, &addrlen);

            if (nread < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                h3_log(LOG_LEVEL_ERROR, "CLIENT", "recvfrom() failed: %s", strerror(errno));
                continue;
            }

            h3_log(LOG_LEVEL_DEBUG, "CLIENT", "[QUIC] Received %zd bytes", nread);

            /* Process received packet */
            ngtcp2_path recv_path = {
                .local = { .addr = (struct sockaddr *)&local_addr, .addrlen = local_addrlen },
                .remote = { .addr = (struct sockaddr *)&addr, .addrlen = addrlen }
            };

            rv = ngtcp2_conn_read_pkt(ctx.conn, &recv_path, &pi, buf, nread, get_timestamp());
            if (rv != 0) {
                if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
                    h3_log(LOG_LEVEL_INFO, "CLIENT", "[QUIC] Connection closing/draining");
                    break;
                } else {
                    h3_log(LOG_LEVEL_ERROR, "CLIENT", "[QUIC] ngtcp2_conn_read_pkt failed: %s (%d)",
                           ngtcp2_strerror(rv), rv);
                    /* Print OpenSSL error if any */
                    unsigned long ssl_err;
                    while ((ssl_err = ERR_get_error()) != 0) {
                        char err_buf[256];
                        ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
                        h3_log(LOG_LEVEL_ERROR, "CLIENT", "OpenSSL error: %s", err_buf);
                    }
                }
            } else {
                h3_log(LOG_LEVEL_DEBUG, "CLIENT", "[QUIC] Packet processed successfully");
            }
        }
    }

    /* Print final result */
    if (ctx.response_received) {
        h3_log(LOG_LEVEL_INFO, "CLIENT", "========================================");
        h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Request completed successfully!");
        h3_log(LOG_LEVEL_INFO, "CLIENT", "[HTTP/3] Response status: %d", ctx.response.status);
        h3_log(LOG_LEVEL_INFO, "CLIENT", "========================================");
        printf("\nHTTP/3 TEST: SUCCESS\n");
    } else {
        h3_log(LOG_LEVEL_ERROR, "CLIENT", "========================================");
        h3_log(LOG_LEVEL_ERROR, "CLIENT", "[HTTP/3] Request failed or timed out");
        h3_log(LOG_LEVEL_ERROR, "CLIENT", "========================================");
        printf("\nHTTP/3 TEST: FAILED\n");
    }

    /* Cleanup */
    h3_message_free(&ctx.response);

    if (ctx.conn) {
        ngtcp2_conn_del(ctx.conn);
    }
    if (ctx.ssl) {
        SSL_free(ctx.ssl);
    }
    if (ctx.ssl_ctx) {
        SSL_CTX_free(ctx.ssl_ctx);
    }
    close(ctx.fd);

    return ctx.response_received ? 0 : 1;
}
