/*
 * HTTP/3 Server Implementation (RFC 9114)
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

#define SERVER_PORT 4433
#define MAX_DATAGRAM_SIZE 1350
#define MAX_STREAMS 100

static volatile sig_atomic_t running = 1;

/* Server context */
typedef struct {
    int fd;
    SSL_CTX *ssl_ctx;
    ngtcp2_conn *conn;
    SSL *ssl;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;
    ngtcp2_crypto_conn_ref conn_ref;

    /* HTTP/3 state */
    h3_settings_t settings;
    int64_t control_stream_id;
    bool control_stream_opened;
    bool settings_sent;
    bool settings_received;

    /* QPACK streams (simplified - we don't use them actively) */
    int64_t qpack_encoder_stream_id;
    int64_t qpack_decoder_stream_id;

    /* Request handling */
    uint8_t recv_buf[65536];
    size_t recv_buf_len;
} server_ctx_t;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

/* ALPN selection callback for HTTP/3 */
static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl;
    (void)arg;

    /* Select h3 ALPN for HTTP/3 */
    for (unsigned int i = 0; i < inlen; ) {
        unsigned int len = in[i];
        if (i + 1 + len <= inlen) {
            if (len == 2 && memcmp(in + i + 1, "h3", 2) == 0) {
                *out = in + i + 1;
                *outlen = (unsigned char)len;
                return SSL_TLSEXT_ERR_OK;
            }
        }
        i += 1 + len;
    }
    return SSL_TLSEXT_ERR_NOACK;
}


/* Callback to get ngtcp2_conn from crypto connection reference */
static ngtcp2_conn *get_conn_from_ref(ngtcp2_crypto_conn_ref *ref) {
    if (!ref || !ref->user_data) {
        return NULL;
    }
    server_ctx_t *ctx = (server_ctx_t *)ref->user_data;
    return ctx->conn;
}

static uint64_t get_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

static void rand_bytes(uint8_t *data, size_t len) {
    RAND_bytes(data, (int)len);
}

/* ngtcp2 callbacks - use the built-in crypto callbacks */

static int server_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                                   int64_t stream_id, uint64_t offset,
                                   const uint8_t *data, size_t datalen,
                                   void *user_data, void *stream_user_data) {
    (void)conn;
    (void)flags;
    (void)offset;
    (void)stream_user_data;
    server_ctx_t *ctx = user_data;

    h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Received %zu bytes on stream %ld",
           datalen, stream_id);

    /* Dump raw hex at debug level */
    h3_dump_frame_hex("SERVER", "Received", data, datalen);

    /* Check if this is a unidirectional stream (client-initiated: stream_id & 0x2) */
    bool is_uni = (stream_id & 0x2) != 0;
    bool is_client_initiated = (stream_id & 0x1) == 0;

    if (is_uni && is_client_initiated) {
        /* Client-initiated unidirectional stream - should be control or QPACK stream */
        if (datalen > 0) {
            uint64_t stream_type;
            size_t consumed = h3_decode_varint(data, datalen, &stream_type);
            if (consumed > 0) {
                h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Client unidirectional stream type: 0x%lx (%s)",
                       stream_type, h3_stream_type_name(stream_type));
                h3_log(LOG_LEVEL_DEBUG, "SERVER",
                       "[RFC 9114 Section 6.2] Unidirectional Stream Type: %s (0x%02lx)",
                       h3_stream_type_name(stream_type), (unsigned long)stream_type);

                if (stream_type == H3_STREAM_TYPE_CONTROL) {
                    h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Received client CONTROL stream");
                    h3_log(LOG_LEVEL_DEBUG, "SERVER",
                           "[RFC 9114 Section 6.2.1] Control stream carries frames affecting entire connection");

                    /* Parse SETTINGS frame */
                    if (datalen > consumed) {
                        h3_frame_t frame;
                        size_t frame_len = h3_decode_frame(data + consumed, datalen - consumed, &frame);
                        if (frame_len > 0 && frame.type == H3_FRAME_SETTINGS) {
                            h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Received SETTINGS frame (len=%lu)",
                                   frame.length);

                            /* Debug: dump frame details */
                            h3_dump_frame_translated("SERVER", "Received", &frame, stream_id);

                            h3_settings_t client_settings;
                            h3_decode_settings_frame(frame.payload, frame.length, &client_settings);
                            ctx->settings_received = true;
                            h3_log(LOG_LEVEL_INFO, "SERVER",
                                   "[HTTP/3] Client settings: max_field_section_size=%lu",
                                   client_settings.max_field_section_size);
                        }
                    }
                } else if (stream_type == H3_STREAM_TYPE_QPACK_ENCODER) {
                    h3_log(LOG_LEVEL_DEBUG, "SERVER", "[HTTP/3] Received client QPACK encoder stream");
                    h3_log(LOG_LEVEL_DEBUG, "SERVER",
                           "[RFC 9114 Section 6.2.3] QPACK encoder stream for dynamic table updates");
                } else if (stream_type == H3_STREAM_TYPE_QPACK_DECODER) {
                    h3_log(LOG_LEVEL_DEBUG, "SERVER", "[HTTP/3] Received client QPACK decoder stream");
                    h3_log(LOG_LEVEL_DEBUG, "SERVER",
                           "[RFC 9114 Section 6.2.3] QPACK decoder stream for acknowledgments");
                }
            }
        }
    } else if (!is_uni && is_client_initiated) {
        /* Client-initiated bidirectional stream - this is a request stream */
        h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Processing request on stream %ld", stream_id);
        h3_log(LOG_LEVEL_DEBUG, "SERVER",
               "[RFC 9114 Section 4.1] Request stream %lld carries HTTP request message",
               (long long)stream_id);

        /* Parse HTTP/3 frames */
        size_t offset_local = 0;
        h3_message_t request;
        h3_message_init(&request);
        bool got_headers = false;

        while (offset_local < datalen) {
            h3_frame_t frame;
            size_t frame_len = h3_decode_frame(data + offset_local, datalen - offset_local, &frame);
            if (frame_len == 0) break;

            h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Frame: type=%s (0x%lx), length=%lu",
                   h3_frame_type_name(frame.type), frame.type, frame.length);

            /* Debug: dump raw frame hex and translation */
            h3_dump_frame_hex("SERVER", "Received", data + offset_local, frame_len);
            h3_dump_frame_translated("SERVER", "Received", &frame, stream_id);

            if (frame.type == H3_FRAME_HEADERS) {
                h3_decode_headers(frame.payload, frame.length, &request, false);
                got_headers = true;

                /* Debug: dump decoded headers with RFC terminology */
                h3_dump_headers_translated("SERVER", &request, false);

                h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Request: %s %s%s",
                       request.method ? request.method : "?",
                       request.authority ? request.authority : "",
                       request.path ? request.path : "/");
            } else if (frame.type == H3_FRAME_DATA) {
                h3_log(LOG_LEVEL_DEBUG, "SERVER", "[HTTP/3] Request body: %zu bytes", frame.length);
            }

            offset_local += frame_len;
        }

        /* Send response if we got headers */
        if (got_headers) {
            h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Sending response on stream %ld", stream_id);

            /* Build response */
            h3_message_t response;
            h3_message_init(&response);
            response.status = 200;
            h3_message_add_header(&response, "content-type", "text/plain");
            h3_message_add_header(&response, "server", "http3-c-server/1.0");

            /* Debug: dump response headers with RFC terminology */
            h3_dump_headers_translated("SERVER", &response, true);

            const char *body = "Hello from HTTP/3 server! This response was sent using the HTTP/3 protocol (RFC 9114) over QUIC.\n";
            size_t body_len = strlen(body);

            /* Encode HEADERS frame */
            uint8_t headers_payload[1024];
            size_t headers_len = h3_encode_headers(&response, headers_payload, sizeof(headers_payload), true);

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

            /* Debug: dump HEADERS frame */
            h3_dump_frame_translated("SERVER", "Sending", &headers_frame, stream_id);

            /* DATA frame */
            h3_frame_t data_frame = {
                .type = H3_FRAME_DATA,
                .length = body_len,
                .payload = (uint8_t *)body
            };
            frame_offset += h3_encode_frame(&data_frame, frame_buf + frame_offset,
                                            sizeof(frame_buf) - frame_offset);

            /* Debug: dump DATA frame */
            h3_dump_frame_translated("SERVER", "Sending", &data_frame, stream_id);

            /* Debug: dump complete response hex */
            h3_dump_frame_hex("SERVER", "Sending", frame_buf, frame_offset);

            /* Send response - write stream data to packet and send */
            ngtcp2_vec vec = { .base = frame_buf, .len = frame_offset };
            int64_t written;
            uint8_t pktbuf[MAX_DATAGRAM_SIZE];
            ngtcp2_path_storage ps;
            ngtcp2_path_storage_zero(&ps);
            ngtcp2_pkt_info pi = {0};

            ngtcp2_ssize pktlen = ngtcp2_conn_writev_stream(conn, &ps.path, &pi, pktbuf,
                                                            sizeof(pktbuf), &written,
                                                            NGTCP2_WRITE_STREAM_FLAG_FIN,
                                                            stream_id, &vec, 1, get_timestamp());
            if (pktlen > 0) {
                ssize_t sent = sendto(ctx->fd, pktbuf, pktlen, 0,
                                      (struct sockaddr *)&ctx->client_addr, ctx->client_addrlen);
                if (sent > 0) {
                    h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Response sent: %zu bytes payload in %zd byte packet",
                           frame_offset, pktlen);
                } else {
                    h3_log(LOG_LEVEL_ERROR, "SERVER", "[HTTP/3] Failed to send response: %s", strerror(errno));
                }
            } else if (pktlen < 0) {
                h3_log(LOG_LEVEL_ERROR, "SERVER", "[HTTP/3] Failed to write response to packet: %s",
                       ngtcp2_strerror((int)pktlen));
            }

            h3_message_free(&response);
        }

        h3_message_free(&request);
    }

    return 0;
}

static int server_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
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

static int server_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    (void)conn;
    server_ctx_t *ctx = user_data;

    bool is_bidi = (stream_id & 0x2) == 0;
    bool is_client = (stream_id & 0x1) == 0;

    h3_log(LOG_LEVEL_DEBUG, "SERVER", "Stream opened: %ld (%s, %s-initiated)",
           stream_id,
           is_bidi ? "bidirectional" : "unidirectional",
           is_client ? "client" : "server");

    return 0;
}

static int server_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                               uint64_t app_error_code, void *user_data,
                               void *stream_user_data) {
    (void)conn;
    (void)flags;
    (void)stream_user_data;
    server_ctx_t *ctx = user_data;

    h3_log(LOG_LEVEL_DEBUG, "SERVER", "Stream %ld closed with error code %lu",
           stream_id, app_error_code);

    return 0;
}

static void server_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    (void)rand_ctx;
    rand_bytes(dest, destlen);
}

static int server_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                        uint8_t *token, size_t cidlen,
                                        void *user_data) {
    (void)conn;
    (void)user_data;
    rand_bytes(cid->data, cidlen);
    cid->datalen = cidlen;
    rand_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}


static int server_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data, void *user_data) {
    (void)conn;
    (void)user_data;
    rand_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN);
    return 0;
}

static int server_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    server_ctx_t *ctx = user_data;

    h3_log(LOG_LEVEL_INFO, "SERVER", "[QUIC] Handshake completed!");
    h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Connection established via QUIC");

    return 0;
}


static void setup_ssl_ctx(server_ctx_t *ctx, const char *cert_file, const char *key_file) {
    ctx->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx->ssl_ctx) {
        h3_log(LOG_LEVEL_ERROR, "SERVER", "Failed to create SSL_CTX");
        exit(1);
    }

    /* Configure SSL context for QUIC using ngtcp2 helper */
    if (ngtcp2_crypto_quictls_configure_server_context(ctx->ssl_ctx) != 0) {
        h3_log(LOG_LEVEL_ERROR, "SERVER", "Failed to configure SSL context for QUIC");
        exit(1);
    }

    if (SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, cert_file) != 1) {
        h3_log(LOG_LEVEL_ERROR, "SERVER", "Failed to load certificate: %s", cert_file);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        h3_log(LOG_LEVEL_ERROR, "SERVER", "Failed to load private key: %s", key_file);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Set ALPN for HTTP/3 */
    SSL_CTX_set_alpn_select_cb(ctx->ssl_ctx, alpn_select_cb, NULL);

    h3_log(LOG_LEVEL_INFO, "SERVER", "SSL context initialized with h3 ALPN");
}

static int open_server_control_stream(server_ctx_t *ctx) {
    if (ctx->control_stream_opened) return 0;

    /* Open server-initiated unidirectional control stream */
    int rv = ngtcp2_conn_open_uni_stream(ctx->conn, &ctx->control_stream_id, NULL);
    if (rv != 0) {
        h3_log(LOG_LEVEL_ERROR, "SERVER", "Failed to open control stream: %d", rv);
        return rv;
    }

    h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Opened control stream: %ld", ctx->control_stream_id);

    /* Prepare control stream data: stream type + SETTINGS frame */
    uint8_t control_data[256];
    size_t offset = 0;

    /* Stream type */
    offset += h3_encode_varint(H3_STREAM_TYPE_CONTROL, control_data + offset, sizeof(control_data) - offset);

    /* SETTINGS frame */
    ctx->settings.max_field_section_size = H3_DEFAULT_MAX_FIELD_SECTION_SIZE;
    ctx->settings.qpack_max_table_capacity = 0;
    ctx->settings.qpack_blocked_streams = 0;
    offset += h3_encode_settings_frame(&ctx->settings, control_data + offset, sizeof(control_data) - offset);

    h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Sending SETTINGS frame on control stream");

    /* Debug: dump outgoing SETTINGS */
    h3_dump_frame_hex("SERVER", "Sending", control_data, offset);
    h3_log(LOG_LEVEL_DEBUG, "SERVER",
           "[RFC 9114 Section 6.2.1] Control stream type 0x00 followed by SETTINGS frame");
    h3_dump_settings_translated("SERVER", &ctx->settings);

    /* Actually write the control stream data */
    ngtcp2_vec control_vec = { .base = control_data, .len = offset };
    int64_t written;
    uint8_t pktbuf[MAX_DATAGRAM_SIZE];
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi = {0};

    ngtcp2_ssize pktlen = ngtcp2_conn_writev_stream(ctx->conn, &ps.path, &pi, pktbuf,
                                                    sizeof(pktbuf), &written,
                                                    NGTCP2_WRITE_STREAM_FLAG_NONE,
                                                    ctx->control_stream_id, &control_vec, 1,
                                                    get_timestamp());
    if (pktlen > 0) {
        sendto(ctx->fd, pktbuf, pktlen, 0,
               (struct sockaddr *)&ctx->client_addr, ctx->client_addrlen);
        h3_log(LOG_LEVEL_DEBUG, "SERVER", "[HTTP/3] Control stream data sent: %zu bytes", offset);
    }

    ctx->control_stream_opened = true;
    ctx->settings_sent = true;

    return 0;
}

static int create_server_socket(int port) {
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        h3_log(LOG_LEVEL_ERROR, "SERVER", "socket() failed: %s", strerror(errno));
        return -1;
    }

    int optval = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval));

    optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        h3_log(LOG_LEVEL_ERROR, "SERVER", "bind() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}

int main(int argc, char **argv) {
    const char *cert_file = "/certs/server.crt";
    const char *key_file = "/certs/server.key";
    int port = SERVER_PORT;

    if (argc > 1) cert_file = argv[1];
    if (argc > 2) key_file = argv[2];
    if (argc > 3) port = atoi(argv[3]);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    h3_log(LOG_LEVEL_INFO, "SERVER", "========================================");
    h3_log(LOG_LEVEL_INFO, "SERVER", "HTTP/3 Server (RFC 9114) starting...");
    h3_log(LOG_LEVEL_INFO, "SERVER", "========================================");
    h3_log(LOG_LEVEL_INFO, "SERVER", "Port: %d", port);
    h3_log(LOG_LEVEL_INFO, "SERVER", "Certificate: %s", cert_file);
    h3_log(LOG_LEVEL_INFO, "SERVER", "Private key: %s", key_file);

    server_ctx_t ctx = {0};
    ctx.control_stream_id = -1;

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Note: ngtcp2_crypto_quictls_init() is deprecated in newer versions
     * The crypto callbacks are set up automatically by ngtcp2_crypto_quictls_configure_server_context() */

    /* Setup SSL context */
    setup_ssl_ctx(&ctx, cert_file, key_file);

    /* Create UDP socket */
    ctx.fd = create_server_socket(port);
    if (ctx.fd < 0) {
        return 1;
    }

    h3_log(LOG_LEVEL_INFO, "SERVER", "[QUIC] Listening on UDP port %d", port);
    h3_log(LOG_LEVEL_INFO, "SERVER", "[HTTP/3] Server ready to accept connections");
    h3_log(LOG_LEVEL_INFO, "SERVER", "========================================");

    /* Main event loop */
    uint8_t buf[MAX_DATAGRAM_SIZE];

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx.fd, &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int nfds = select(ctx.fd + 1, &rfds, NULL, NULL, &tv);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (nfds == 0) {
            /* Timeout - handle connection timers if we have an active connection */
            if (ctx.conn) {
                /* Write any pending data */
                ngtcp2_path_storage ps;
                ngtcp2_path_storage_zero(&ps);
                ngtcp2_pkt_info pi = {0};

                for (;;) {
                    ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(
                        ctx.conn, &ps.path, &pi, buf, sizeof(buf), get_timestamp());

                    if (nwrite < 0) {
                        if (nwrite != NGTCP2_ERR_WRITE_MORE) break;
                        continue;
                    }
                    if (nwrite == 0) break;

                    sendto(ctx.fd, buf, nwrite, 0,
                           (struct sockaddr *)&ctx.client_addr, ctx.client_addrlen);
                }
            }
            continue;
        }

        if (FD_ISSET(ctx.fd, &rfds)) {
            struct sockaddr_storage addr;
            socklen_t addrlen = sizeof(addr);

            ssize_t nread = recvfrom(ctx.fd, buf, sizeof(buf), 0,
                                     (struct sockaddr *)&addr, &addrlen);

            if (nread < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                h3_log(LOG_LEVEL_ERROR, "SERVER", "recvfrom() failed: %s", strerror(errno));
                continue;
            }

            h3_log(LOG_LEVEL_DEBUG, "SERVER", "[QUIC] Received %zd bytes", nread);

            /* If no connection exists, try to accept a new one */
            if (!ctx.conn) {
                ngtcp2_pkt_hd hd;
                int rv = ngtcp2_accept(&hd, buf, nread);
                if (rv < 0) {
                    h3_log(LOG_LEVEL_DEBUG, "SERVER", "Not an Initial packet, ignoring");
                    continue;
                }

                h3_log(LOG_LEVEL_INFO, "SERVER", "[QUIC] Received Initial packet, accepting connection");

                /* Create SSL object */
                ctx.ssl = SSL_new(ctx.ssl_ctx);
                SSL_set_accept_state(ctx.ssl);

                /* Set up crypto connection reference BEFORE creating ngtcp2 connection
                 * This is required because the crypto callbacks access it during handshake.
                 * user_data points to our server context, and get_conn retrieves the ngtcp2_conn from it */
                ctx.conn_ref.get_conn = get_conn_from_ref;
                ctx.conn_ref.user_data = &ctx;
                SSL_set_app_data(ctx.ssl, &ctx.conn_ref);

                /* Setup ngtcp2 connection - use built-in crypto callbacks */
                ngtcp2_callbacks callbacks = {
                    .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
                    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
                    .encrypt = ngtcp2_crypto_encrypt_cb,
                    .decrypt = ngtcp2_crypto_decrypt_cb,
                    .hp_mask = ngtcp2_crypto_hp_mask_cb,
                    .recv_stream_data = server_recv_stream_data,
                    .acked_stream_data_offset = server_acked_stream_data_offset,
                    .stream_open = server_stream_open,
                    .stream_close = server_stream_close,
                    .rand = server_rand,
                    .get_new_connection_id = server_get_new_connection_id,
                    .update_key = ngtcp2_crypto_update_key_cb,
                    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
                    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
                    .get_path_challenge_data = server_get_path_challenge_data,
                    .handshake_completed = server_handshake_completed,
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

                /* Server MUST set original_dcid from the Initial packet's DCID */
                params.original_dcid = hd.dcid;
                params.original_dcid_present = 1;

                /* Generate server connection ID */
                ngtcp2_cid scid;
                rand_bytes(scid.data, NGTCP2_MAX_CIDLEN);
                scid.datalen = NGTCP2_MAX_CIDLEN;

                /* Store client address */
                ctx.client_addr = addr;
                ctx.client_addrlen = addrlen;

                /* Get and store local address */
                ctx.local_addrlen = sizeof(ctx.local_addr);
                getsockname(ctx.fd, (struct sockaddr *)&ctx.local_addr, &ctx.local_addrlen);

                ngtcp2_path path = {
                    .local = { .addr = (struct sockaddr *)&ctx.local_addr, .addrlen = ctx.local_addrlen },
                    .remote = { .addr = (struct sockaddr *)&ctx.client_addr, .addrlen = ctx.client_addrlen }
                };

                /* ngtcp2_conn_server_new parameters:
                 *   dcid: Client's SCID from Initial packet (what client wants to be called)
                 *   scid: Server's chosen SCID
                 * And params.original_dcid = Client's DCID from Initial packet */
                rv = ngtcp2_conn_server_new(&ctx.conn, &hd.scid, &scid, &path,
                                            hd.version, &callbacks, &settings,
                                            &params, NULL, &ctx);
                if (rv != 0) {
                    h3_log(LOG_LEVEL_ERROR, "SERVER", "ngtcp2_conn_server_new failed: %d", rv);
                    SSL_free(ctx.ssl);
                    ctx.ssl = NULL;
                    continue;
                }

                /* Link the TLS native handle to the ngtcp2 connection */
                ngtcp2_conn_set_tls_native_handle(ctx.conn, ctx.ssl);

                /* Note: ngtcp2_crypto_quictls_configure_server_context sets up the callbacks
                 * that handle transport params automatically through the conn_ref mechanism.
                 * We should NOT manually set transport params here. */

                /* Debug: Check if conn_ref is properly accessible via SSL */
                {
                    ngtcp2_crypto_conn_ref *ref = SSL_get_app_data(ctx.ssl);
                    if (!ref) {
                        h3_log(LOG_LEVEL_ERROR, "SERVER", "SSL app_data (conn_ref) is NULL!");
                    } else if (!ref->get_conn) {
                        h3_log(LOG_LEVEL_ERROR, "SERVER", "conn_ref->get_conn is NULL!");
                    } else {
                        ngtcp2_conn *test_conn = ref->get_conn(ref);
                        if (!test_conn) {
                            h3_log(LOG_LEVEL_ERROR, "SERVER", "get_conn returned NULL!");
                        } else {
                            h3_log(LOG_LEVEL_DEBUG, "SERVER", "conn_ref setup verified OK");
                        }
                    }
                }

                /* Note: Transport params are set by ngtcp2 crypto callbacks during handshake.
                 * The server's transport params are set when generating ServerHello. */

                h3_log(LOG_LEVEL_INFO, "SERVER", "[QUIC] Connection created, dcid_len=%zu, scid_len=%zu",
                       hd.dcid.datalen, scid.datalen);
                h3_log(LOG_LEVEL_INFO, "SERVER", "[QUIC] TLS native handle set, processing handshake...");
            }

            /* Process received packet - local is server, remote is client */
            ngtcp2_path path = {
                .local = { .addr = (struct sockaddr *)&ctx.local_addr, .addrlen = ctx.local_addrlen },
                .remote = { .addr = (struct sockaddr *)&ctx.client_addr, .addrlen = ctx.client_addrlen }
            };
            ngtcp2_pkt_info pi = {0};

            h3_log(LOG_LEVEL_DEBUG, "SERVER", "[QUIC] Reading packet of %zd bytes", nread);
            h3_log(LOG_LEVEL_DEBUG, "SERVER", "[QUIC] Calling ngtcp2_conn_read_pkt...");
            int rv = ngtcp2_conn_read_pkt(ctx.conn, &path, &pi, buf, nread, get_timestamp());
            h3_log(LOG_LEVEL_DEBUG, "SERVER", "[QUIC] ngtcp2_conn_read_pkt returned %d", rv);
            if (rv != 0) {
                if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
                    h3_log(LOG_LEVEL_INFO, "SERVER", "[QUIC] Connection closing/draining");
                } else {
                    h3_log(LOG_LEVEL_ERROR, "SERVER", "[QUIC] ngtcp2_conn_read_pkt failed: %s (%d)",
                           ngtcp2_strerror(rv), rv);
                    /* Get ngtcp2 TLS alert code if available */
                    uint8_t alert = ngtcp2_conn_get_tls_alert(ctx.conn);
                    if (alert != 0) {
                        h3_log(LOG_LEVEL_ERROR, "SERVER", "TLS alert: %u", (unsigned)alert);
                    }
                    /* Print OpenSSL error if any */
                    unsigned long ssl_err;
                    while ((ssl_err = ERR_get_error()) != 0) {
                        char err_buf[256];
                        ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
                        h3_log(LOG_LEVEL_ERROR, "SERVER", "OpenSSL error: %s", err_buf);
                    }
                }
            } else {
                h3_log(LOG_LEVEL_DEBUG, "SERVER", "[QUIC] Packet processed successfully");
            }

            /* Open control stream after handshake */
            if (ngtcp2_conn_get_handshake_completed(ctx.conn) && !ctx.control_stream_opened) {
                open_server_control_stream(&ctx);
            }

            /* Write response packets */
            ngtcp2_path_storage ps;
            ngtcp2_path_storage_zero(&ps);

            for (;;) {
                ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(
                    ctx.conn, &ps.path, &pi, buf, sizeof(buf), get_timestamp());

                if (nwrite < 0) {
                    if (nwrite != NGTCP2_ERR_WRITE_MORE) break;
                    continue;
                }
                if (nwrite == 0) break;

                ssize_t sent = sendto(ctx.fd, buf, nwrite, 0,
                                      (struct sockaddr *)&ctx.client_addr, ctx.client_addrlen);
                if (sent < 0) {
                    h3_log(LOG_LEVEL_ERROR, "SERVER", "sendto() failed: %s", strerror(errno));
                }
            }
        }
    }

    h3_log(LOG_LEVEL_INFO, "SERVER", "Server shutting down...");

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

    return 0;
}
