# HTTP/3 Implementation in C

A complete HTTP/3 (RFC 9114) implementation in C, featuring both client and server components built on the QUIC transport protocol.

## Quick Start

### Using Docker (Easiest)

```bash
# Clone and run tests
git clone <repository-url>
cd http3-implementation
./scripts/test-http3.sh docker
```

### Local Build (macOS/Linux)

```bash
# Install dependencies
./scripts/install-deps-macos.sh  # or install-deps-linux.sh

# Add to your shell profile (then restart terminal or source it):
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
export DYLD_LIBRARY_PATH="$HOME/.local/lib:$DYLD_LIBRARY_PATH"  # macOS
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"      # Linux

# Build and test
./scripts/build-local.sh
./scripts/test-http3.sh
```

## Overview

This project implements the HTTP/3 protocol as specified in [RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114), using:

- **QUIC Transport**: [ngtcp2](https://github.com/ngtcp2/ngtcp2) library
- **TLS 1.3**: OpenSSL for cryptographic operations
- **HTTP/3 Framing**: Custom implementation of HTTP/3 frame encoding/decoding

### Features

- HTTP/3 frame types: DATA, HEADERS, SETTINGS, GOAWAY, and more
- QUIC variable-length integer encoding (RFC 9000 Section 16)
- Simplified QPACK header compression
- TLS 1.3 handshake with ALPN negotiation ("h3")
- Bidirectional request/response streams
- Unidirectional control streams
- Complete error code handling per RFC 9114 Section 8.1

## Project Structure

```
http3-implementation/
├── include/
│   └── http3.h              # Public API header
├── src/
│   ├── http3_common.c       # Common utilities (frame encoding, logging)
│   ├── h3_server.c          # HTTP/3 server implementation
│   └── h3_client.c          # HTTP/3 client implementation
├── docker/
│   ├── Dockerfile.server    # Server container build
│   └── Dockerfile.client    # Client container build
├── scripts/
│   ├── test-http3.sh        # Unified test script (local/docker/auto)
│   ├── install-deps-macos.sh # Install dependencies on macOS
│   ├── install-deps-linux.sh # Install dependencies on Linux
│   ├── build-local.sh       # Build project locally
│   └── show-debug-logs.sh   # Show RFC 9114 debug output
├── certs/                   # TLS certificates (generated)
├── CMakeLists.txt           # CMake build configuration
├── docker-compose.yml       # Docker orchestration
└── README.md                # This file
```

## Prerequisites

### For Native Build

- CMake 3.16+
- GCC or Clang with C11 support
- OpenSSL 1.1.1+
- ngtcp2 library with OpenSSL crypto support
- pkg-config

### For Docker Build

- Docker 20.10+
- Docker Compose 2.0+

## Building

### Option 1: Docker (Recommended)

The easiest way to build and test is using Docker:

```bash
# Build both server and client images
docker compose build

# Or build individually
docker compose build http3-server
docker compose build http3-client
```

### Option 2: Local Build (Recommended for Development)

Use the provided scripts to install dependencies and build locally. These scripts build quictls (OpenSSL with QUIC support) and ngtcp2 from source.

#### macOS

```bash
# Install dependencies (requires Homebrew)
./scripts/install-deps-macos.sh

# Add to your shell profile (the script will show these commands):
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
export DYLD_LIBRARY_PATH="$HOME/.local/lib:$DYLD_LIBRARY_PATH"

# Build the project
./scripts/build-local.sh
```

#### Linux (Debian/Ubuntu)

```bash
# Install dependencies
./scripts/install-deps-linux.sh

# Add to your shell profile (~/.bashrc):
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"

# Build the project
./scripts/build-local.sh
```

### Option 3: Manual Native Build

If you prefer to install dependencies manually:

#### Install Dependencies (Debian/Ubuntu)

```bash
# Install build tools and OpenSSL
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libssl-dev \
    git autoconf automake libtool

# Build and install ngtcp2 from source
git clone --depth 1 --branch v1.2.0 https://github.com/ngtcp2/ngtcp2.git
cd ngtcp2
autoreconf -fi
./configure --prefix=/usr/local --enable-lib-only --with-openssl
make -j$(nproc)
sudo make install
sudo ldconfig
```

#### Build the Project

```bash
# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build
make -j$(nproc)

# Install (optional)
sudo make install
```

## Running

### Using the Test Script (Recommended)

The unified test script handles both local and Docker testing:

```bash
# Auto-detect mode (uses local binaries if available, else Docker)
./scripts/test-http3.sh

# Force local mode
./scripts/test-http3.sh local

# Force Docker mode
./scripts/test-http3.sh docker
```

### Using Docker Compose

#### Run the Complete Test Suite

```bash
# Start server and run tests
docker compose up http3-test

# View test results
docker compose logs http3-test
```

#### Run Server and Client Separately

```bash
# Terminal 1: Start the server
docker compose up http3-server

# Terminal 2: Run the client
docker compose run --rm http3-client -p 4433 http3-server /
```

#### Run with Custom Configuration

```bash
# Run client with different parameters
docker compose run --rm http3-client -p 4433 http3-server /api/test
```

### Manual Native Execution

#### Generate TLS Certificates

```bash
# Create certificates directory
mkdir -p certs

# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 \
    -keyout certs/server.key -out certs/server.crt \
    -days 365 -nodes -subj "/CN=localhost"
```

#### Run the Server

```bash
# Default configuration (port 4433)
./build/h3_server certs/server.crt certs/server.key 4433

# Custom port
./build/h3_server certs/server.crt certs/server.key 8443
```

#### Run the Client

```bash
# Basic request
./build/h3_client localhost /

# With options
./build/h3_client -p 4433 -m GET localhost /index.html

# Show help
./build/h3_client -h
```

## Testing

### Unified Test Script

The project includes a unified test script that supports multiple modes:

```bash
# Auto-detect: uses local binaries if available, otherwise Docker
./scripts/test-http3.sh

# Force local mode (requires build-local.sh first)
./scripts/test-http3.sh local

# Force Docker mode (builds and runs in containers)
./scripts/test-http3.sh docker

# View RFC 9114 debug output (frame dumps, settings)
./scripts/show-debug-logs.sh
```

### Test Coverage

The test suite verifies:

1. **Basic GET Request** - Root path request/response
2. **Path Handling** - Different URL paths
3. **Query Strings** - URL with query parameters
4. **Sequential Requests** - Multiple requests in succession

### Expected Output

```
==============================================
HTTP/3 Local Test Suite
==============================================

Configuration:
  Mode: Local
  Server: localhost:4433
  Build Dir: /path/to/http3-implementation/build

Starting HTTP/3 server on port 4433...
Waiting for server to be ready...
Server is ready!
Server started (PID: 12345)

==============================================
Running HTTP/3 Protocol Tests
==============================================

Running: Basic GET Request (root path)
  Request: GET https://localhost:4433/
[PASS] Basic GET Request (root path)

Running: GET Request (index.html)
  Request: GET https://localhost:4433/index.html
[PASS] GET Request (index.html)

Running: GET Request (with query)
  Request: GET https://localhost:4433/test?param=value
[PASS] GET Request (with query)

Running: Multiple Sequential Requests
[PASS] Multiple Sequential Requests (3/3 successful)

==============================================
Test Summary
==============================================

  Total Tests:  4
  Passed:       4
  Failed:       0

==============================================
All HTTP/3 tests passed successfully!
==============================================

Protocol verification:
  ✓ QUIC transport layer operational
  ✓ TLS 1.3 handshake completed
  ✓ HTTP/3 frames encoded/decoded correctly
  ✓ SETTINGS exchange successful
  ✓ Request/Response cycle working
==============================================
```

## Architecture

### Protocol Stack

```
┌─────────────────────────────────────┐
│           Application               │
│    (h3_client.c / h3_server.c)     │
├─────────────────────────────────────┤
│           HTTP/3 Layer              │
│    (Frames, Headers, Settings)      │
│         (http3_common.c)            │
├─────────────────────────────────────┤
│           QUIC Transport            │
│            (ngtcp2)                 │
├─────────────────────────────────────┤
│           TLS 1.3                   │
│           (OpenSSL)                 │
├─────────────────────────────────────┤
│           UDP                       │
└─────────────────────────────────────┘
```

### HTTP/3 Frame Types Implemented

| Frame Type | Code | Description |
|------------|------|-------------|
| DATA | 0x00 | Request/response body content |
| HEADERS | 0x01 | Request/response headers (QPACK encoded) |
| CANCEL_PUSH | 0x03 | Cancel server push |
| SETTINGS | 0x04 | Connection configuration |
| PUSH_PROMISE | 0x05 | Server push announcement |
| GOAWAY | 0x07 | Graceful shutdown |
| MAX_PUSH_ID | 0x0D | Maximum push ID limit |

### Stream Types

| Stream Type | Code | Direction | Purpose |
|-------------|------|-----------|---------|
| Control | 0x00 | Both | SETTINGS, GOAWAY |
| Push | 0x01 | Server→Client | Server push responses |
| QPACK Encoder | 0x02 | Both | Dynamic table updates |
| QPACK Decoder | 0x03 | Both | Acknowledgments |

## Configuration

### Server Options

| Argument | Default | Description |
|----------|---------|-------------|
| cert_file | /certs/server.crt | TLS certificate path |
| key_file | /certs/server.key | TLS private key path |
| port | 4433 | UDP listening port |

### Client Options

| Option | Default | Description |
|--------|---------|-------------|
| -p port | 4433 | Server port |
| -m method | GET | HTTP method |
| -h | - | Show help |

## Troubleshooting

### Common Issues

1. **Connection Timeout**
   - Ensure the server is running and accessible
   - Check UDP port 4433 is not blocked by firewall
   - Verify network connectivity between client and server

2. **TLS Handshake Failure**
   - Regenerate certificates if expired
   - Ensure OpenSSL version supports TLS 1.3

3. **Docker Build Fails**
   - Update Docker and Docker Compose to latest versions
   - Check internet connectivity for package downloads

4. **Library Not Found (macOS)**
   - Ensure environment variables are set:
     ```bash
     export DYLD_LIBRARY_PATH="$HOME/.local/lib:$DYLD_LIBRARY_PATH"
     ```
   - Restart your terminal after setting environment variables

### Debug Mode

The implementation includes RFC 9114 debug logging that shows:
- Raw hex dumps of HTTP/3 frames
- Translated frame contents with RFC terminology
- SETTINGS parameters with explanations
- QPACK-encoded headers

View debug output after running tests:

```bash
# With Docker
./scripts/show-debug-logs.sh

# Or view logs directly
docker compose logs http3-client | grep -E "(RFC 9114|Frame Type)"
docker compose logs http3-server | grep -E "(RFC 9114|Frame Type)"
```

You can also enable verbose logging by modifying the log level in the source code:

```c
// In main() of either client or server
h3_set_log_level(LOG_LEVEL_DEBUG);
```

### IDE Setup

The build script automatically generates `compile_commands.json` for IDE support (VSCode, CLion, etc.):

```bash
./scripts/build-local.sh
# compile_commands.json is copied to project root
```

## RFC Compliance

This implementation follows these specifications:

- **RFC 9114** - HTTP/3
- **RFC 9000** - QUIC: A UDP-Based Multiplexed and Secure Transport
- **RFC 9001** - Using TLS to Secure QUIC
- **RFC 9204** - QPACK: Field Compression for HTTP/3 (simplified)

### Limitations

- Simplified QPACK implementation (literal encoding only, no dynamic tables)
- Single connection handling (not production-ready)
- Server push not fully implemented
- No connection migration support

## References

- [RFC 9114 - HTTP/3](https://datatracker.ietf.org/doc/html/rfc9114)
- [RFC 9000 - QUIC Transport](https://datatracker.ietf.org/doc/html/rfc9000)
- [ngtcp2 - QUIC library](https://github.com/ngtcp2/ngtcp2)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
