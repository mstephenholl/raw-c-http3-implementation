#!/bin/bash
# Run HTTP/3 client-server test locally (without Docker)
# Run build-local.sh first

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
CERTS_DIR="$PROJECT_DIR/certs"

cd "$PROJECT_DIR"

echo "=========================================="
echo "HTTP/3 Local Test"
echo "=========================================="

# Check if binaries exist
if [[ ! -x "$BUILD_DIR/h3_server" ]] || [[ ! -x "$BUILD_DIR/h3_client" ]]; then
    echo "Error: Binaries not found. Run build-local.sh first."
    exit 1
fi

# Set up library paths
INSTALL_PREFIX="$HOME/.local"
export LD_LIBRARY_PATH="$INSTALL_PREFIX/lib:$LD_LIBRARY_PATH"
export DYLD_LIBRARY_PATH="$INSTALL_PREFIX/lib:$DYLD_LIBRARY_PATH"

# Generate certificates if needed
if [[ ! -f "$CERTS_DIR/server.crt" ]] || [[ ! -f "$CERTS_DIR/server.key" ]]; then
    echo ""
    echo "Generating self-signed certificates..."
    mkdir -p "$CERTS_DIR"
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERTS_DIR/server.key" \
        -out "$CERTS_DIR/server.crt" \
        -days 365 -nodes \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    echo "Certificates generated in $CERTS_DIR"
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Start server in background
echo ""
echo "Starting HTTP/3 server on port 4433..."
"$BUILD_DIR/h3_server" "$CERTS_DIR/server.crt" "$CERTS_DIR/server.key" 4433 &
SERVER_PID=$!

# Wait for server to be ready
echo "Waiting for server to start..."
sleep 2

# Check if server is still running
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Error: Server failed to start"
    exit 1
fi

echo "Server started (PID: $SERVER_PID)"

# Run client test
echo ""
echo "Running HTTP/3 client..."
echo ""

if "$BUILD_DIR/h3_client" -p 4433 localhost /; then
    echo ""
    echo "=========================================="
    echo "✓ TEST PASSED: HTTP/3 communication successful"
    echo "=========================================="
    EXIT_CODE=0
else
    echo ""
    echo "=========================================="
    echo "✗ TEST FAILED"
    echo "=========================================="
    EXIT_CODE=1
fi

exit $EXIT_CODE
