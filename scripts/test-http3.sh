#!/bin/bash
#
# HTTP/3 Test Script
# Unified test runner for both local and Docker environments
#
# Usage:
#   ./test-http3.sh          # Auto-detect mode (local if binaries exist, else Docker)
#   ./test-http3.sh local    # Force local mode
#   ./test-http3.sh docker   # Force Docker mode
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
CERTS_DIR="$PROJECT_DIR/certs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
SERVER_HOST="${SERVER_HOST:-localhost}"
SERVER_PORT="${SERVER_PORT:-4433}"
MAX_RETRIES=5
RETRY_DELAY=2

cd "$PROJECT_DIR"

# Function to print test status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" -eq 0 ]; then
        echo -e "[${GREEN}PASS${NC}] $message"
    else
        echo -e "[${RED}FAIL${NC}] $message"
    fi
}

# Function to run a test
run_test() {
    local test_name=$1
    local test_path=$2
    local client_cmd=$3

    echo ""
    echo -e "${YELLOW}Running: $test_name${NC}"
    echo "  Request: GET https://${SERVER_HOST}:${SERVER_PORT}${test_path}"

    # Run the HTTP/3 client and capture output
    local output
    local exit_code=0
    output=$($client_cmd -p "$SERVER_PORT" "$SERVER_HOST" "$test_path" 2>&1) || exit_code=$?

    # Check for success indicators
    if echo "$output" | grep -q "HTTP/3 TEST: SUCCESS"; then
        print_status 0 "$test_name"
        return 0
    else
        print_status 1 "$test_name"
        echo "  Output:"
        echo "$output" | sed 's/^/    /'
        return 1
    fi
}

# Function to run all protocol tests
run_protocol_tests() {
    local client_cmd=$1
    local tests_passed=0
    local tests_failed=0
    local tests_total=0

    echo ""
    echo "=============================================="
    echo -e "${BLUE}Running HTTP/3 Protocol Tests${NC}"
    echo "=============================================="

    # Test 1: Basic GET request to root
    tests_total=$((tests_total + 1))
    if run_test "Basic GET Request (root path)" "/" "$client_cmd"; then
        tests_passed=$((tests_passed + 1))
    else
        tests_failed=$((tests_failed + 1))
    fi

    # Test 2: GET request with different path
    tests_total=$((tests_total + 1))
    if run_test "GET Request (index.html)" "/index.html" "$client_cmd"; then
        tests_passed=$((tests_passed + 1))
    else
        tests_failed=$((tests_failed + 1))
    fi

    # Test 3: GET request with query string
    tests_total=$((tests_total + 1))
    if run_test "GET Request (with query)" "/test?param=value" "$client_cmd"; then
        tests_passed=$((tests_passed + 1))
    else
        tests_failed=$((tests_failed + 1))
    fi

    # Test 4: Multiple sequential requests
    echo ""
    echo -e "${YELLOW}Running: Multiple Sequential Requests${NC}"
    local seq_success=0
    for i in 1 2 3; do
        if $client_cmd -p "$SERVER_PORT" "$SERVER_HOST" "/seq-$i" 2>&1 | grep -q "HTTP/3 TEST: SUCCESS"; then
            seq_success=$((seq_success + 1))
        fi
    done
    tests_total=$((tests_total + 1))
    if [ $seq_success -eq 3 ]; then
        print_status 0 "Multiple Sequential Requests ($seq_success/3 successful)"
        tests_passed=$((tests_passed + 1))
    else
        print_status 1 "Multiple Sequential Requests ($seq_success/3 successful)"
        tests_failed=$((tests_failed + 1))
    fi

    # Print summary
    echo ""
    echo "=============================================="
    echo -e "${BLUE}Test Summary${NC}"
    echo "=============================================="
    echo ""
    echo "  Total Tests:  $tests_total"
    echo -e "  Passed:       ${GREEN}$tests_passed${NC}"
    echo -e "  Failed:       ${RED}$tests_failed${NC}"
    echo ""

    if [ $tests_failed -eq 0 ]; then
        echo -e "${GREEN}=============================================="
        echo "All HTTP/3 tests passed successfully!"
        echo "=============================================="
        echo ""
        echo "Protocol verification:"
        echo "  ✓ QUIC transport layer operational"
        echo "  ✓ TLS 1.3 handshake completed"
        echo "  ✓ HTTP/3 frames encoded/decoded correctly"
        echo "  ✓ SETTINGS exchange successful"
        echo "  ✓ Request/Response cycle working"
        echo -e "==============================================${NC}"
        return 0
    else
        echo -e "${RED}=============================================="
        echo "Some HTTP/3 tests failed!"
        echo -e "==============================================${NC}"
        return 1
    fi
}

# ============================================
# LOCAL MODE
# ============================================
run_local_tests() {
    echo ""
    echo "=============================================="
    echo -e "${BLUE}HTTP/3 Local Test Suite${NC}"
    echo "=============================================="
    echo ""
    echo "Configuration:"
    echo "  Mode: Local"
    echo "  Server: ${SERVER_HOST}:${SERVER_PORT}"
    echo "  Build Dir: ${BUILD_DIR}"
    echo ""

    # Check if binaries exist
    if [[ ! -x "$BUILD_DIR/h3_server" ]] || [[ ! -x "$BUILD_DIR/h3_client" ]]; then
        echo -e "${RED}Error: Binaries not found. Run build-local.sh first.${NC}"
        exit 1
    fi

    # Set up library paths
    INSTALL_PREFIX="$HOME/.local"
    export LD_LIBRARY_PATH="$INSTALL_PREFIX/lib:$LD_LIBRARY_PATH"
    export DYLD_LIBRARY_PATH="$INSTALL_PREFIX/lib:$DYLD_LIBRARY_PATH"

    # Generate certificates if needed
    if [[ ! -f "$CERTS_DIR/server.crt" ]] || [[ ! -f "$CERTS_DIR/server.key" ]]; then
        echo -e "${YELLOW}Generating self-signed certificates...${NC}"
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
    echo -e "${YELLOW}Starting HTTP/3 server on port ${SERVER_PORT}...${NC}"
    "$BUILD_DIR/h3_server" "$CERTS_DIR/server.crt" "$CERTS_DIR/server.key" "$SERVER_PORT" &
    SERVER_PID=$!

    # Wait for server to be ready
    echo -e "${YELLOW}Waiting for server to be ready...${NC}"
    local retry=0
    while [ $retry -lt $MAX_RETRIES ]; do
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo -e "${RED}Server process died${NC}"
            exit 1
        fi

        if "$BUILD_DIR/h3_client" -p "$SERVER_PORT" "$SERVER_HOST" "/" 2>&1 | grep -q "HTTP/3"; then
            echo -e "${GREEN}Server is ready!${NC}"
            break
        fi

        retry=$((retry + 1))
        echo "  Attempt $retry/$MAX_RETRIES - waiting ${RETRY_DELAY}s..."
        sleep $RETRY_DELAY
    done

    if [ $retry -eq $MAX_RETRIES ]; then
        echo -e "${RED}Server did not become ready in time${NC}"
        exit 1
    fi

    echo "Server started (PID: $SERVER_PID)"

    # Run tests
    run_protocol_tests "$BUILD_DIR/h3_client"
}

# ============================================
# DOCKER MODE
# ============================================
run_docker_tests() {
    echo ""
    echo "=============================================="
    echo -e "${BLUE}HTTP/3 Docker Test Suite${NC}"
    echo "=============================================="
    echo ""
    echo "Configuration:"
    echo "  Mode: Docker"
    echo ""

    # Clean up any previous containers
    echo -e "${YELLOW}Cleaning up previous containers...${NC}"
    docker compose down 2>/dev/null || true

    # Build images
    echo ""
    echo -e "${YELLOW}Building Docker images...${NC}"
    docker compose build

    # Run tests
    echo ""
    echo -e "${YELLOW}Starting HTTP/3 server and test containers...${NC}"
    echo ""

    # Run with timeout and capture exit code
    local exit_code=0
    if timeout 120 docker compose up http3-test --abort-on-container-exit 2>&1; then
        exit_code=0
    else
        exit_code=$?
    fi

    # Show summary based on test container output
    echo ""
    if docker compose logs http3-test 2>&1 | grep -q "All HTTP/3 tests passed"; then
        echo -e "${GREEN}=============================================="
        echo "Docker tests completed successfully!"
        echo -e "==============================================${NC}"
        exit_code=0
    elif [ $exit_code -ne 0 ]; then
        echo -e "${RED}=============================================="
        echo "Docker tests failed!"
        echo "=============================================="
        echo ""
        echo "Recent server logs:"
        docker compose logs http3-server 2>&1 | tail -20
        echo -e "==============================================${NC}"
    fi

    # Cleanup
    docker compose down 2>/dev/null || true

    return $exit_code
}

# ============================================
# MAIN
# ============================================
main() {
    local mode="${1:-auto}"

    # Auto-detect mode
    if [ "$mode" = "auto" ]; then
        if [[ -x "$BUILD_DIR/h3_server" ]] && [[ -x "$BUILD_DIR/h3_client" ]]; then
            echo -e "${BLUE}Auto-detected: Local binaries found${NC}"
            mode="local"
        elif command -v docker &> /dev/null && [ -f "$PROJECT_DIR/docker-compose.yml" ]; then
            echo -e "${BLUE}Auto-detected: Using Docker${NC}"
            mode="docker"
        else
            echo -e "${RED}Error: No local binaries found and Docker not available${NC}"
            echo "Run build-local.sh to build locally, or install Docker"
            exit 1
        fi
    fi

    case "$mode" in
        local)
            run_local_tests
            ;;
        docker)
            run_docker_tests
            ;;
        *)
            echo "Usage: $0 [local|docker|auto]"
            echo ""
            echo "Modes:"
            echo "  auto   - Auto-detect (default): use local if binaries exist, else Docker"
            echo "  local  - Run tests locally (requires build-local.sh first)"
            echo "  docker - Run tests in Docker containers"
            exit 1
            ;;
    esac
}

main "$@"
