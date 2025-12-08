#!/bin/bash
# Validate HTTP/3 implementation in Docker
# Runs the full test suite and reports results

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=========================================="
echo "HTTP/3 Implementation Validation"
echo "=========================================="
echo ""

# Clean up any previous containers
echo "Cleaning up previous containers..."
docker compose down 2>/dev/null || true

# Build images
echo ""
echo "Building Docker images..."
docker compose build

# Run tests
echo ""
echo "Running HTTP/3 client-server test..."
echo ""

# Run with timeout and capture exit code
if timeout 60 docker compose up --abort-on-container-exit 2>&1; then
    EXIT_CODE=0
else
    EXIT_CODE=$?
fi

# Show summary
echo ""
echo "=========================================="
if docker compose logs http3-client 2>&1 | grep -q "HTTP/3 TEST: SUCCESS"; then
    echo "✓ TEST PASSED: HTTP/3 communication successful"
    echo ""
    echo "Key events:"
    docker compose logs http3-client 2>&1 | grep -E "(Handshake completed|Response status|Request completed)" | head -5
else
    echo "✗ TEST FAILED"
    echo ""
    echo "Recent logs:"
    docker compose logs 2>&1 | tail -30
fi
echo "=========================================="

# Cleanup
docker compose down 2>/dev/null || true

exit $EXIT_CODE
