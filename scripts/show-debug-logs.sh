#!/bin/bash
# Show RFC 9114 debug logs from the HTTP/3 test run
# Filters for the detailed frame dumps and translations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=========================================="
echo "HTTP/3 RFC 9114 Debug Output"
echo "=========================================="
echo ""

# Check if containers are running or have logs
if ! docker compose ps -q 2>/dev/null | grep -q .; then
    echo "No running containers. Running test first..."
    echo ""
    docker compose up --abort-on-container-exit 2>&1 | head -100
    echo ""
fi

echo "=== CLIENT DEBUG (RFC 9114 Frames) ==="
docker compose logs http3-client 2>&1 | grep -E "(RFC 9114|Frame Type|Frame Length|Interpretation|SETTINGS_)" | head -50

echo ""
echo "=== SERVER DEBUG (RFC 9114 Frames) ==="
docker compose logs http3-server 2>&1 | grep -E "(RFC 9114|Frame Type|Frame Length|Interpretation|SETTINGS_)" | head -50

echo ""
echo "=== RAW HEX DUMPS ==="
docker compose logs 2>&1 | grep "raw hex" | head -20

# Cleanup
docker compose down 2>/dev/null || true
