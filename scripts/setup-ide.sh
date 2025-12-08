#!/bin/bash
# Setup script for IDE support (generates compile_commands.json)
# This helps IDEs like VSCode/CLion resolve includes and detect issues

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Setting up IDE support for HTTP/3 implementation..."

# Check if we're on macOS and need to use Homebrew OpenSSL
if [[ "$(uname)" == "Darwin" ]]; then
    echo "Detected macOS, checking for Homebrew OpenSSL..."

    if command -v brew &> /dev/null; then
        OPENSSL_PREFIX=$(brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo "")
        if [[ -n "$OPENSSL_PREFIX" ]]; then
            echo "Found OpenSSL at: $OPENSSL_PREFIX"
            export PKG_CONFIG_PATH="$OPENSSL_PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH"
        fi
    fi
fi

# Create build directory
BUILD_DIR="$PROJECT_DIR/build-ide"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "Generating compile_commands.json..."

# Try to configure with CMake
# This may fail if dependencies aren't installed locally, but that's OK
# The point is to help the IDE understand the project structure
cmake "$PROJECT_DIR" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_BUILD_TYPE=Debug \
    2>&1 || {
    echo ""
    echo "Note: CMake configuration failed (dependencies may not be installed locally)"
    echo "This is expected if you're only building in Docker."
    echo ""
    echo "Creating a basic compile_commands.json for IDE support..."

    # Create a minimal compile_commands.json for IDE parsing
    cat > "$PROJECT_DIR/compile_commands.json" << 'EOF'
[
  {
    "directory": ".",
    "file": "src/http3_common.c",
    "arguments": ["cc", "-I", "include", "-Wall", "-Wextra", "-c", "src/http3_common.c"]
  },
  {
    "directory": ".",
    "file": "src/h3_client.c",
    "arguments": ["cc", "-I", "include", "-Wall", "-Wextra", "-c", "src/h3_client.c"]
  },
  {
    "directory": ".",
    "file": "src/h3_server.c",
    "arguments": ["cc", "-I", "include", "-Wall", "-Wextra", "-c", "src/h3_server.c"]
  }
]
EOF
    echo "Created basic compile_commands.json"
    exit 0
}

# Copy compile_commands.json to project root for IDE discovery
if [[ -f "$BUILD_DIR/compile_commands.json" ]]; then
    cp "$BUILD_DIR/compile_commands.json" "$PROJECT_DIR/"
    echo "compile_commands.json copied to project root"
fi

echo ""
echo "IDE setup complete!"
echo "Your IDE should now be able to resolve includes and detect issues."
