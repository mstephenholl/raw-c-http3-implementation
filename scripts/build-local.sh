#!/bin/bash
# Build HTTP/3 implementation locally (without Docker)
# Run install-deps-macos.sh or install-deps-linux.sh first

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=========================================="
echo "Building HTTP/3 Implementation"
echo "=========================================="

# Set up paths for locally installed dependencies
INSTALL_PREFIX="$HOME/.local"

if [[ ! -d "$INSTALL_PREFIX/lib/pkgconfig" ]]; then
    echo "Error: Dependencies not found at $INSTALL_PREFIX"
    echo ""
    echo "Please run the appropriate install script first:"
    echo "  macOS:  ./scripts/install-deps-macos.sh"
    echo "  Linux:  ./scripts/install-deps-linux.sh"
    exit 1
fi

export PKG_CONFIG_PATH="$INSTALL_PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$INSTALL_PREFIX/lib:$LD_LIBRARY_PATH"
export DYLD_LIBRARY_PATH="$INSTALL_PREFIX/lib:$DYLD_LIBRARY_PATH"

# Create build directory
BUILD_DIR="$PROJECT_DIR/build"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo ""
echo "Configuring with CMake..."

# On macOS, ensure we use the native clang compiler (not cross-compilers like arm-none-eabi-gcc)
if [[ "$(uname)" == "Darwin" ]]; then
    export CC=/usr/bin/clang
    export CXX=/usr/bin/clang++
fi

cmake "$PROJECT_DIR" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DOPENSSL_ROOT_DIR="$INSTALL_PREFIX"

echo ""
echo "Building..."
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Copy compile_commands.json to project root for IDE support
if [[ -f "$BUILD_DIR/compile_commands.json" ]]; then
    cp "$BUILD_DIR/compile_commands.json" "$PROJECT_DIR/"
fi

echo ""
echo "=========================================="
echo "Build complete!"
echo "=========================================="
echo ""
echo "Binaries:"
echo "  $BUILD_DIR/h3_server"
echo "  $BUILD_DIR/h3_client"
echo ""
echo "Run tests with: ./scripts/run-local-test.sh"
