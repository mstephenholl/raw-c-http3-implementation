#!/bin/bash
# Install dependencies for building HTTP/3 implementation on macOS
# Requires Homebrew

set -e

echo "=========================================="
echo "Installing HTTP/3 dependencies for macOS"
echo "=========================================="

# Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "Error: Homebrew is required. Install from https://brew.sh"
    exit 1
fi

echo ""
echo "Installing build tools..."
brew install cmake pkg-config autoconf automake libtool

echo ""
echo "Installing OpenSSL (with QUIC support)..."
# Note: Standard Homebrew OpenSSL doesn't have QUIC support
# We need to build quictls from source
brew install openssl@3  # For headers reference

INSTALL_PREFIX="$HOME/.local"
mkdir -p "$INSTALL_PREFIX"

echo ""
echo "Building quictls (OpenSSL with QUIC support)..."
TMPDIR=$(mktemp -d)
cd "$TMPDIR"

git clone --depth 1 --branch openssl-3.1.5-quic1 https://github.com/quictls/openssl.git
cd openssl
./Configure --prefix="$INSTALL_PREFIX" --openssldir="$INSTALL_PREFIX/ssl" --libdir=lib
make -j$(sysctl -n hw.ncpu)
make install_sw

echo ""
echo "Building ngtcp2..."
cd "$TMPDIR"
git clone --depth 1 --branch v1.2.0 https://github.com/ngtcp2/ngtcp2.git
cd ngtcp2
autoreconf -fi
PKG_CONFIG_PATH="$INSTALL_PREFIX/lib/pkgconfig" \
LDFLAGS="-L$INSTALL_PREFIX/lib" \
CFLAGS="-I$INSTALL_PREFIX/include" \
./configure --prefix="$INSTALL_PREFIX" --enable-lib-only --with-openssl
make -j$(sysctl -n hw.ncpu)
make install

# Cleanup
rm -rf "$TMPDIR"

echo ""
echo "=========================================="
echo "Installation complete!"
echo "=========================================="
echo ""
echo "Libraries installed to: $INSTALL_PREFIX"
echo ""
echo "Add to your shell profile:"
echo "  export PKG_CONFIG_PATH=\"$INSTALL_PREFIX/lib/pkgconfig:\$PKG_CONFIG_PATH\""
echo "  export LD_LIBRARY_PATH=\"$INSTALL_PREFIX/lib:\$LD_LIBRARY_PATH\""
echo "  export DYLD_LIBRARY_PATH=\"$INSTALL_PREFIX/lib:\$DYLD_LIBRARY_PATH\""
echo ""
echo "Then run: ./scripts/build-local.sh"
