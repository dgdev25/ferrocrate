#!/bin/bash
# Setup script for Linux desktop app dependencies
# Run with: ./scripts/setup-linux-desktop.sh

set -e

echo "🔧 FerroCrate Desktop - Linux Setup"
echo "===================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run with sudo"
   echo "   Run: sudo ./scripts/setup-linux-desktop.sh"
   exit 1
fi

echo "📦 Installing Tauri build dependencies for Linux..."

# Update package list
apt-get update > /dev/null

# Install required packages for Tauri on Linux
PACKAGES=(
    "libwebkit2gtk-4.1-dev"    # WebKit2GTK development headers
    "libsoup-3.0-dev"          # libsoup3 development headers
    "libgtk-3-dev"             # GTK3 development headers (usually installed, but ensure)
    "libssl-dev"               # OpenSSL development headers
    "pkg-config"               # pkg-config tool
    "build-essential"          # GCC and build tools
    "libclang-dev"             # Clang development headers (for some crates)
)

echo ""
echo "Installing packages:"
for pkg in "${PACKAGES[@]}"; do
    echo "  • $pkg"
done
echo ""

apt-get install -y "${PACKAGES[@]}" 2>&1 | grep -E "^(Setting|Unpacking|Processing|Reading|Building)" || true

echo ""
echo "✅ Dependencies installed successfully!"
echo ""
echo "Next steps:"
echo "1. cd /media/USER/datadisk/dev/ferrocrate/apps/ferro-desktop-ui"
echo "2. npm install (if not already done)"
echo "3. npm run tauri:build"
echo ""
