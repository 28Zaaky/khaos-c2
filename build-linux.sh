#!/usr/bin/env bash
# ============================================================
# KHAOS C2 — Build script for Kali Linux / Debian
# Run this on the Linux machine where you want to build
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$SCRIPT_DIR/server"
UI_DIR="$SCRIPT_DIR/ui"
BINARIES_DIR="$UI_DIR/src-tauri/binaries"

echo "[*] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    curl wget git build-essential pkg-config \
    libssl-dev libsqlite3-dev python3 python3-pip python3-venv \
    libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
    librsvg2-dev patchelf

# ---- Node.js ----
if ! command -v node &>/dev/null; then
    echo "[*] Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

# ---- Rust ----
if ! command -v cargo &>/dev/null; then
    echo "[*] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
source "$HOME/.cargo/env"

# ---- Python venv ----
echo "[*] Setting up Python venv..."
cd "$SERVER_DIR"
python3 -m venv venv
./venv/bin/pip install -q -r requirements.txt
./venv/bin/pip install -q pyinstaller

# ---- Build khaos-server (Linux binary) ----
echo "[*] Building khaos-server with PyInstaller..."
./venv/bin/pyinstaller --clean khaos-server.spec

# Copy sidecar with Linux target triple name
mkdir -p "$BINARIES_DIR"
TRIPLE="x86_64-unknown-linux-gnu"
cp dist/khaos-server "$BINARIES_DIR/khaos-server-$TRIPLE"
chmod +x "$BINARIES_DIR/khaos-server-$TRIPLE"
echo "[+] Sidecar copied: khaos-server-$TRIPLE"

# ---- Build Tauri UI ----
echo "[*] Installing npm dependencies..."
cd "$UI_DIR"
npm install --silent

echo "[*] Building Tauri app for Linux..."
cargo tauri build

echo ""
echo "[+] Build complete!"
echo "    .deb:     $UI_DIR/src-tauri/target/release/bundle/deb/"
echo "    AppImage: $UI_DIR/src-tauri/target/release/bundle/appimage/"
echo ""
echo "[!] Config & DB will be stored in ~/.local/share/KHAOS/ on first run"
