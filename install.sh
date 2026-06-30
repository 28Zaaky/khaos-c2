#!/usr/bin/env bash
# install.sh — KHAØS C2 setup (Ubuntu 22.04+ / Debian 12+)
# Usage: bash install.sh
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GRN}[*]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
die()   { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

# ── Root check ──────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash install.sh"

# ── Deps ────────────────────────────────────────────────────────────────────
info "Installing system dependencies..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    gcc-mingw-w64-x86-64 \
    binutils-mingw-w64-x86-64 \
    mingw-w64 \
    make \
    python3 python3-pip python3-venv \
    nodejs npm \
    openssl \
    curl \
    git 2>/dev/null

# ── Python server deps ───────────────────────────────────────────────────────
info "Installing Python server dependencies..."
pip3 install -q -r server/requirements.txt

# ── UI build ─────────────────────────────────────────────────────────────────
info "Building UI..."
cd ui
npm ci --silent
npm run build --silent
cd ..

# ── TLS cert ─────────────────────────────────────────────────────────────────
if [[ ! -f server/cert.pem ]]; then
    info "Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout server/cert.key \
        -out    server/cert.pem \
        -subj   "/CN=khaos-c2" \
        -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null
    info "cert.pem + cert.key generated."
else
    warn "cert.pem already exists — skipping TLS generation."
fi

# ── Config ───────────────────────────────────────────────────────────────────
if [[ ! -f server/config.yaml ]]; then
    cp server/config.example.yaml server/config.yaml
    JWT=$(openssl rand -base64 32)
    sed -i "s|GENERATE_WITH: openssl rand -base64 32|${JWT}|" server/config.yaml
    warn "server/config.yaml created with a random JWT secret."
    warn "Edit it to fill in your channel credentials (Teams / Gist / HTTP / DoH)."
else
    warn "server/config.yaml already exists — skipping."
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GRN}Setup complete.${NC}"
echo ""
echo "  Next steps:"
echo "  1. Edit server/config.yaml  — add your channel credentials"
echo "  2. python3 server/main.py   — start the C2 server"
echo "  3. Open http://localhost:8443 or use the UI Build tab to generate agent.exe"
echo ""
echo "  Default login: operator / changeme"
echo "  Change via:    KHAOS_OPERATOR_USER=x KHAOS_OPERATOR_PASS=y python3 server/main.py"
echo ""
