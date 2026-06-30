#!/usr/bin/env bash
# Generate self-signed cert for dev / VPS without Let's Encrypt
# For production with a real domain, use:
#   certbot certonly --standalone -d your-domain.com
#   then symlink: cert.pem -> fullchain.pem, key.pem -> privkey.pem
#
# Usage: ./gen_cert.sh [CN]   (default CN = localhost)

CN="${1:-localhost}"
DAYS=365

openssl req -x509 -newkey rsa:4096 -sha256 \
    -keyout key.pem \
    -out    cert.pem \
    -days   $DAYS \
    -nodes \
    -subj   "/CN=${CN}" \
    -addext "subjectAltName=DNS:${CN},IP:127.0.0.1"

echo "[ok] cert.pem / key.pem generated (CN=${CN}, ${DAYS}d)"
