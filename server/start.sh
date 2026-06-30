#!/usr/bin/env bash
# LegitC2 team server — production start (Linux VPS)
# Usage: ./start.sh [--dev]
#
# --dev  : HTTP on 8000, no SSL (local testing)
# default: HTTPS on 8443 with cert.pem / key.pem

set -e
cd "$(dirname "$0")"

DEV=0
[[ "${1:-}" == "--dev" ]] && DEV=1

if [[ $DEV -eq 1 ]]; then
    echo "[start] DEV mode — HTTP 0.0.0.0:8000"
    exec uvicorn main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --log-level info
else
    if [[ ! -f cert.pem || ! -f key.pem ]]; then
        echo "[error] cert.pem / key.pem not found — run gen_cert.sh first"
        exit 1
    fi
    echo "[start] PROD mode — HTTPS 0.0.0.0:8443"
    exec uvicorn main:app \
        --host 0.0.0.0 \
        --port 8443 \
        --ssl-certfile cert.pem \
        --ssl-keyfile  key.pem \
        --log-level info
fi
