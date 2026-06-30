#!/usr/bin/env python3
"""
Get the SHA-256 pin of a TLS server's leaf certificate (DER bytes).
Usage:  python tools/get_cert_pin.py <host> [port]

Output: 64 hex chars — paste into server/config.yaml → http.cert_pin
"""
import ssl, socket, hashlib, sys

host = sys.argv[1] if len(sys.argv) > 1 else None
port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

if not host:
    print("Usage: python tools/get_cert_pin.py <host> [port]")
    sys.exit(1)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

try:
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            pin = hashlib.sha256(der).hexdigest()
            print(f"[+] {host}:{port}")
            print(f"[+] SHA-256 pin: {pin}")
            print()
            print(f"# Paste into server/config.yaml:")
            print(f'    cert_pin: "{pin}"')
except Exception as e:
    print(f"[-] Error: {e}", file=sys.stderr)
    sys.exit(1)
