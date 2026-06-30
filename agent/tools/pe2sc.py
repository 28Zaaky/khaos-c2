#!/usr/bin/env python3
"""
pe2sc.py — convert a PE executable to position-independent shellcode via donut.

Usage:
    python pe2sc.py <input.exe> <output.bin>

Requires ONE of:
  a) pip install donut-shellcode    (Python extension, needs MSVC on Windows)
  b) donut.exe in PATH or tools/    (pre-built binary from github.com/TheWover/donut)

Download donut.exe:
  https://github.com/TheWover/donut/releases
"""
import sys
import os
import subprocess
import shutil


def _via_python(in_path: str, out_path: str) -> bool:
    try:
        import donut  # type: ignore
    except ImportError:
        return False
    shellcode = donut.create(file=in_path, arch=3, entropy=3)
    with open(out_path, "wb") as fh:
        fh.write(shellcode)
    print(f"[ok] {out_path}  ({len(shellcode)} bytes)  [donut python]")
    return True


def _via_binary(in_path: str, out_path: str) -> bool:
    # Look for donut.exe in PATH, then next to this script
    donut_bin = shutil.which("donut") or shutil.which("donut.exe")
    if not donut_bin:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidate  = os.path.join(script_dir, "donut.exe")
        if os.path.exists(candidate):
            donut_bin = candidate
    if not donut_bin:
        return False

    # donut.exe -f 1 (raw) -a 3 (x86+x64) -e 3 (encrypt+random) -o <out> <in>
    cmd = [donut_bin, "-f", "1", "-a", "3", "-e", "3", "-o", out_path, in_path]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr or r.stdout, file=sys.stderr)
        return False
    sz = os.path.getsize(out_path) if os.path.exists(out_path) else 0
    print(f"[ok] {out_path}  ({sz} bytes)  [donut binary]")
    return True


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <input.exe> <output.bin>", file=sys.stderr)
        sys.exit(1)

    in_path, out_path = sys.argv[1], sys.argv[2]

    if not os.path.exists(in_path):
        print(f"error: {in_path}: file not found", file=sys.stderr)
        sys.exit(1)

    if _via_python(in_path, out_path):
        return
    if _via_binary(in_path, out_path):
        return

    print(
        "error: donut not found.\n"
        "  option 1: pip install donut-shellcode  (requires MSVC on Windows)\n"
        "  option 2: place donut.exe in PATH or agent/tools/\n"
        "            https://github.com/TheWover/donut/releases",
        file=sys.stderr,
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
