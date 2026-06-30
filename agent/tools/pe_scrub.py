#!/usr/bin/env python3
"""
pe_scrub.py — post-build PE normalization.
  - Timestamp: random plausible past date (2021-2024)
  - Checksum:  0x00000000
  - DOS stub padding: randomized (defeats stub fingerprint)
  - Debug directory: timestamp fields zeroed
"""
import sys, os, struct, random, time, datetime

def scrub(path):
    with open(path, 'r+b') as f:
        data = bytearray(f.read())

    if data[:2] != b'MZ':
        print(f"[!] pe_scrub: not a PE: {path}"); return 1

    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        print(f"[!] pe_scrub: bad PE signature"); return 1

    # Random timestamp 2021-01-01 … 2024-06-01
    ts_min = int(time.mktime((2021, 1,  1, 0, 0, 0, 0, 0, 0)))
    ts_max = int(time.mktime((2024, 6,  1, 0, 0, 0, 0, 0, 0)))
    ts = random.randint(ts_min, ts_max)
    struct.pack_into('<I', data, e_lfanew + 8, ts)

    # Zero checksum (Optional Header + 0x40)
    opt_off = e_lfanew + 4 + 20
    struct.pack_into('<I', data, opt_off + 64, 0)

    # Randomize DOS stub padding (0x40 .. e_lfanew-4)
    pad_start, pad_end = 0x40, e_lfanew - 4
    if pad_end > pad_start:
        for i in range(pad_start, pad_end):
            data[i] = random.randint(0, 255)

    # Parse section table (needed for both debug dir and .comment)
    num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt_size     = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    sec_off      = e_lfanew + 24 + opt_size
    magic        = struct.unpack_from('<H', data, opt_off)[0]

    def rva_to_off(rva):
        for s in range(num_sections):
            o = sec_off + s * 40
            va = struct.unpack_from('<I', data, o + 12)[0]
            vs = struct.unpack_from('<I', data, o + 16)[0]
            ro = struct.unpack_from('<I', data, o + 20)[0]
            if va <= rva < va + vs:
                return ro + (rva - va)
        return None

    # Zero debug directory timestamp
    dd_off   = opt_off + (96 if magic == 0x10b else 112) + 6 * 8
    dbg_rva  = struct.unpack_from('<I', data, dd_off)[0]
    dbg_size = struct.unpack_from('<I', data, dd_off + 4)[0]
    if dbg_rva and dbg_size >= 28:
        fo = rva_to_off(dbg_rva)
        if fo:
            struct.pack_into('<I', data, fo + 4, 0)

    # Zero .comment section content (GCC version fingerprint)
    for s in range(num_sections):
        o = sec_off + s * 40
        name = data[o:o+8].rstrip(b'\x00')
        if name == b'.comment':
            raw_sz = struct.unpack_from('<I', data, o + 16)[0]
            raw_off = struct.unpack_from('<I', data, o + 20)[0]
            for i in range(raw_off, raw_off + raw_sz):
                data[i] = 0
            break

    with open(path, 'wb') as f:
        f.write(data)

    ts_str = datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d')
    print(f"[ok] pe_scrub {os.path.basename(path)}  ts={ts_str}  chk=0x00000000")
    return 0

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <pe_file>"); sys.exit(1)
    sys.exit(scrub(sys.argv[1]))
