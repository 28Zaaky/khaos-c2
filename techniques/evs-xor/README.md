# evs-xor

Compile-time XOR string obfuscation for Windows implants. Prevents API/DLL name strings from appearing in `.rdata`, defeating static YARA rules that match literal API names.

Extracted from [KHAOS C2](https://github.com/28Zaaky/khaos-c2).

---

## The problem

Any implant that calls `GetProcAddress(ntdll, "NtOpenProcess")` has the string `"NtOpenProcess"` sitting in `.rdata`. A two-line YARA rule catches every implant that uses that API by name. Same for `"AmsiScanBuffer"`, `"EtwEventWrite"`, `"lsass.exe"`, `"SeDebugPrivilege"`, etc.

```
strings build/implant.exe | grep NtOpenProcess
    → NtOpenProcess        ← instant YARA hit
```

---

## How EVS XOR solves it

**Build time** (Python generator):

1. `gen_evs.py` reads your string table (`strings.txt`).
2. Picks a random 1-byte XOR key (`secrets.randbelow(256)`, non-zero).
3. XOR-encodes each string byte-by-byte.
4. Writes `include/evs_strings.h` with static byte arrays + `EVS_KEY` define.

Key changes on every build → every byte array changes → no static YARA rule survives a rebuild.

**Runtime** (C decoder):

```c
char buf[16] = {0};
EVS_D(buf, EVS_dll_ntdll);      // XOR decode "ntdll.dll" into buf at runtime
HMODULE h = GetModuleHandleA(buf);
SecureZeroMemory(buf, sizeof(buf));  // wipe from stack
```

**Why `noinline`:**

One hundred `EVS_D()` calls inlined = one hundred short identical XOR loops in `.text`. ML-based AV heuristics flag high density of identical short loops as a packing / shellcode signature. `__attribute__((noinline))` keeps a single function body — one code pattern, not one hundred.

---

## Usage

### 1. Add strings to `strings.txt`

```
# Format: plaintext_value   C_identifier_suffix

ntdll.dll               dll_ntdll
NtOpenProcess           fn_NtOpenProcess
AmsiScanBuffer          fn_AmsiScanBuffer
lsass.exe               str_lsass
```

### 2. Generate header

```bash
python gen_evs.py strings.txt -o include/evs_strings.h
# or just: make
```

Output: `include/evs_strings.h` with randomized key + encoded arrays.

### 3. Include and use

```c
#include "evs.h"
#include "evs_strings.h"

// decode at the call site, use, wipe
char dll[16] = {0};
EVS_D(dll, EVS_dll_ntdll);
HMODULE h = GetModuleHandleA(dll);
SecureZeroMemory(dll, sizeof(dll));

char fn[24] = {0};
EVS_D(fn, EVS_fn_NtOpenProcess);
FARPROC p = GetProcAddress(h, fn);
SecureZeroMemory(fn, sizeof(fn));
```

### Rebuild with new key

```bash
make rekey   # deletes evs_strings.h, regenerates with a new random key, rebuilds
```

---

## Build

```bash
make
./build/demo.exe
```

Expected output:

```
[*] EVS_KEY = 0xCC  (random per build — changes every make)

[*] Encoded arrays in .rodata (no plaintext):
  EVS_dll_ntdll                A2 B8 A8 A0 A0 E2 A8 A0 A0
  EVS_fn_NtOpenProcess         82 B8 83 BC A9 A2 9C BE A3 AF ...
  ...

[*] Decoded at runtime:
  dll:       ntdll.dll
  api:       NtOpenProcess
  api:       EtwEventWrite
  ...

[+] GetModuleHandleA(ntdll.dll)   = 0x00007ffe2fc40000
[+] GetProcAddress(NtOpenProcess) = 0x00007ffe2fda0510
[+] EVS XOR working — no plaintext strings, APIs resolved correctly
```

Verify no plaintext leaks:

```powershell
$b = [IO.File]::ReadAllBytes("build\demo.exe")
$t = [Text.Encoding]::Latin1.GetString($b)
[regex]::Matches($t,'[!-~]{5,}') | Where Value -match "ntdll|NtOpen|AmsiScan"
# → 0 results
```

---

## gen_evs.py options

```
usage: gen_evs.py [strings.txt] [-o header.h] [-k 0xNN]

positional:
  strings.txt    string table file (default: strings.txt)

optional:
  -o PATH        output header path (default: include/evs_strings.h)
  -k 0xNN        fixed XOR key — useful for testing; random by default
```

---

## Limitations

- **Single-byte XOR** — simple but sufficient to defeat static string matching. Not cryptographically strong. A determined analyst can brute-force 255 keys in milliseconds. The goal is defeating *static* AV/YARA, not a human analyst.
- **Key in binary** — `EVS_KEY` is a literal in the compiled binary. Visible in a hex dump. Sufficient for static scanning evasion; not for obfuscating against reverse engineering.
- **`SecureZeroMemory` is advisory** — compiler may optimize it away with LTO. Use `volatile` wipes or `explicit_bzero` in hardened production code.
- **Import table still names `KERNEL32.dll`** — any PE that calls `GetProcAddress` will. Replace with a PEB walk to eliminate even that reference.

---

## Operational notes

- **Stack buffer sizing**: `EVS_D(buf, EVS_foo)` writes `sizeof(EVS_foo) + 1` bytes. Allocate `sizeof(EVS_foo) + 1` minimum.
- **Thread safety**: `evs_dec()` is stateless — safe to call from multiple threads.
- **Integration with PEB walk**: pair EVS with a PEB module walker to resolve DLLs without any string in the import table or `.rdata`.
- **Integration with indirect syscalls**: EVS encodes Nt* function names passed to `sc_ssn()` — no plaintext syscall names appear even in the SSN resolver.

---

*Part of [KHAOS C2](https://github.com/28Zaaky/khaos-c2) — by [28Zaaky](https://github.com/28Zaaky)*
