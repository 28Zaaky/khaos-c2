# ShdwLdr

Reflective DLL loader for Windows x64. Maps a raw DLL from memory without the Windows loader.  

By 28Zaaky — [KHAOS C2](https://github.com/28Zaaky/khaos-c2)

## Techniques

- Hash-based API resolution (ROR13, no plaintext strings)
- Hell's Gate + Halos Gate + Tartarus Gate (direct syscalls, hooked stub recovery)
- Per-section permissions via `NtProtectVirtualMemory` syscall
- TLS callbacks + slot allocation before `DllMain`
- `RtlAddFunctionTable` for x64 SEH
- AMSI + ETW bypass
- Header erasure, security cookie init

## Build

```bash
x86_64-w64-mingw32-gcc -O2 -Iinclude -fno-asynchronous-unwind-tables \
  -fno-ident -fno-stack-protector -Wl,--file-alignment,0x1000 \
  -shared -o build/example.dll src/reflect.c src/example_dll.c

x86_64-w64-mingw32-gcc -O2 -Iinclude -fno-asynchronous-unwind-tables \
  -fno-ident -fno-stack-protector -o build/loader.exe examples/loader.c
```

> `--file-alignment,0x1000` : `PointerToRawData == VirtualAddress` — required for RIP-relative access while running from the raw buffer.

## Usage

```c
uint8_t *mem = VirtualAlloc(NULL, sz, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(mem, raw_dll, sz);
typedef ULONG_PTR (WINAPI *RL_t)(LPVOID);
ULONG_PTR base = ((RL_t)find_export(mem, "ReflectiveLoader"))(mem);
```

## Notes

- x64 only. No module list entry added.
- Module stomping disabled — `LoadLibraryExA(DONT_RESOLVE_DLL_REFERENCES)` calls `DllMain` on Win10+. Needs `NtMapViewOfSection`.
- `_rl_dbg` export contains runtime telemetry (SSNs, alloc method) — strip for production.
