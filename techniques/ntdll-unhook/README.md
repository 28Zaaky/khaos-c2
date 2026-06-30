# ntdll-unhook

Restore ntdll.dll `.text` from a fresh disk mapping to remove EDR inline hooks. Also patches `EtwTi*` telemetry functions with a single `RET`.

Extracted from [KHAOS C2](https://github.com/28Zaaky/khaos-c2).

---

## How it works

EDR products hook ntdll syscall stubs by overwriting the first bytes with a `JMP` to their trampoline:

```
NtOpenProcess (hooked):
  E9 xx xx xx xx    JMP <edr_hook>
  ...

NtOpenProcess (clean):
  4C 8B D1          mov r10, rcx
  B8 26 00 00 00    mov eax, 0x26   ; SSN
  0F 05             syscall
  C3                ret
```

### ntdll_unhook()

```
CreateFileW(SystemDir\ntdll.dll, GENERIC_READ)
  |
  v
CreateFileMappingW(PAGE_READONLY | SEC_IMAGE)   <- kernel maps + validates PE
  |
  v
MapViewOfFile(FILE_MAP_READ)                    <- clean image, no hooks
  |
  v
walk .text section in disk image
  |
  v
NtProtectVirtualMemory(live .text, PAGE_EXECUTE_READWRITE)
memcpy(live .text, disk .text, VirtualSize)
NtProtectVirtualMemory(live .text, original perms)
```

Key: `SEC_IMAGE` tells the kernel to map the file as a PE image (applying relocations, verifying signature). The result is a clean in-memory copy of ntdll identical to what the Windows loader would produce — before any userland hooks are applied.

`NtProtectVirtualMemory` is used instead of `VirtualProtect` because `VirtualProtect` itself goes through ntdll and may be hooked.

### ntdll_patch_etw_ti()

Patches three functions in ntdll that feed the kernel ETW-TI (Threat Intelligence) provider:

| Function | Event |
|---|---|
| `EtwTiLogOpenProcess` | fires on `NtOpenProcess` |
| `EtwTiLogReadWriteVm` | fires on `NtReadVirtualMemory` / `NtWriteVirtualMemory` |
| `EtwTiLogDuplicateHandle` | fires on `NtDuplicateObject` |

Each is overwritten with `0xC3` (RET). These functions are in ntdll's `.text` section and do not require kernel interaction to patch.

---

## API

```c
int ntdll_unhook(void);       // restore .text — returns 0 on success, -1 on failure
int ntdll_patch_etw_ti(void); // patch 3 EtwTi functions — returns count patched (0-3)
```

---

## Build

```bash
make
build/demo.exe
```

Expected output on an unhooked system:

```
[*] NtOpenProcess bytes before unhook:
[before] 4C 8B D1 B8 26 00 00 00
[*] ntdll_unhook() = 0 (OK)
[*] NtOpenProcess bytes after unhook:
[after ] 4C 8B D1 B8 26 00 00 00
[+] stub is clean
[*] ntdll_patch_etw_ti() patched 3/3 functions
```

On an EDR-hooked system, `before` will show `E9 ...` (JMP trampoline) and `after` will show the clean syscall stub.

---

## Limitations

- Restores `.text` only — hooks in other sections (`.data`, import table patching) are not removed.
- Does not re-register exception tables (`.pdata`) for the restored `.text`. If the EDR modified anything related to unwind data, this won't fix it.
- `EtwTi*` patch survives ntdll reload but not process restart.
- Some EDR products monitor `NtMapViewOfSection` for `SEC_IMAGE` mappings of system DLLs. Consider calling `ntdll_unhook` as early as possible (before EDR's DLL loads).

---

## Operational notes

Call order matters: unhook ntdll **before** patching ETW-TI, so `NtProtectVirtualMemory` calls in `ntdll_patch_etw_ti` go through a clean syscall stub.

For cross-process injection, unhook in the **target process** context by embedding this code in your shellcode or reflective DLL payload — not from the injector.

---

*Part of [KHAOS C2](https://github.com/28Zaaky/khaos-c2) — by [28Zaaky](https://github.com/28Zaaky)*
