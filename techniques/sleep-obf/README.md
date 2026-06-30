# sleep-obf

Encrypted sleep obfuscation for Windows x64 implants.

Encrypts the calling module's `.text` section with a `BCryptGenRandom` key, marks it `PAGE_NOACCESS`, pivots to a fake thread context waiting on `NtWaitForSingleObject`, and decrypts on wakeup. Stack scan during sleep shows a legitimate `NtWaitForSingleObject` call chain, not your implant.

Extracted from [KHAOS C2](https://github.com/28Zaaky/khaos-c2).

---

## How it works

```
RtlCaptureContext()          <- save real context (RIP points back here)
       |
       v
CreateThread(_timer_thread)  <- fires Sleep(ms) then SetEvent(done)
       |
       v
XOR .text with 32-byte BCryptGenRandom key
VirtualProtect .text -> PAGE_NOACCESS
Rewrite TEB StackBase/StackLimit -> fake stack
       |
       v
NtContinue(fake_ctx)         <- pivot: RIP=NtWaitForSingleObject, RSP=fake_stack
       |                        stack now shows: NtWait -> RtlUserThreadStart+0x10
       v
[EVENT FIRES after ms]
       |
       v
_sleep_trampoline()          <- on fake stack, called as return from NtWait
       |
       v
XOR .text again (decrypt)
VirtualProtect .text -> PAGE_EXECUTE_READ
Restore TEB stack bounds
NtContinue(real_ctx)         <- resume exactly where RtlCaptureContext was called
```

Key properties:

- **Fake call stack**: during sleep, the thread stack shows `NtWaitForSingleObject` called from `RtlUserThreadStart+0x10`. No implant frames visible.
- **TEB stack bounds rewritten**: `StackBase`/`StackLimit` in the TEB point to the fake stack so ETW stack walks stay within valid bounds.
- **Timer thread in `.run` section**: timer thread code and trampoline are in a separate `.run` section, not `.text`. They keep executing while `.text` is `NOACCESS`.
- **No IAT thunks in critical path**: `VirtualProtect`, `Sleep`, `SetEvent` are resolved to direct function addresses and stored in `obf_ctx_t`. IAT thunks live in `.text` and would fault if called during sleep.
- **NtProtectVirtualMemory** is used instead of `VirtualProtect` to protect the protect call itself from userland hooks.
- **ACG fallback**: if the permission round-trip fails (e.g. ACG-enforced process), falls back to plain `Sleep()`.

---

## Usage

```c
#include "sleep_obf.h"

// basic usage
sleep_obf(5000);  // sleep 5 seconds with .text encrypted

// optional: hook to arm ETW/AMSI hardware breakpoints on the timer thread
// (implement your own or use the hwbp-evasion technique)
g_sleep_obf_thread_hook = my_hwbp_arm_fn;
sleep_obf(5000);
```

---

## Build

Requires MinGW-w64 cross-compiler.

```bash
make
./build/demo.exe
```

On a Windows host with MSVC, adjust `CC`, link `bcrypt.lib` and `ntdll.lib`.

---

## Limitations

- x64 only.
- Requires the calling module to have a `.text` section (standard for PE files).
- Does not survive process suspension during the encryption window (between `CreateThread` and `NtContinue`) — this window is a few microseconds.
- DLLs with `DLL_THREAD_ATTACH` callbacks that touch `.text` will fault during timer thread creation if `.text` is already encrypted. The implementation creates the thread **before** encrypting to avoid this.

### Kernel-mode AV (Kaspersky, ESET, etc.)

Some AV products (notably Kaspersky Total Security / KAV) use kernel-mode callbacks that intercept `NtProtectVirtualMemory` calls targeting the process's own `.text` section. When detected, they terminate the thread via a kernel APC before the syscall returns. **No userland exception handler (VEH, SEH) can catch this** — the VEH is never invoked.

The implementation handles this gracefully: the permission round-trip test (`PAGE_READWRITE` → restore) catches the failure and falls back to plain `Sleep()` before any encryption is attempted. The setjmp/VEH in `_nt_prot` catches the exception on products that raise it (Defender, etc.); for products that issue a kernel APC (Kaspersky), the fallback relies on a clean thread termination message in the OS.

**Testing**: run in a VM without AV, or with AV excluded/disabled, to observe the full sleep obfuscation behavior. The technique is effective against userland-hook-based EDRs (Microsoft Defender, CrowdStrike Falcon in standard config, SentinelOne in detect-only mode).

---

## Operational notes

This PoC uses `GetModuleHandleA`/`GetProcAddress` with plaintext strings. In production:

- Replace with a PEB walk (`__readgsqword(0x60)`) to resolve modules without touching the IAT or leaving strings in `.rdata`.
- Encrypt sensitive string literals (see EVS XOR in KHAOS C2).

---

## Credits

Technique originally described by [Ekko](https://github.com/Cracked5pider/Ekko) (Cracked5pider). This implementation extends it with:

- `NtProtectVirtualMemory` instead of `VirtualProtect` for the permission flip
- TEB `StackBase`/`StackLimit` rewrite for ETW stack walk validity
- Fallback path for ACG-enforced environments
- Thread hook integration point for HWBP-based ETW/AMSI bypass

---

*Part of [KHAOS C2](https://github.com/28Zaaky/khaos-c2) — by [28Zaaky](https://github.com/28Zaaky)*
