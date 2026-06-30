# hwbp-evasion

ETW and AMSI bypass using hardware breakpoints and a Vectored Exception Handler (VEH). No patching, no memory writes to protected regions — the breakpoints live entirely in CPU debug registers.

Extracted from [KHAOS C2](https://github.com/28Zaaky/khaos-c2).

---

## How it works

x64 debug registers `Dr0`–`Dr3` can each watch an address for execution. When the CPU hits a watched address, it raises `EXCEPTION_SINGLE_STEP` before executing the instruction. A VEH registered as the first handler in the chain intercepts that exception, manipulates the thread context, and returns `EXCEPTION_CONTINUE_EXECUTION` — the original function never executes.

```
hwbp_patch_all()
  |
  +-> resolve EtwEventWrite    -> Dr0
  +-> resolve AmsiScanBuffer   -> Dr1
  +-> resolve AmsiScanString   -> Dr2
  +-> set Dr7 local enable bits
  +-> AddVectoredExceptionHandler(1, _hwbp_veh)   <- first in chain

[AV calls AmsiScanBuffer]
  |
  +-> CPU fires EXCEPTION_SINGLE_STEP (Dr1 match)
  |
  +-> _hwbp_veh()
        Rax  = E_INVALIDARG (0x80070057)
        Rip  = [Rsp]          <- skip to caller's return address
        Rsp += 8
        Dr6 &= ~0x2           <- clear B1 status bit
        return EXCEPTION_CONTINUE_EXECUTION

[AmsiScanBuffer never executed — caller sees E_INVALIDARG]
```

Same logic for `EtwEventWrite` (returns `STATUS_SUCCESS`) and `AmsiScanString` (returns `E_INVALIDARG`).

---

## Why hardware breakpoints

Compared to memory patching (`mov rax, ret`) or inline hooks:

- **No writes to protected pages** — no `VirtualProtect` calls that EDR hooks watch
- **No detectable byte modifications** in ntdll or amsi.dll — memory integrity scans find nothing
- **Per-thread** — debug registers are thread-local, so the bypass only applies to threads where `hwbp_apply_thread` is called
- **Revocable at runtime** — clear Dr7 bits to disable without touching any DLL

The tradeoff: Dr0–Dr3 are also used by debuggers and some EDR products. If a debugger owns those registers, conflicts can occur.

---

## API

```c
void hwbp_patch_etw(void);          // arm Dr0 -> EtwEventWrite
void hwbp_patch_amsi(void);         // arm Dr1 -> AmsiScanBuffer, Dr2 -> AmsiScanString
void hwbp_patch_all(void);          // arm all three

void hwbp_apply_thread(HANDLE ht);  // propagate active breakpoints to another thread
```

`hwbp_apply_thread` is useful when spawning new threads (e.g. the timer thread in sleep obfuscation) that will also call ETW-instrumented code.

---

## Integration with sleep-obf

The `.run` section attribute on `_hwbp_veh` keeps the handler executable when `.text` is `PAGE_NOACCESS` during obfuscated sleep:

```c
// in your sleep callback, before encrypting .text:
g_sleep_obf_thread_hook = hwbp_apply_thread;
sleep_obf(5000);
```

This ensures the timer thread also has the breakpoints armed and won't trigger ETW during sleep.

---

## Build

```bash
make
./build/demo.exe
```

Expected output (on a system with AMSI loaded):

```
[*] without bypass:
[before] hr=0x00000000  result=32  detected=YES
[*] arming HWBP bypass...
[+] armed
[*] with bypass:
[after ] hr=0x80070057  result=0   detected=no
```

---

## Limitations

- x64 only.
- Debug registers are thread-local. Call `hwbp_apply_thread` for every thread that needs the bypass.
- Some EDR products monitor `SetThreadContext` calls that modify debug registers. The call on `GetCurrentThread()` is less visible than cross-thread calls.
- If a kernel-mode ETW provider (`EtwTi*`) is active, this bypass does not cover it. See the ntdll-unhook technique for `EtwTiLogOpenProcess` / `EtwTiLogReadWriteVm` / `EtwTiLogDuplicateHandle`.

---

## Operational notes

This PoC uses plaintext strings and `GetModuleHandleA`. In production:

- Resolve modules via PEB walk (`__readgsqword(0x60)`)
- Encrypt string literals at compile time
- Use `LoadLibraryA` only if amsi.dll is not already in the PEB module list — calling `LoadLibraryA` itself is a detectable event

---

*Part of [KHAOS C2](https://github.com/28Zaaky/khaos-c2) — by [28Zaaky](https://github.com/28Zaaky)*
