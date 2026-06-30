#include "indirect_syscall.h"
#include <windows.h>
#include <stdio.h>

/*
 * Demo: allocate a page via indirect NtAllocateVirtualMemory, write bytes,
 * flip to PAGE_EXECUTE_READ via indirect NtProtectVirtualMemory, verify.
 *
 * On an EDR-hooked system, sc_ssn() uses Halo's Gate to recover the real SSN
 * even when the syscall stub starts with a JMP trampoline.
 */

int main(void)
{
    printf("[*] sc_init()...\n");
    if (sc_init() != 0) {
        printf("[!] sc_init failed — no syscall;ret gadget found in ntdll .text\n");
        return 1;
    }

    printf("[+] sc_gadget  = %p  (syscall;ret in ntdll .text — indirect jmp target)\n",
           sc_gadget);
    printf("[+] sc_frame1  = %p  (KernelBase ret gadget — inner spoof frame)\n",
           sc_frame1);
    printf("[+] sc_frame2  = %p  (ntdll ret gadget — outer spoof frame)\n\n",
           sc_frame2);

    /* Resolve SSNs */
    uint16_t ssn_alloc = sc_ssn("NtAllocateVirtualMemory");
    uint16_t ssn_prot  = sc_ssn("NtProtectVirtualMemory");
    uint16_t ssn_free  = sc_ssn("NtFreeVirtualMemory");
    uint16_t ssn_write = sc_ssn("NtWriteVirtualMemory");
    uint16_t ssn_open  = sc_ssn("NtOpenProcess");

    printf("[*] SSN NtAllocateVirtualMemory = 0x%04X\n", ssn_alloc);
    printf("[*] SSN NtProtectVirtualMemory  = 0x%04X\n", ssn_prot);
    printf("[*] SSN NtFreeVirtualMemory     = 0x%04X\n", ssn_free);
    printf("[*] SSN NtWriteVirtualMemory    = 0x%04X\n", ssn_write);
    printf("[*] SSN NtOpenProcess           = 0x%04X\n\n", ssn_open);

    if (ssn_alloc == 0xFFFF || ssn_prot == 0xFFFF) {
        printf("[!] SSN resolve failed — Halo's Gate unable to find clean neighbor\n");
        return 1;
    }

    /*
     * NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
     *                         RegionSize, AllocationType, Protect)
     */
    HANDLE proc = (HANDLE)(LONG_PTR)-1;   /* current process */
    PVOID  base = NULL;
    SIZE_T sz   = 0x1000;

    NTSTATUS st = sc_call(ssn_alloc,
        (uintptr_t)proc,
        (uintptr_t)&base,
        0,
        (uintptr_t)&sz,
        (uintptr_t)(MEM_COMMIT | MEM_RESERVE),
        (uintptr_t)PAGE_READWRITE,
        0, 0, 0, 0, 0);

    if (st != 0 || !base) {
        printf("[!] NtAllocateVirtualMemory failed: 0x%08X\n", (unsigned)st);
        return 1;
    }
    printf("[+] NtAllocateVirtualMemory: base=%p  sz=0x%zX  st=0x%08X\n",
           base, sz, (unsigned)st);

    /* Write a recognizable marker — page is PAGE_READWRITE at this point */
    ((BYTE *)base)[0] = 0xDE;
    ((BYTE *)base)[1] = 0xAD;
    ((BYTE *)base)[2] = 0xBE;
    ((BYTE *)base)[3] = 0xEF;

    /*
     * NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize,
     *                        NewProtect, OldProtect)
     */
    PVOID  pbase = base;
    SIZE_T psz   = 0x1000;
    ULONG  old   = 0;

    st = sc_call(ssn_prot,
        (uintptr_t)proc,
        (uintptr_t)&pbase,
        (uintptr_t)&psz,
        (uintptr_t)PAGE_EXECUTE_READ,
        (uintptr_t)&old,
        0, 0, 0, 0, 0, 0);

    printf("[%c] NtProtectVirtualMemory: st=0x%08X  old_prot=0x%lX\n",
           st == 0 ? '+' : '!', (unsigned)st, old);

    /* Verify via VirtualQuery — does not go through ntdll hooks */
    MEMORY_BASIC_INFORMATION mbi = {0};
    VirtualQuery(base, &mbi, sizeof(mbi));
    printf("[*] VirtualQuery Protect = 0x%lX  (expected 0x%lX = PAGE_EXECUTE_READ)\n",
           mbi.Protect, (ULONG)PAGE_EXECUTE_READ);

    BOOL ok = (st == 0 && mbi.Protect == PAGE_EXECUTE_READ);
    printf("[%c] page is %s\n", ok ? '+' : '!',
           ok ? "PAGE_EXECUTE_READ — indirect syscalls working correctly"
              : "UNEXPECTED — check output above");

    /* NtFreeVirtualMemory */
    PVOID  fbase = base;
    SIZE_T fsz   = 0;
    sc_call(ssn_free,
        (uintptr_t)proc,
        (uintptr_t)&fbase,
        (uintptr_t)&fsz,
        (uintptr_t)MEM_RELEASE,
        0, 0, 0, 0, 0, 0, 0);

    return ok ? 0 : 1;
}
