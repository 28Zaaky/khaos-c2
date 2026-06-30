#include "ntdll_unhook.h"
#include <windows.h>
#include <stdio.h>

/*
 * Demo: read the first 6 bytes of NtOpenProcess before and after unhooking.
 *
 * A hooked stub looks like:
 *   E9 xx xx xx xx xx    JMP <EDR trampoline>
 *
 * A clean stub looks like:
 *   4C 8B D1             mov r10, rcx
 *   B8 xx 00 00 00       mov eax, <SSN>
 *   0F 05                syscall
 *   C3                   ret
 */
static void print_bytes(const char *label, const BYTE *p, int n)
{
    printf("[%s] ", label);
    for (int i = 0; i < n; i++) printf("%02X ", p[i]);
    printf("\n");
}

int main(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    BYTE *fn = (BYTE *)(void *)GetProcAddress(ntdll, "NtOpenProcess");

    printf("[*] NtOpenProcess bytes before unhook:\n");
    print_bytes("before", fn, 8);

    int rc = ntdll_unhook();
    printf("[*] ntdll_unhook() = %d (%s)\n", rc, rc == 0 ? "OK" : "FAIL");

    printf("[*] NtOpenProcess bytes after unhook:\n");
    print_bytes("after ", fn, 8);

    /* Expected clean pattern: 4C 8B D1 B8 <SSN_LO> <SSN_HI> 00 00 */
    int clean = (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8);
    printf("[%s] stub is %s\n", clean ? "+" : "!", clean ? "clean" : "still hooked or unknown");

    /* ETW-TI patch — only present on specific Windows builds (PPL/ETW-TI enabled) */
    int n = ntdll_patch_etw_ti();
    if (n > 0)
        printf("[+] ntdll_patch_etw_ti() patched %d/3 functions\n", n);
    else
        printf("[*] ntdll_patch_etw_ti(): EtwTi* exports not present on this build (normal on consumer SKUs)\n");

    return clean ? 0 : 1;
}
