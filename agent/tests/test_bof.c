// standalone harness: loads a COFF .o, b64-encodes it, runs cmd_bof()
// build: gcc -O0 -Iinclude tests/test_bof.c bof.o -o test_bof.exe -lkernel32 -ladvapi32
// run:   test_bof.exe tests/bof_hello.o
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include "bof.h"
#include "adv_lazy.h"

// stub for _bp_is_admin shim in bof.o
const adv_api_t *adv_get(void)
{
    static adv_api_t a;
    static int init = 0;
    if (!init) {
        HMODULE adv = LoadLibraryA("advapi32.dll");
        if (adv) {
            a.OpenProcessToken      = (void *)GetProcAddress(adv, "OpenProcessToken");
            a.AdjustTokenPrivileges = (void *)GetProcAddress(adv, "AdjustTokenPrivileges");
            a.DuplicateTokenEx      = (void *)GetProcAddress(adv, "DuplicateTokenEx");
            a.ImpersonateLoggedOnUser = (void *)GetProcAddress(adv, "ImpersonateLoggedOnUser");
            a.LogonUserA            = (void *)GetProcAddress(adv, "LogonUserA");
            a.LookupPrivilegeNameA  = (void *)GetProcAddress(adv, "LookupPrivilegeNameA");
            a.LookupPrivilegeValueA = (void *)GetProcAddress(adv, "LookupPrivilegeValueA");
            a.OpenThreadToken       = (void *)GetProcAddress(adv, "OpenThreadToken");
            a.RevertToSelf          = (void *)GetProcAddress(adv, "RevertToSelf");
            a.CloseServiceHandle    = (void *)GetProcAddress(adv, "CloseServiceHandle");
            a.EnumServicesStatusExA = (void *)GetProcAddress(adv, "EnumServicesStatusExA");
            a.OpenSCManagerA        = (void *)GetProcAddress(adv, "OpenSCManagerA");
            a.OpenServiceA          = (void *)GetProcAddress(adv, "OpenServiceA");
            a.QueryServiceConfigA   = (void *)GetProcAddress(adv, "QueryServiceConfigA");
        }
        init = 1;
    }
    return &a;
}

// required by bof.o — must match signature in crypto.h
static const int DEC[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

uint8_t *base64_decode(const char *str, size_t *out_len)
{
    if (!str) { if (out_len) *out_len = 0; return NULL; }
    size_t slen = strlen(str);
    if (slen == 0) { if (out_len) *out_len = 0; return (uint8_t *)calloc(1, 1); }

    size_t pad = 0;
    if (slen >= 1 && str[slen-1] == '=') { pad++; slen--; }
    if (slen >= 1 && str[slen-1] == '=') { pad++; slen--; }

    size_t dlen = (slen * 3) / 4;
    uint8_t *out = (uint8_t *)malloc(dlen + 1);
    if (!out) { if (out_len) *out_len = 0; return NULL; }

    size_t i = 0, o = 0;
    while (i + 3 < slen + pad) {
        unsigned char c0 = (i   < slen) ? (unsigned char)str[i]   : 0;
        unsigned char c1 = (i+1 < slen) ? (unsigned char)str[i+1] : 0;
        unsigned char c2 = (i+2 < slen) ? (unsigned char)str[i+2] : 0;
        unsigned char c3 = (i+3 < slen) ? (unsigned char)str[i+3] : 0;

        int v0 = DEC[c0], v1 = DEC[c1], v2 = DEC[c2], v3 = DEC[c3];
        if (v0 < 0 || v1 < 0) break;

        uint32_t triple = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12)
                        | ((uint32_t)(v2 >= 0 ? v2 : 0) << 6)
                        |  (uint32_t)(v3 >= 0 ? v3 : 0);

        if (o < dlen) out[o++] = (uint8_t)((triple >> 16) & 0xff);
        if (o < dlen && (i+2 < slen)) out[o++] = (uint8_t)((triple >> 8) & 0xff);
        if (o < dlen && (i+3 < slen)) out[o++] = (uint8_t)(triple & 0xff);
        i += 4;
    }
    out[o] = '\0';
    if (out_len) *out_len = o;
    return out;
}

static const char ENC[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const uint8_t *data, size_t len)
{
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char *out = (char *)malloc(out_len);
    if (!out) return NULL;

    size_t i, o = 0;
    for (i = 0; i + 2 < len; i += 3) {
        out[o++] = ENC[(data[i]   >> 2) & 0x3f];
        out[o++] = ENC[((data[i]   & 3)  << 4) | (data[i+1] >> 4)];
        out[o++] = ENC[((data[i+1] & 0xf)<< 2) | (data[i+2] >> 6)];
        out[o++] = ENC[ data[i+2] & 0x3f];
    }
    if (i < len) {
        out[o++] = ENC[(data[i] >> 2) & 0x3f];
        if (i + 1 < len) {
            out[o++] = ENC[((data[i] & 3) << 4) | (data[i+1] >> 4)];
            out[o++] = ENC[(data[i+1] & 0xf) << 2];
        } else {
            out[o++] = ENC[(data[i] & 3) << 4];
            out[o++] = '=';
        }
        out[o++] = '=';
    }
    out[o] = '\0';
    return out;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: test_bof.exe <coff.o> [args_b64]\n");
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "[-] cannot open: %s\n", argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    rewind(f);

    uint8_t *coff_raw = (uint8_t *)malloc((size_t)fsz);
    if (!coff_raw) { fclose(f); return 1; }
    fread(coff_raw, 1, (size_t)fsz, f);
    fclose(f);

    char *coff_b64 = b64_encode(coff_raw, (size_t)fsz);
    free(coff_raw);
    if (!coff_b64) { fprintf(stderr, "[-] b64_encode failed\n"); return 1; }

    const char *args_b64 = (argc >= 3) ? argv[2] : NULL;

    printf("[*] COFF: %s (%ld bytes, b64=%zu chars)\n", argv[1], fsz, strlen(coff_b64));
    printf("[*] Calling cmd_bof()...\n");
    fflush(stdout);

    char output[65536] = {0};
    int ret = cmd_bof(coff_b64, args_b64, output, sizeof(output));
    free(coff_b64);

    printf("[*] cmd_bof() = %d\n", ret);
    if (output[0])
        printf("[*] BOF output:\n%s", output);
    else
        printf("[*] BOF output: (empty)\n");

    return (ret == 0) ? 0 : 1;
}
