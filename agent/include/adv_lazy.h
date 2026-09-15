#ifndef ADV_LAZY_H
#define ADV_LAZY_H

#include <windows.h>
#include <winsvc.h>

typedef struct {
    /* token manipulation */
    BOOL  (WINAPI *AdjustTokenPrivileges)(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
    BOOL  (WINAPI *DuplicateTokenEx)(HANDLE,DWORD,LPSECURITY_ATTRIBUTES,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE);
    BOOL  (WINAPI *GetTokenInformation)(HANDLE,TOKEN_INFORMATION_CLASS,LPVOID,DWORD,PDWORD);
    BOOL  (WINAPI *ImpersonateLoggedOnUser)(HANDLE);
    BOOL  (WINAPI *LogonUserA)(LPCSTR,LPCSTR,LPCSTR,DWORD,DWORD,PHANDLE);
    BOOL  (WINAPI *LookupPrivilegeNameA)(LPCSTR,PLUID,LPSTR,LPDWORD);
    BOOL  (WINAPI *LookupPrivilegeValueA)(LPCSTR,LPCSTR,PLUID);
    BOOL  (WINAPI *OpenProcessToken)(HANDLE,DWORD,PHANDLE);
    BOOL  (WINAPI *OpenThreadToken)(HANDLE,DWORD,BOOL,PHANDLE);
    BOOL  (WINAPI *RevertToSelf)(void);
    /* registry */
    LONG  (WINAPI *RegCreateKeyExA)(HKEY,LPCSTR,DWORD,LPSTR,DWORD,REGSAM,LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
    LONG  (WINAPI *RegSetValueExA)(HKEY,LPCSTR,DWORD,DWORD,const BYTE *,DWORD);
    /* service management */
    BOOL  (WINAPI *CloseServiceHandle)(SC_HANDLE);
    BOOL  (WINAPI *EnumServicesStatusExA)(SC_HANDLE,SC_ENUM_TYPE,DWORD,DWORD,LPBYTE,DWORD,LPDWORD,LPDWORD,LPDWORD,LPCSTR);
    SC_HANDLE (WINAPI *OpenSCManagerA)(LPCSTR,LPCSTR,DWORD);
    SC_HANDLE (WINAPI *OpenServiceA)(SC_HANDLE,LPCSTR,DWORD);
    BOOL  (WINAPI *QueryServiceConfigA)(SC_HANDLE,LPQUERY_SERVICE_CONFIGA,DWORD,LPDWORD);
    SERVICE_STATUS_HANDLE (WINAPI *RegisterServiceCtrlHandlerA)(LPCSTR,LPHANDLER_FUNCTION);
    BOOL  (WINAPI *SetServiceStatus)(SERVICE_STATUS_HANDLE,LPSERVICE_STATUS);
    BOOL  (WINAPI *StartServiceCtrlDispatcherA)(LPSERVICE_TABLE_ENTRYA);
} adv_api_t;

const adv_api_t *adv_get(void);

/* Shadow these APIs through lazy loader — removes IAT entries */
#undef  GetTokenInformation
#define GetTokenInformation(h,tc,p,s,r)            (adv_get()->GetTokenInformation(h,tc,p,s,r))
#undef  RegCreateKeyExA
#define RegCreateKeyExA(h,s,r,c,o,sam,sa,rk,d)    (adv_get()->RegCreateKeyExA(h,s,r,c,o,sam,sa,rk,d))
#undef  RegSetValueExA
#define RegSetValueExA(h,n,r,t,d,s)               (adv_get()->RegSetValueExA(h,n,r,t,d,s))

#endif /* ADV_LAZY_H */
