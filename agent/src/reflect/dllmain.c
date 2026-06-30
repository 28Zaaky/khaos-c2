#ifdef _REFLECTIVE_DLL
#include <windows.h>

void agent_main(void);

static DWORD WINAPI _agent_thread(LPVOID param)
{
    (void)param;
    agent_main();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD dwReason, LPVOID lpReserved)
{
    (void)lpReserved;
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstDLL);
        CreateThread(NULL, 0, _agent_thread, NULL, 0, NULL);
    }
    return TRUE;
}
#endif /* _REFLECTIVE_DLL */
