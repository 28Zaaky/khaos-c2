// Minimal example DLL for reflective loading.
// Build this with reflect.c and export ReflectiveLoader.

#include <windows.h>

// TLS callback — called by ReflectiveLoader BEFORE DllMain.
// Writes %TEMP%\reflect_tls.txt to prove the callback ran.
static void NTAPI tls_callback(PVOID DllHandle, DWORD reason, PVOID reserved)
{
    (void)DllHandle;
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH)
        return;

    OutputDebugStringA("[reflect-dll] TLS callback DLL_PROCESS_ATTACH\n");

    char path[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("TEMP", path, MAX_PATH - 20);
    if (n && n < MAX_PATH - 20)
    {
        const char *suffix = "\\reflect_tls.txt";
        for (int i = 0; suffix[i]; i++)
            path[n++] = suffix[i];
        path[n] = '\0';
        HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE)
        {
            const char msg[] = "TLS callback fired before DllMain\r\n";
            DWORD w;
            WriteFile(hf, msg, sizeof(msg) - 1, &w, NULL);
            CloseHandle(hf);
        }
    }
}

static __thread volatile int _tls_anchor = 0;
__attribute__((section(".CRT$XLB"), used)) static PIMAGE_TLS_CALLBACK _tls_cb_entry = tls_callback;

__declspec(dllexport)
BOOL WINAPI
DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    (void)hInst;
    (void)reserved;

    // only perform actions on process attach
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hInst);

        OutputDebugStringA("[reflect-dll] DllMain DLL_PROCESS_ATTACH loaded reflectively\n");

        char path[MAX_PATH];
        DWORD n = GetEnvironmentVariableA("TEMP", path, MAX_PATH - 20);
        if (n && n < MAX_PATH - 20)
        {
            const char *suffix = "\\reflect_demo.txt";
            for (int i = 0; suffix[i]; i++)
                path[n++] = suffix[i];
            path[n] = '\0';

            HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hf != INVALID_HANDLE_VALUE)
            {
                const char msg[] = "Reflective DLL loaded via ReflectiveLoader()\r\n";
                DWORD written;
                WriteFile(hf, msg, sizeof(msg) - 1, &written, NULL);
                CloseHandle(hf);
            }
        }
    }
    return TRUE;
}
