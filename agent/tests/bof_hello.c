// test BOF: DLL$Function convention + BeaconPrintf
// compile: gcc -c bof_hello.c -o bof_hello.o
#include <windows.h>

void BeaconPrintf(int type, const char *fmt, ...);

// DLL$Function — loader strips prefix and resolves from named dll
BOOL  ADVAPI32$GetUserNameA(LPSTR buf, LPDWORD sz);
DWORD KERNEL32$GetCurrentProcessId(void);

void go(char *args, int len)
{
    (void)args; (void)len;

    char user[256] = {0};
    DWORD usersz = (DWORD)sizeof(user);
    ADVAPI32$GetUserNameA(user, &usersz);

    DWORD pid = KERNEL32$GetCurrentProcessId();

    BeaconPrintf(0, "[BOF] Hello from KHAOS BOF loader!\n");
    BeaconPrintf(0, "[BOF] User: %s | PID: %lu\n", user, (unsigned long)pid);
}
