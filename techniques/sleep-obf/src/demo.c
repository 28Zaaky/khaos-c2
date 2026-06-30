#include "sleep_obf.h"
#include <windows.h>
#include <stdio.h>

int main(void)
{
    printf("[*] starting — sleeping 5 seconds with .text obfuscation\n");
    fflush(stdout);

    sleep_obf(5000);

    printf("[+] woke up — .text restored, execution resumed\n");
    fflush(stdout);

    /* loop to show repeated sleeps work */
    for (int i = 0; i < 3; i++) {
        printf("[*] loop %d — sleeping 2 seconds\n", i + 1);
        fflush(stdout);
        sleep_obf(2000);
        printf("[+] loop %d — resumed\n", i + 1);
        fflush(stdout);
    }

    printf("[+] done\n");
    return 0;
}
