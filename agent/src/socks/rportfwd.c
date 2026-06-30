#include "socks.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RPORTFWD_BUF 65536
#define RPORTFWD_MAX 16

typedef struct
{
    unsigned short lport;
    char rhost[256];
    unsigned short rport;
    SOCKET lsock;
    HANDLE thread;
    volatile LONG running;
} fwd_entry_t;

static fwd_entry_t g_fwds[RPORTFWD_MAX];
static CRITICAL_SECTION g_lock;
static LONG g_init = 0;

static void _init(void)
{
    if (InterlockedCompareExchange(&g_init, 1, 0) == 0)
    {
        InitializeCriticalSection(&g_lock);
        for (int i = 0; i < RPORTFWD_MAX; i++)
        {
            memset(&g_fwds[i], 0, sizeof(g_fwds[i]));
            g_fwds[i].lsock = INVALID_SOCKET;
        }
    }
}

/* per-connection relay context */
typedef struct
{
    SOCKET client;
    char rhost[256];
    unsigned short rport;
} relay_arg_t;

static DWORD WINAPI _relay_thread(LPVOID arg)
{
    relay_arg_t *ra = (relay_arg_t *)arg;
    SOCKET cli = ra->client;

    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", ra->rport);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    SOCKET rem = INVALID_SOCKET;
    if (getaddrinfo(ra->rhost, portstr, &hints, &res) == 0 && res)
    {
        rem = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (rem != INVALID_SOCKET)
        {
            if (connect(rem, res->ai_addr, (int)res->ai_addrlen) != 0)
            {
                closesocket(rem);
                rem = INVALID_SOCKET;
            }
        }
        freeaddrinfo(res);
    }

    if (rem == INVALID_SOCKET)
    {
        closesocket(cli);
        free(ra);
        return 0;
    }

    char *buf = (char *)malloc(RPORTFWD_BUF);
    if (buf)
    {
        for (;;)
        {
            fd_set rd;
            FD_ZERO(&rd);
            FD_SET(cli, &rd);
            FD_SET(rem, &rd);
            SOCKET mx = (cli > rem ? cli : rem) + 1;
            struct timeval tv = {30, 0};
            if (select((int)mx, &rd, NULL, NULL, &tv) <= 0)
                break;
            if (FD_ISSET(cli, &rd))
            {
                int n = recv(cli, buf, RPORTFWD_BUF, 0);
                if (n <= 0 || send(rem, buf, n, 0) <= 0)
                    break;
            }
            if (FD_ISSET(rem, &rd))
            {
                int n = recv(rem, buf, RPORTFWD_BUF, 0);
                if (n <= 0 || send(cli, buf, n, 0) <= 0)
                    break;
            }
        }
        free(buf);
    }

    closesocket(rem);
    closesocket(cli);
    free(ra);
    return 0;
}

static DWORD WINAPI _listener_thread(LPVOID arg)
{
    fwd_entry_t *e = (fwd_entry_t *)arg;

    while (e->running && e->lsock != INVALID_SOCKET)
    {
        struct sockaddr_in peer;
        int plen = sizeof(peer);
        SOCKET cli = accept(e->lsock, (struct sockaddr *)&peer, &plen);
        if (cli == INVALID_SOCKET)
            break;

        relay_arg_t *ra = (relay_arg_t *)malloc(sizeof(relay_arg_t));
        if (!ra)
        {
            closesocket(cli);
            continue;
        }
        ra->client = cli;
        strncpy(ra->rhost, e->rhost, 255);
        ra->rhost[255] = '\0';
        ra->rport = e->rport;

        HANDLE ht = CreateThread(NULL, 0, _relay_thread, ra, 0, NULL);
        if (!ht)
        {
            closesocket(cli);
            free(ra);
            continue;
        }
        CloseHandle(ht);
    }

    InterlockedExchange(&e->running, 0);
    return 0;
}

/* public API */

int rportfwd_start(unsigned short lport, const char *rhost, unsigned short rport,
                   char *out, size_t outsz)
{
    _init();

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    EnterCriticalSection(&g_lock);

    for (int i = 0; i < RPORTFWD_MAX; i++)
    {
        if (g_fwds[i].running && g_fwds[i].lport == lport)
        {
            LeaveCriticalSection(&g_lock);
            snprintf(out, outsz, "[rportfwd] port %u already active\n", lport);
            return -1;
        }
    }

    int slot = -1;
    for (int i = 0; i < RPORTFWD_MAX; i++)
    {
        if (!g_fwds[i].running)
        {
            slot = i;
            break;
        }
    }
    if (slot < 0)
    {
        LeaveCriticalSection(&g_lock);
        snprintf(out, outsz, "[rportfwd] max %d forwards reached\n", RPORTFWD_MAX);
        return -1;
    }

    fwd_entry_t *e = &g_fwds[slot];
    e->lport = lport;
    strncpy(e->rhost, rhost, 255);
    e->rhost[255] = '\0';
    e->rport = rport;

    e->lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (e->lsock == INVALID_SOCKET)
    {
        LeaveCriticalSection(&g_lock);
        snprintf(out, outsz, "[rportfwd] socket() failed: %d\n", WSAGetLastError());
        return -1;
    }

    int opt = 1;
    setsockopt(e->lsock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(lport);

    if (bind(e->lsock, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(e->lsock, SOMAXCONN) != 0)
    {
        closesocket(e->lsock);
        e->lsock = INVALID_SOCKET;
        LeaveCriticalSection(&g_lock);
        snprintf(out, outsz, "[rportfwd] bind/listen %u failed: %d\n",
                 lport, WSAGetLastError());
        return -1;
    }

    InterlockedExchange(&e->running, 1);
    e->thread = CreateThread(NULL, 0, _listener_thread, e, 0, NULL);
    if (!e->thread)
    {
        closesocket(e->lsock);
        e->lsock = INVALID_SOCKET;
        InterlockedExchange(&e->running, 0);
        LeaveCriticalSection(&g_lock);
        snprintf(out, outsz, "[rportfwd] CreateThread failed\n");
        return -1;
    }

    LeaveCriticalSection(&g_lock);
    snprintf(out, outsz, "[rportfwd] 0.0.0.0:%u → %s:%u\n", lport, rhost, rport);
    return 0;
}

int rportfwd_stop(unsigned short lport, char *out, size_t outsz)
{
    _init();
    EnterCriticalSection(&g_lock);

    for (int i = 0; i < RPORTFWD_MAX; i++)
    {
        fwd_entry_t *e = &g_fwds[i];
        if (e->running && e->lport == lport)
        {
            InterlockedExchange(&e->running, 0);
            if (e->lsock != INVALID_SOCKET)
            {
                closesocket(e->lsock);
                e->lsock = INVALID_SOCKET;
            }
            if (e->thread)
            {
                WaitForSingleObject(e->thread, 2000);
                CloseHandle(e->thread);
                e->thread = NULL;
            }
            LeaveCriticalSection(&g_lock);
            snprintf(out, outsz, "[rportfwd] stopped port %u\n", lport);
            return 0;
        }
    }

    LeaveCriticalSection(&g_lock);
    snprintf(out, outsz, "[rportfwd] port %u not found\n", lport);
    return -1;
}

int rportfwd_list(char *out, size_t outsz)
{
    _init();
    EnterCriticalSection(&g_lock);

    size_t pos = 0;
    int found = 0;
    for (int i = 0; i < RPORTFWD_MAX; i++)
    {
        fwd_entry_t *e = &g_fwds[i];
        if (!e->running)
            continue;
        int n = snprintf(out + pos, outsz - pos,
                         "[rportfwd] 0.0.0.0:%u → %s:%u\n",
                         e->lport, e->rhost, e->rport);
        if (n > 0)
            pos += (size_t)n;
        found++;
    }
    if (!found)
        snprintf(out, outsz, "[rportfwd] no active forwards\n");

    LeaveCriticalSection(&g_lock);
    return 0;
}
