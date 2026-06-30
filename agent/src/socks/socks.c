#include "socks.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define SOCKS_BUF  65536
#define SOCKS_AUTH_NONE  0x00
#define SOCKS_CMD_CONNECT 0x01
#define SOCKS_ATYP_IPV4   0x01
#define SOCKS_ATYP_FQDN   0x03
#define SOCKS_ATYP_IPV6   0x04

static SOCKET  g_listen  = INVALID_SOCKET;
static HANDLE  g_thread  = NULL;
static volatile LONG g_running = 0;

/* per-client relay context */
typedef struct { SOCKET client; SOCKET remote; } relay_t;

static int _recv_all(SOCKET s, char *buf, int n)
{
    int got = 0;
    while (got < n) {
        int r = recv(s, buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return got;
}

static void _relay(SOCKET c, SOCKET r)
{
    char *buf = (char *)malloc(SOCKS_BUF);
    if (!buf) return;

    while (1) {
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(c, &rd);
        FD_SET(r, &rd);
        SOCKET maxfd = (c > r ? c : r) + 1;

        struct timeval tv = {30, 0};
        int rc = select((int)maxfd, &rd, NULL, NULL, &tv);
        if (rc <= 0) break;

        if (FD_ISSET(c, &rd)) {
            int n = recv(c, buf, SOCKS_BUF, 0);
            if (n <= 0) break;
            if (send(r, buf, n, 0) <= 0) break;
        }
        if (FD_ISSET(r, &rd)) {
            int n = recv(r, buf, SOCKS_BUF, 0);
            if (n <= 0) break;
            if (send(c, buf, n, 0) <= 0) break;
        }
    }
    free(buf);
}

/* client handler thread */
static DWORD WINAPI _client_thread(LPVOID arg)
{
    relay_t *ctx = (relay_t *)arg;
    SOCKET  cli  = ctx->client;
    free(ctx);

    char buf[512];

    /* step 1: version + method negotiation */
    if (_recv_all(cli, buf, 2) < 0) goto done;
    if ((unsigned char)buf[0] != 5) goto done;       /* not SOCKS5 */

    int nmeth = (unsigned char)buf[1];
    if (nmeth < 1 || nmeth > 255) goto done;
    if (_recv_all(cli, buf, nmeth) < 0) goto done;

    /* Respond: SOCKS5, no-auth */
    char reply2[2] = {5, SOCKS_AUTH_NONE};
    send(cli, reply2, 2, 0);

    /* step 2: parse SOCKS5 request */
    if (_recv_all(cli, buf, 4) < 0) goto done;
    /* buf[0]=5, buf[1]=cmd, buf[2]=0, buf[3]=atyp */
    if ((unsigned char)buf[0] != 5) goto done;
    if ((unsigned char)buf[1] != SOCKS_CMD_CONNECT) {
        /* Command not supported */
        char err[10] = {5,7,0,1, 0,0,0,0, 0,0};
        send(cli, err, sizeof(err), 0);
        goto done;
    }

    char host[256] = {0};
    unsigned short port = 0;
    unsigned char atyp = (unsigned char)buf[3];

    if (atyp == SOCKS_ATYP_IPV4) {
        unsigned char ipb[4];
        if (_recv_all(cli, (char *)ipb, 4) < 0) goto done;
        if (_recv_all(cli, (char *)&port, 2) < 0) goto done;
        port = ntohs(port);
        snprintf(host, sizeof(host), "%u.%u.%u.%u",
                 ipb[0], ipb[1], ipb[2], ipb[3]);

    } else if (atyp == SOCKS_ATYP_FQDN) {
        unsigned char len;
        if (_recv_all(cli, (char *)&len, 1) < 0) goto done;
        if (_recv_all(cli, host, len) < 0) goto done;
        host[len] = '\0';
        if (_recv_all(cli, (char *)&port, 2) < 0) goto done;
        port = ntohs(port);

    } else {
        /* IPv6 not supported — send error */
        char err[10] = {5,8,0,1, 0,0,0,0, 0,0};
        send(cli, err, sizeof(err), 0);
        goto done;
    }

    /* step 3: connect to target host */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
        char err[10] = {5,4,0,1, 0,0,0,0, 0,0};
        send(cli, err, sizeof(err), 0);
        goto done;
    }

    SOCKET rem = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (rem == INVALID_SOCKET) {
        freeaddrinfo(res);
        char err[10] = {5,1,0,1, 0,0,0,0, 0,0};
        send(cli, err, sizeof(err), 0);
        goto done;
    }

    if (connect(rem, res->ai_addr, (int)res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        closesocket(rem);
        char err[10] = {5,5,0,1, 0,0,0,0, 0,0};
        send(cli, err, sizeof(err), 0);
        goto done;
    }
    freeaddrinfo(res);

    /* Success reply: 5 0 0 1 0.0.0.0:0 */
    char ok[10] = {5,0,0,1, 0,0,0,0, 0,0};
    send(cli, ok, sizeof(ok), 0);

    /* step 4: relay traffic */
    _relay(cli, rem);
    closesocket(rem);

done:
    closesocket(cli);
    return 0;
}

/* listener thread */
static DWORD WINAPI _listen_thread(LPVOID arg)
{
    (void)arg;
    while (g_running && g_listen != INVALID_SOCKET) {
        struct sockaddr_in peer;
        int plen = sizeof(peer);
        SOCKET cli = accept(g_listen, (struct sockaddr *)&peer, &plen);
        if (cli == INVALID_SOCKET) break;

        relay_t *ctx = (relay_t *)malloc(sizeof(relay_t));
        if (!ctx) { closesocket(cli); continue; }
        ctx->client = cli;
        ctx->remote = INVALID_SOCKET;

        HANDLE ht = CreateThread(NULL, 0, _client_thread, ctx, 0, NULL);
        if (!ht) { closesocket(cli); free(ctx); continue; }
        CloseHandle(ht);
    }
    InterlockedExchange(&g_running, 0);
    return 0;
}

/* public API */

int socks_start(unsigned short port, char *out, size_t outsz)
{
    if (InterlockedCompareExchange(&g_running, 1, 0) != 0) {
        snprintf(out, outsz, "[socks] already running\n");
        return -1;
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listen == INVALID_SOCKET) {
        InterlockedExchange(&g_running, 0);
        snprintf(out, outsz, "[socks] socket() failed: %d\n", WSAGetLastError());
        return -1;
    }

    int opt = 1;
    setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port        = htons(port);

    if (bind(g_listen, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        closesocket(g_listen); g_listen = INVALID_SOCKET;
        InterlockedExchange(&g_running, 0);
        snprintf(out, outsz, "[socks] bind %u failed: %d\n", port, WSAGetLastError());
        return -1;
    }

    if (listen(g_listen, SOMAXCONN) != 0) {
        closesocket(g_listen); g_listen = INVALID_SOCKET;
        InterlockedExchange(&g_running, 0);
        snprintf(out, outsz, "[socks] listen failed: %d\n", WSAGetLastError());
        return -1;
    }

    g_thread = CreateThread(NULL, 0, _listen_thread, NULL, 0, NULL);
    if (!g_thread) {
        closesocket(g_listen); g_listen = INVALID_SOCKET;
        InterlockedExchange(&g_running, 0);
        snprintf(out, outsz, "[socks] thread failed\n");
        return -1;
    }

    snprintf(out, outsz, "[socks] listener up on 0.0.0.0:%u\n", port);
    return 0;
}

int socks_stop(char *out, size_t outsz)
{
    if (!g_running) {
        snprintf(out, outsz, "[socks] not running\n");
        return -1;
    }
    InterlockedExchange(&g_running, 0);
    if (g_listen != INVALID_SOCKET) {
        closesocket(g_listen);
        g_listen = INVALID_SOCKET;
    }
    if (g_thread) {
        WaitForSingleObject(g_thread, 3000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
    snprintf(out, outsz, "[socks] stopped\n");
    return 0;
}

int socks_running(void) { return (int)g_running; }
