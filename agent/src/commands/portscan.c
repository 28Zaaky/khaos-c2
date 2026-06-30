#ifndef FD_SETSIZE
#define FD_SETSIZE 512
#endif
#include "commands.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SCAN_BATCH 256

static int _scan_batch(const char *host,
                       unsigned short *ports, int nports,
                       int timeout_ms,
                       char *out, size_t outsz, size_t *pos)
{
    SOCKET socks[SCAN_BATCH];
    int    valid[SCAN_BATCH];
    struct addrinfo *res[SCAN_BATCH];

    for (int i = 0; i < nports; i++) {
        socks[i] = INVALID_SOCKET;
        valid[i] = 0;
        res[i]   = NULL;
    }

    /* start non-blocking connects */
    for (int i = 0; i < nports; i++) {
        char portstr[8];
        snprintf(portstr, sizeof(portstr), "%u", ports[i]);

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(host, portstr, &hints, &res[i]) != 0 || !res[i])
            continue;

        socks[i] = socket(res[i]->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (socks[i] == INVALID_SOCKET) {
            freeaddrinfo(res[i]); res[i] = NULL;
            continue;
        }

        /* Non-blocking */
        u_long nb = 1;
        ioctlsocket(socks[i], FIONBIO, &nb);

        connect(socks[i], res[i]->ai_addr, (int)res[i]->ai_addrlen);
        /* WSAEWOULDBLOCK expected */
        valid[i] = 1;
    }

    /* wait for results */
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    fd_set wset, eset;
    FD_ZERO(&wset);
    FD_ZERO(&eset);

    for (int i = 0; i < nports; i++) {
        if (valid[i] && socks[i] != INVALID_SOCKET) {
            FD_SET(socks[i], &wset);
            FD_SET(socks[i], &eset);
        }
    }

    select(0, NULL, &wset, &eset, &tv);

    int found = 0;
    for (int i = 0; i < nports; i++) {
        if (!valid[i] || socks[i] == INVALID_SOCKET) goto cleanup;

        if (FD_ISSET(socks[i], &wset)) {
            /* Check SO_ERROR — 0 means connected */
            int   err  = 0;
            int   elen = sizeof(err);
            getsockopt(socks[i], SOL_SOCKET, SO_ERROR,
                       (char *)&err, &elen);
            if (err == 0) {
                int n = snprintf(out + *pos, outsz - *pos,
                                 "  open  %s:%u\n", host, ports[i]);
                if (n > 0 && (size_t)n < outsz - *pos) *pos += (size_t)n;
                found++;
            }
        }

    cleanup:
        if (socks[i] != INVALID_SOCKET) {
            closesocket(socks[i]);
            socks[i] = INVALID_SOCKET;
        }
        if (res[i]) { freeaddrinfo(res[i]); res[i] = NULL; }
    }
    return found;
}

int cmd_portscan(const char *host, unsigned short start, unsigned short end,
                 int timeout_ms, char *output_buf, size_t output_size)
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    if (!host || !host[0] || start > end) {
        snprintf(output_buf, output_size,
                 "[portscan] usage: portscan <host> <start>-<end> [timeout_ms]\n");
        return -1;
    }

    if (timeout_ms <= 0) timeout_ms = 500;

    size_t pos = 0;
    int n = snprintf(output_buf + pos, output_size - pos,
                     "[portscan] %s  %u-%u  timeout=%dms\n",
                     host, start, end, timeout_ms);
    if (n > 0) pos += (size_t)n;

    unsigned short batch[SCAN_BATCH];
    int            bsz   = 0;
    int            total = 0;

    for (unsigned int p = start; p <= (unsigned int)end; p++) {
        batch[bsz++] = (unsigned short)p;
        if (bsz == SCAN_BATCH || p == (unsigned int)end) {
            total += _scan_batch(host, batch, bsz, timeout_ms,
                                 output_buf, output_size, &pos);
            bsz = 0;
            /* Bail if output nearly full */
            if (pos + 256 >= output_size) break;
        }
    }

    n = snprintf(output_buf + pos, output_size - pos,
                 "[portscan] done  %d open\n", total);
    if (n > 0 && (size_t)n < output_size - pos) pos += (size_t)n;

    return 0;
}
