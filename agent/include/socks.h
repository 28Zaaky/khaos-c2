#ifndef SOCKS_H
#define SOCKS_H

#include <stddef.h>

int  socks_start(unsigned short port, char *output_buf, size_t output_sz);
int  socks_stop(char *output_buf, size_t output_sz);
int  socks_running(void);

int  rportfwd_start(unsigned short lport, const char *rhost, unsigned short rport,
                    char *out, size_t outsz);
int  rportfwd_stop(unsigned short lport, char *out, size_t outsz);
int  rportfwd_list(char *out, size_t outsz);

#endif /* SOCKS_H */
