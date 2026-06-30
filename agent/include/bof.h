#ifndef BOF_H
#define BOF_H

#include <stddef.h>

int cmd_bof(const char *coff_b64, const char *args_b64,
            char *output_buf, size_t output_sz);

#endif /* BOF_H */
