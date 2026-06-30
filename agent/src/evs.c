#include "evs_strings.h"
#include <stddef.h>

/* Single XOR-decode function. noinline = one code pattern in .text, not 100+ loops. */
__attribute__((noinline))
void _evs_dec(char *out, const unsigned char *enc, size_t n)
{
    unsigned char k = EVS_KEY;
    for (size_t i = 0; i < n; i++)
        out[i] = (char)(enc[i] ^ k);
    out[n] = '\0';
}
