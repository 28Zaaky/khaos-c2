#include "evs_strings.h"
#include <stddef.h>

/* Rotating-key decode — no constant XOR immediate in inner loop.
 * Key rotates left 3 bits each byte: inner loop is register-register XOR only.
 * Both k and r stay in registers; no xor reg, imm32 pattern. */
__attribute__((noinline))
void _evs_dec(char *out, const unsigned char *enc, size_t n)
{
    volatile unsigned char _k = EVS_KEY;
    unsigned char k = _k;
    unsigned char r = k ^ 0x5C;
    for (size_t i = 0; i < n; i++) {
        r = (unsigned char)((r << 3) | (r >> 5));
        out[i] = (char)(enc[i] ^ k ^ r);
    }
    out[n] = '\0';
}
