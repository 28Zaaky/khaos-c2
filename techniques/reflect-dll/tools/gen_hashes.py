def rl_hash(s):
    h = 0
    for c in s.upper():
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

apis = [
    'kernel32.dll',
    'LoadLibraryA',
    'GetProcAddress',
    'VirtualAlloc',
    'VirtualProtect',
    'FlushInstructionCache',
    'GetCurrentProcess',
]

for a in apis:
    key = a.replace('.', '_')
    print('#define HASH_%-30s 0x%08XULL  // %s' % (key, rl_hash(a), a))
