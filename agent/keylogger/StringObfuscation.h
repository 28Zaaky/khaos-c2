#ifndef STRING_OBFUSCATION_H
#define STRING_OBFUSCATION_H

#include <string>
#include <cstdint>

/* FNV-1a hash for compile-time key derivation */
constexpr uint32_t StringHash(const char* str, size_t len) {
    uint32_t hash = 0x811C9DC5;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint32_t>(str[i]);
        hash *= 0x01000193;
    }
    return hash;
}

constexpr uint32_t WStringHash(const wchar_t* str, size_t len) {
    uint32_t hash = 0x811C9DC5;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint32_t>(str[i]);
        hash *= 0x01000193;
    }
    return hash;
}

/* Keystream generator — Murmur3-inspired mixing, no lookup tables */
constexpr uint8_t ObfKeystream(uint32_t seed, size_t idx) {
    uint32_t h = seed ^ static_cast<uint32_t>(idx * 0x6B43A9B5UL);
    h ^= h >> 16;
    h *= 0x85EBCA6BUL;
    h ^= h >> 13;
    h *= 0xC2B2AE35UL;
    h ^= h >> 16;
    return static_cast<uint8_t>(h);
}

constexpr uint8_t ObfEncrypt(uint8_t p, uint8_t k) { return p ^ k; }
constexpr uint8_t ObfDecrypt(uint8_t e, uint8_t k) { return e ^ k; }

/* Compile-time encrypted narrow string */
template<size_t N>
class ObfuscatedString {
private:
    uint8_t  data_[N];
    uint32_t seed_;

public:
    constexpr ObfuscatedString(const char* str) : data_{}, seed_(StringHash(str, N-1)) {
        for (size_t i = 0; i < N-1; ++i)
            data_[i] = ObfEncrypt(static_cast<uint8_t>(str[i]), ObfKeystream(seed_, i));
        data_[N-1] = '\0';
    }

    std::string decrypt() const {
        std::string r;
        r.reserve(N-1);
        for (size_t i = 0; i < N-1; ++i)
            r += static_cast<char>(ObfDecrypt(data_[i], ObfKeystream(seed_, i)));
        return r;
    }

    const char* c_str() const {
        static thread_local char buf[256];
        size_t len = (N-1 < 255u) ? N-1 : 255u;
        for (size_t i = 0; i < len; ++i)
            buf[i] = static_cast<char>(ObfDecrypt(data_[i], ObfKeystream(seed_, i)));
        buf[len] = '\0';
        return buf;
    }
};

/* Compile-time encrypted wide string */
template<size_t N>
class ObfuscatedWString {
private:
    uint16_t data_[N];
    uint32_t seed_;

public:
    constexpr ObfuscatedWString(const wchar_t* str) : data_{}, seed_(WStringHash(str, N-1)) {
        for (size_t i = 0; i < N-1; ++i) {
            uint16_t c   = static_cast<uint16_t>(str[i]);
            uint8_t  ks1 = ObfKeystream(seed_, i*2);
            uint8_t  ks2 = ObfKeystream(seed_, i*2+1);
            uint8_t  lo  = ObfEncrypt(static_cast<uint8_t>(c & 0xFF),       ks1);
            uint8_t  hi  = ObfEncrypt(static_cast<uint8_t>((c >> 8) & 0xFF), ks2);
            data_[i] = static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
        }
        data_[N-1] = L'\0';
    }

    std::wstring decrypt() const {
        std::wstring r;
        r.reserve(N-1);
        for (size_t i = 0; i < N-1; ++i) {
            uint8_t ks1 = ObfKeystream(seed_, i*2);
            uint8_t ks2 = ObfKeystream(seed_, i*2+1);
            uint8_t lo  = ObfDecrypt(static_cast<uint8_t>(data_[i] & 0xFF),       ks1);
            uint8_t hi  = ObfDecrypt(static_cast<uint8_t>((data_[i] >> 8) & 0xFF), ks2);
            r += static_cast<wchar_t>(static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8));
        }
        return r;
    }

    const wchar_t* c_str() const {
        static thread_local wchar_t buf[256];
        size_t len = (N-1 < 255u) ? N-1 : 255u;
        for (size_t i = 0; i < len; ++i) {
            uint8_t ks1 = ObfKeystream(seed_, i*2);
            uint8_t ks2 = ObfKeystream(seed_, i*2+1);
            uint8_t lo  = ObfDecrypt(static_cast<uint8_t>(data_[i] & 0xFF),       ks1);
            uint8_t hi  = ObfDecrypt(static_cast<uint8_t>((data_[i] >> 8) & 0xFF), ks2);
            buf[i] = static_cast<wchar_t>(static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8));
        }
        buf[len] = L'\0';
        return buf;
    }
};

constexpr size_t StrLen(const char* str) {
    size_t n = 0; while (str[n]) ++n; return n + 1;
}
constexpr size_t WStrLen(const wchar_t* str) {
    size_t n = 0; while (str[n]) ++n; return n + 1;
}

#define OBFUSCATE(str)   (ObfuscatedString<StrLen(str)>(str).c_str())
#define OBFUSCATE_W(str) (ObfuscatedWString<WStrLen(str)>(str).c_str())

#endif /* STRING_OBFUSCATION_H */
