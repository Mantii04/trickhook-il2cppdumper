#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <functional>
#include <memory>

using LogFn = std::function<void(const std::string&)>;

struct Reader {
    const uint8_t* data = nullptr;
    size_t size = 0;
    size_t pos = 0;
    bool ok = true;

    uint8_t  u8()  { return rd<uint8_t>(); }
    uint16_t u16() { return rd<uint16_t>(); }
    uint32_t u32() { return rd<uint32_t>(); }
    int32_t  i32() { return rd<int32_t>(); }
    uint64_t u64() { return rd<uint64_t>(); }
    int64_t  i64() { return rd<int64_t>(); }

    template<class T> T rd() {
        if (pos + sizeof(T) > size) { ok = false; return 0; }
        T v; std::memcpy(&v, data + pos, sizeof(T)); pos += sizeof(T); return v;
    }
    void skip(size_t n) { pos += n; }
    void seek(size_t p) { pos = p; }
};

static inline uint32_t crc32_calc(const uint8_t* p, size_t n) {
    static uint32_t tab[256]; static bool init = false;
    if (!init) { for (uint32_t i=0;i<256;i++){uint32_t c=i;for(int k=0;k<8;k++)c=c&1?0xEDB88320u^(c>>1):c>>1;tab[i]=c;} init=true; }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i=0;i<n;i++) c = tab[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}
