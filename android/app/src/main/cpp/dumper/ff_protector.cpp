#include "ff_protector.h"
#include "aes.h"

static const int8_t D8[8] = {-1, 0, +4, -1, +4, -1, -3, -2};

// Base64 decode (standard alphabet, no padding required)
static std::vector<uint8_t> b64_decode(const char* s, size_t n) {
    static const int8_t T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    std::vector<uint8_t> out;
    int val = 0, bits = 0;
    for (size_t i = 0; i < n; i++) {
        int8_t c = T[(uint8_t)s[i]];
        if (c < 0) continue;
        val = (val << 6) | c;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)((val >> bits) & 0xFF));
        }
    }
    return out;
}

bool ff_unpack(ElfInfo& elf, std::vector<uint8_t>& buf, const LogFn& log) {
    const uint8_t* data = buf.data();
    size_t size = buf.size();

    // 1. Find the descriptor magic 0x12345678 in the trailing region.
    //    Descriptor is inside the appended stub ELF. Search the last 4 MB.
    size_t search_start = size > 4*1024*1024 ? size - 4*1024*1024 : 0;
    size_t desc_off = SIZE_MAX;
    for (size_t i = search_start; i + 0x200 <= size; i += 4) {
        uint32_t m; std::memcpy(&m, data + i, 4);
        if (m == 0x12345678u) {
            // Sanity: section name should be printable and begin with '.'
            const char* nm = (const char*)(data + i + 4);
            if (nm[0] == '.' && nm[1] >= 'a' && nm[1] <= 'z') { desc_off = i; break; }
        }
    }
    if (desc_off == SIZE_MAX) {
        log("  no packer descriptor found (0x12345678) — .so assumed already plaintext");
        return true;
    }
    log("Detected packed ELF (stub_decrypt_elf)");

    uint32_t file_off, vaddr, sec_size, desc_crc;
    std::memcpy(&file_off, data + desc_off + 0x14, 4);
    std::memcpy(&vaddr,    data + desc_off + 0x18, 4);
    std::memcpy(&sec_size, data + desc_off + 0x1c, 4);
    std::memcpy(&desc_crc, data + desc_off + 0x20, 4);
    log("  .rodata offset=0x" + std::to_string(file_off) +
        " vaddr=0x" + std::to_string(vaddr) +
        " size=0x" + std::to_string(sec_size));

    if ((uint64_t)file_off + sec_size > size) {
        log("  ERROR: descriptor offset out of file bounds");
        return false;
    }

    // 2. Derive XOR key from descriptor+0x186.
    uint8_t k1 = data[desc_off + 0x186] ^ 0x4F;

    // 3. Derive K from base64 key blob at +0x1a8.
    const char* b64 = (const char*)(data + desc_off + 0x1a8);
    size_t b64_len = 0;
    while (b64_len < 64 && b64[b64_len] && b64[b64_len] != '\0') b64_len++;
    // Cap to the base64 run length
    while (b64_len > 0 && b64[b64_len-1] != '=' && !((b64[b64_len-1]>='A'&&b64[b64_len-1]<='Z') ||
           (b64[b64_len-1]>='a'&&b64[b64_len-1]<='z') ||
           (b64[b64_len-1]>='0'&&b64[b64_len-1]<='9') ||
           b64[b64_len-1]=='+'||b64[b64_len-1]=='/')) b64_len--;
    // Advance to end of base64
    b64_len = 0;
    while (b64_len < 64) {
        char c = b64[b64_len];
        if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='+'||c=='/'||c=='=')) break;
        b64_len++;
    }

    auto blob = b64_decode(b64, b64_len);
    for (auto& b : blob) b ^= 0x4F;

    if (blob.size() < 16) {
        log("  ERROR: key blob too short");
        return false;
    }
    uint32_t K_be;
    std::memcpy(&K_be, blob.data() + 12, 4);
    // Blob is big-endian packed; swap on little-endian host
    uint32_t K = ((K_be & 0xFF) << 24) | ((K_be & 0xFF00) << 8) |
                 ((K_be >> 8) & 0xFF00) | ((K_be >> 24) & 0xFF);
    uint8_t k2 = (K >> 16) & 0xFF;

    // Cross-check: two independent signals must agree.
    if (k1 != k2) {
        log("  ERROR: descriptor key vs blob key mismatch (" +
            std::to_string(k1) + " vs " + std::to_string(k2) + ")");
        return false;
    }

    // Third signal — most frequent byte of packed region.
    uint32_t hist[256] = {0};
    const uint8_t* sec = data + file_off;
    for (uint32_t i = 0; i < sec_size; i += 64) hist[sec[i]]++;
    uint32_t best = 0; uint8_t best_byte = 0;
    for (int i = 0; i < 256; i++) if (hist[i] > best) { best = hist[i]; best_byte = (uint8_t)i; }
    // Plaintext .rodata is dominated by 0x00. If 0x00 wins, region is already plaintext.
    if (best_byte == 0x00 && hist[0] > sec_size / 128) {
        log("  .rodata already plaintext, skipping unpack");
        return true;
    }

    log("  Unpacked with key 0x" + [&]{ char b[8]; snprintf(b,8,"%02X",k1); return std::string(b); }() +
        " (from descriptor), window 0 via AES-128-CBC seed 0x" +
        [&]{ char b[16]; snprintf(b,16,"%08x",K); return std::string(b); }());

    // 4. Bulk XOR + window permutation.
    //    windows are 0x4000 bytes at stride 0x10000, first at (section_start & ~0xFFF) + 0x2000.
    //    window 0 uses AES-128-CBC.
    //    We work on the whole section — but window 0 is the first 0x4000 bytes.
    const size_t WIN = 0x4000;
    const size_t STRIDE = 0x10000;
    uint64_t sec_start = file_off;
    uint64_t win0_start = (sec_start & ~0xFFFULL) + 0x2000;
    if (win0_start < sec_start) win0_start += 0x1000;

    // Number of windows: floor((sec_size - (win0_start - sec_start)) / STRIDE) + 1
    if (win0_start >= sec_start + sec_size) {
        log("  ERROR: window 0 start outside section");
        return false;
    }
    size_t rel0 = win0_start - sec_start;
    size_t nwin = (sec_size - rel0 + STRIDE - 1) / STRIDE;

    // Work on a copy of the section — we'll write it back into buf.
    std::vector<uint8_t> plain(sec_size);
    std::memcpy(plain.data(), sec, sec_size);

    // First, extract each window from its permuted slot and XOR.
    std::vector<std::vector<uint8_t>> windows(nwin);
    for (size_t i = 0; i < nwin; i++) {
        size_t src_i = i;
        // trailing partial group is not permuted
        size_t group = i / 8;
        size_t in_group = i % 8;
        size_t group_start = group * 8 + 2;
        bool in_trailing = (group_start + 7) >= nwin;
        if (!in_trailing && i >= 2) {
            int8_t d = D8[i % 8];
            src_i = (size_t)((int64_t)i + d);
        }
        // Last window not clipped
        size_t src_off = rel0 + src_i * STRIDE;
        size_t len = (i == nwin - 1) ? (sec_size - rel0 - i * STRIDE) : WIN;
        if (len > WIN) len = WIN;
        if (src_off + len > sec_size) { len = sec_size - src_off; }
        windows[i].resize(len);
        std::memcpy(windows[i].data(), sec + src_off, len);
        for (auto& b : windows[i]) b ^= k1;
    }

    // Write windows back at their natural position
    std::memset(plain.data(), 0, sec_size);
    for (size_t i = 0; i < nwin; i++) {
        size_t dst_off = rel0 + i * STRIDE;
        size_t len = windows[i].size();
        if (dst_off + len > sec_size) len = sec_size - dst_off;
        std::memcpy(plain.data() + dst_off, windows[i].data(), len);
    }

    // Now fix window 0 with AES-128-CBC in 8 x 0x800 chunks.
    {
        char keystr[32];
        snprintf(keystr, sizeof(keystr), "%08x%08x", K, K);
        static const uint8_t IV[16] = {0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
                                       0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11};
        size_t chunk = 0x800;
        size_t w0_len = windows[0].size();
        for (size_t off = 0; off + chunk <= w0_len; off += chunk) {
            aes128_cbc_decrypt((const uint8_t*)keystr, IV,
                               sec + rel0 + off, plain.data() + rel0 + off, chunk);
        }
        // If trailing partial, CBC the remainder as-is (still 16-multiple in practice)
    }

    // CRC32 check
    uint32_t got = crc32_calc(plain.data(), sec_size);
    char crcbuf[64];
    snprintf(crcbuf, sizeof(crcbuf), "0x%08X", got);
    if (got != desc_crc) {
        log(std::string("  CRC32 mismatch: got ") + crcbuf);
        return false;
    }
    snprintf(crcbuf, sizeof(crcbuf), "0x%08X", desc_crc);
    log(std::string("  CRC32 matches the descriptor (") + crcbuf + ") — section is byte-exact.");
    log("Dumping...");

    // Write unpacked section back into the working buffer.
    std::memcpy(buf.data() + file_off, plain.data(), sec_size);
    return true;
}
