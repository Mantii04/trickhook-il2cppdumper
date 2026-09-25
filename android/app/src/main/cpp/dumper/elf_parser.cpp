#include "elf_parser.h"

const ElfSection* ElfInfo::find(const std::string& n) const {
    for (auto& s : sections) if (s.name == n) return &s;
    return nullptr;
}

ElfInfo parse_elf(const uint8_t* data, size_t size) {
    ElfInfo out; out.raw = data; out.raw_size = size;
    if (size < 64) return out;
    if (!(data[0]==0x7f && data[1]=='E' && data[2]=='L' && data[3]=='F')) return out;

    out.is64 = (data[4] == 2);
    Reader r{data, size};

    if (out.is64) {
        r.seek(0x18); out.entry = r.u64();
        r.seek(0x28); uint64_t shoff = r.u64();
        r.seek(0x3A); uint16_t shentsize = r.u16();
        uint16_t shnum = r.u16();
        uint16_t shstrndx = r.u16();

        if (shoff + (uint64_t)shnum * shentsize > size) return out;

        // First pass: read shstrtab
        uint64_t str_off = 0, str_size = 0;
        r.seek(shoff + (uint64_t)shstrndx * shentsize + 0x18);
        str_off = r.u64();
        str_size = r.u64();
        if (str_off + str_size > size) return out;

        for (uint16_t i = 0; i < shnum; i++) {
            r.seek(shoff + (uint64_t)i * shentsize);
            uint32_t name_idx = r.u32();
            uint32_t type = r.u32();
            r.skip(8); // flags + addr
            uint64_t addr = r.u64();
            uint64_t off = r.u64();
            uint64_t sz = r.u64();
            r.skip(8); // link + info
            r.skip(8); // addralign + entsize

            ElfSection s;
            s.sh_type = type;
            s.sh_addr = addr;
            s.sh_offset = off;
            s.sh_size = sz;
            if (name_idx < str_size) {
                const char* base = (const char*)(data + str_off);
                s.name = std::string(base + name_idx);
            }
            out.sections.push_back(std::move(s));
        }
    } else {
        // 32-bit
        r.seek(0x18); out.entry = r.u32();
        r.seek(0x20); uint32_t shoff = r.u32();
        r.seek(0x2E); uint16_t shentsize = r.u16();
        uint16_t shnum = r.u16();
        uint16_t shstrndx = r.u16();

        if (shoff + (uint64_t)shnum * shentsize > size) return out;

        uint32_t str_off = 0, str_size = 0;
        r.seek(shoff + (uint64_t)shstrndx * shentsize + 0x10);
        str_off = r.u32();
        str_size = r.u32();
        if ((uint64_t)str_off + str_size > size) return out;

        for (uint16_t i = 0; i < shnum; i++) {
            r.seek(shoff + (uint64_t)i * shentsize);
            uint32_t name_idx = r.u32();
            uint32_t type = r.u32();
            uint32_t flags = r.u32();
            uint32_t addr = r.u32();
            uint32_t off = r.u32();
            uint32_t sz = r.u32();
            (void)flags;
            ElfSection s;
            s.sh_type = type;
            s.sh_addr = addr;
            s.sh_offset = off;
            s.sh_size = sz;
            if (name_idx < str_size) {
                const char* base = (const char*)(data + str_off);
                s.name = std::string(base + name_idx);
            }
            out.sections.push_back(std::move(s));
        }
    }
    out.valid = true;
    return out;
}
