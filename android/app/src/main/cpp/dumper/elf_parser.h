#pragma once
#include "common.h"

struct ElfSection {
    std::string name;
    uint64_t sh_addr = 0;
    uint64_t sh_offset = 0;
    uint64_t sh_size = 0;
    uint32_t sh_type = 0;
};

struct ElfInfo {
    bool valid = false;
    bool is64 = true;
    uint64_t entry = 0;
    std::vector<ElfSection> sections;
    const uint8_t* raw = nullptr;
    size_t raw_size = 0;

    const ElfSection* find(const std::string& n) const;
};

ElfInfo parse_elf(const uint8_t* data, size_t size);
