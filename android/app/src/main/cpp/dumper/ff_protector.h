#pragma once
#include "common.h"
#include "elf_parser.h"

// Unpacks the Free Fire stub-appended .rodata region in-place.
// Returns true if unpacked (or already plaintext), false on failure.
bool ff_unpack(ElfInfo& elf, std::vector<uint8_t>& workbuf, const LogFn& log);
