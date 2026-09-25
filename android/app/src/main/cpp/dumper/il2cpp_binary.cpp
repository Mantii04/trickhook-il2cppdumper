#include "il2cpp_binary.h"
#include "metadata.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <fstream>
#include <algorithm>

// parse base from filename: *-<hex>-<hex>.bin
// e.g. "com.dts.freefiremax-75d3a81000-75f25ca000.bin" -> 0x75d3a81000
static uint64_t parse_base_from_path(const std::string& path) {
    size_t slash = path.find_last_of('/');
    std::string name = (slash == std::string::npos) ? path : path.substr(slash + 1);
    size_t lastDot = name.find_last_of('.');
    if (lastDot != std::string::npos) name = name.substr(0, lastDot);
    size_t lastDash = name.find_last_of('-');
    if (lastDash == std::string::npos) return 0;
    size_t prevDash = name.find_last_of('-', lastDash - 1);
    if (prevDash == std::string::npos) return 0;
    std::string hexA = name.substr(prevDash + 1, lastDash - prevDash - 1);
    if (hexA.empty() || hexA.size() > 16) return 0;
    for (char c : hexA) if (!isxdigit((unsigned char)c)) return 0;
    return std::strtoull(hexA.c_str(), nullptr, 16);
}

// detect base by looking at .init_array entries — they hold runtime pointers into .text
static uint64_t detect_base_from_init_array(const std::vector<uint8_t>& data, const ElfInfo& elf) {
    const ElfSection* initArr = nullptr;
    for (const auto& s : elf.sections) if (s.name == ".init_array") { initArr = &s; break; }
    if (!initArr || initArr->sh_size < 16) return 0;

    std::vector<uint64_t> entries;
    for (size_t i = 0; i + 8 <= initArr->sh_size; i += 8) {
        size_t off = initArr->sh_offset + i;
        if (off + 8 > data.size()) break;
        uint64_t v; std::memcpy(&v, data.data() + off, 8);
        if (v > 0x100000000ull && v < 0x800000000000ull) entries.push_back(v);
    }
    if (entries.size() < 2) return 0;

    uint64_t mn = *std::min_element(entries.begin(), entries.end());
    // candidate: Y such that every entry - Y is < 256 MB
    for (uint64_t delta = 0; delta < 0x20000000ull; delta += 0x1000) {
        uint64_t Y = (mn & ~0xFFFull) - delta;
        if (Y == 0) break;
        bool ok = true;
        for (uint64_t e : entries) {
            uint64_t norm = e - Y;
            if (norm > 0x10000000ull) { ok = false; break; }
        }
        if (ok) return Y;
    }
    return 0;
}

bool Il2CppBinary::load(const std::string& path, const LogFn& log) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { log("cannot open " + path); return false; }
    f.seekg(0, std::ios::end);
    std::streamoff n = f.tellg();
    f.seekg(0, std::ios::beg);
    data_.resize((size_t)n);
    f.read((char*)data_.data(), n);
    if (!f) { log("read failed"); return false; }

    log("loading .so: " + path);
    log("  " + std::to_string(n / 1024 / 1024) + " MB");

    elf_ = parse_elf(data_.data(), data_.size());
    if (!elf_.valid) { log("not a valid ELF"); return false; }
    log("  parsed ELF, " + std::to_string(elf_.sections.size()) + " sections");

    // Runtime base: parse from filename, fall back to .init_array heuristic
    base_ = parse_base_from_path(path);
    if (base_ == 0) {
        base_ = detect_base_from_init_array(data_, elf_);
        if (base_ != 0) log("  base detected from .init_array");
    }
    if (base_ == 0) {
        log("  WARN: no runtime base detected — assuming dump is normalized");
        base_ = 0;
    }
    {
        char b[64];
        snprintf(b, sizeof(b), "  runtime base = 0x%llx", (unsigned long long)base_);
        log(b);
    }
    imageBase_ = base_;
    return true;
}

uint64_t Il2CppBinary::mapVaddrToOffset(uint64_t runtimeVaddr) const {
    // runtime vaddr -> normalized vaddr -> file offset via sections
    uint64_t v = runtimeVaddr - base_;
    for (auto& s : elf_.sections) {
        if (s.sh_size == 0) continue;
        if (v >= s.sh_addr && v < s.sh_addr + s.sh_size) {
            return v - s.sh_addr + s.sh_offset;
        }
    }
    return v;
}

bool Il2CppBinary::isInRange(uint64_t vaddr, size_t len) const {
    uint64_t off = mapVaddrToOffset(vaddr);
    return off + len <= data_.size();
}

uint64_t Il2CppBinary::readPtr(uint64_t vaddr) const {
    uint64_t off = mapVaddrToOffset(vaddr);
    if (off + 8 > data_.size()) return 0;
    uint64_t v; std::memcpy(&v, data_.data() + off, 8); return v;
}

int32_t Il2CppBinary::readI32(uint64_t vaddr) const {
    uint64_t off = mapVaddrToOffset(vaddr);
    if (off + 4 > data_.size()) return 0;
    int32_t v; std::memcpy(&v, data_.data() + off, 4); return v;
}

uint32_t Il2CppBinary::readU32(uint64_t vaddr) const {
    uint64_t off = mapVaddrToOffset(vaddr);
    if (off + 4 > data_.size()) return 0;
    uint32_t v; std::memcpy(&v, data_.data() + off, 4); return v;
}

uint16_t Il2CppBinary::readU16(uint64_t vaddr) const {
    uint64_t off = mapVaddrToOffset(vaddr);
    if (off + 2 > data_.size()) return 0;
    uint16_t v; std::memcpy(&v, data_.data() + off, 2); return v;
}

std::string Il2CppBinary::readCStr(uint64_t vaddr) const {
    uint64_t off = mapVaddrToOffset(vaddr);
    if (off >= data_.size()) return "";
    const char* p = (const char*)(data_.data() + off);
    size_t max = data_.size() - off;
    size_t len = strnlen(p, max);
    return std::string(p, len);
}

// Find a null-terminated string inside a named section. Returns its RUNTIME vaddr.
static uint64_t find_string_runtime(const uint8_t* data, size_t size,
                                    const ElfInfo& elf, uint64_t base,
                                    const std::string& sectionName,
                                    const std::string& needle) {
    for (const auto& s : elf.sections) {
        if (s.name != sectionName) continue;
        if (s.sh_offset + s.sh_size > size) continue;
        const uint8_t* b = data + s.sh_offset;
        size_t nlen = needle.size();
        for (size_t i = 0; i + nlen < s.sh_size; i++) {
            if (std::memcmp(b + i, needle.data(), nlen) != 0) continue;
            bool leftOk  = (i == 0) || (b[i - 1] == 0);
            bool rightOk = (b[i + nlen] == 0);
            if (leftOk && rightOk) return base + s.sh_addr + i;
        }
    }
    return 0;
}

// Search sections for a qword equal to target. Returns RUNTIME vaddr of the qword.
static uint64_t find_pointer_runtime(const uint8_t* data, size_t size,
                                     const ElfInfo& elf, uint64_t base,
                                     const std::vector<std::string>& sectionNames,
                                     uint64_t target) {
    for (const auto& s : elf.sections) {
        bool ok = false;
        for (const auto& n : sectionNames) if (s.name == n) { ok = true; break; }
        if (!ok) continue;
        if (s.sh_offset + s.sh_size > size) continue;
        size_t i = (s.sh_offset + 7) & ~7ull;
        for (; i + 8 <= s.sh_offset + s.sh_size; i += 8) {
            uint64_t v; std::memcpy(&v, data + i, 8);
            if (v == target) return base + s.sh_addr + (i - s.sh_offset);
        }
    }
    return 0;
}

bool Il2CppBinary::findRegistrations(const Metadata& md, const LogFn& log) {
    (void)md;

    std::vector<std::string> dataSections = {
        ".data", ".data.rel.ro", ".got", ".got.plt", ".bss"
    };

    // Anchor string
    uint64_t strRuntime = find_string_runtime(data_.data(), data_.size(),
                                              elf_, base_, ".rodata", "Assembly-CSharp.dll");
    if (strRuntime == 0) {
        for (const auto& s : elf_.sections) {
            strRuntime = find_string_runtime(data_.data(), data_.size(),
                                             elf_, base_, s.name, "Assembly-CSharp.dll");
            if (strRuntime) break;
        }
    }
    if (strRuntime == 0) {
        log("  ERROR: 'Assembly-CSharp.dll' anchor string not found");
        return false;
    }
    {
        char b[128];
        snprintf(b, sizeof(b), "  anchor string runtime vaddr = 0x%llx",
                 (unsigned long long)strRuntime);
        log(b);
    }

    // Pointer to the string = first CodeGenModule.moduleName
    uint64_t modRuntime = find_pointer_runtime(data_.data(), data_.size(),
                                               elf_, base_, dataSections, strRuntime);
    if (modRuntime == 0) {
        log("  ERROR: no pointer to anchor string in data sections");
        return false;
    }
    {
        char b[128];
        snprintf(b, sizeof(b), "  first CodeGenModule runtime = 0x%llx",
                 (unsigned long long)modRuntime);
        log(b);
    }

    // module: +0x00 name ptr, +0x08 methodPointerCount, +0x10 methodPointers ptr
    uint64_t mpc = readPtr(modRuntime + 0x08);
    uint64_t mpp = readPtr(modRuntime + 0x10);
    {
        char b[160];
        snprintf(b, sizeof(b), "    methodPointerCount=%llu methodPointers=0x%llx",
                 (unsigned long long)mpc, (unsigned long long)mpp);
        log(b);
    }
    if (mpc == 0 || mpc > 1000000) {
        log("  ERROR: CodeGenModule methodPointerCount out of range");
        return false;
    }

    // Find pointer to modRuntime -> entry in codeGenModules array
    uint64_t arrEntry = find_pointer_runtime(data_.data(), data_.size(),
                                             elf_, base_, dataSections, modRuntime);
    if (arrEntry == 0) {
        log("  ERROR: no pointer to CodeGenModule in data sections");
        return false;
    }
    {
        char b[128];
        snprintf(b, sizeof(b), "  codeGenModules array entry runtime = 0x%llx",
                 (unsigned long long)arrEntry);
        log(b);
    }

    // Walk back to find array start
    uint64_t arrStart = arrEntry;
    for (int back = 0; back < 500; back++) {
        uint64_t prev = arrStart - 8;
        uint64_t v = readPtr(prev);
        if (v == 0) break;
        // must land inside a loaded section (normalize by subtracting base)
        uint64_t nv = v - base_;
        bool plausible = false;
        for (const auto& s : elf_.sections) {
            if (nv >= s.sh_addr && nv < s.sh_addr + s.sh_size) { plausible = true; break; }
        }
        if (!plausible) break;
        arrStart = prev;
    }
    {
        char b[128];
        snprintf(b, sizeof(b), "  codeGenModules array start runtime = 0x%llx",
                 (unsigned long long)arrStart);
        log(b);
    }

    // Find pointer to arrStart: this is CodeRegistration.codeGenModules
    uint64_t cgmFieldRuntime = find_pointer_runtime(data_.data(), data_.size(),
                                                    elf_, base_, dataSections, arrStart);
    if (cgmFieldRuntime == 0) {
        log("  ERROR: no pointer to codeGenModules array");
        return false;
    }
    // v31: codeGenModules is at +0x80
    uint64_t codeReg = cgmFieldRuntime - 0x80;
    {
        uint64_t rpwc = readPtr(codeReg + 0x00);
        uint64_t gmcp = readPtr(codeReg + 0x10);
        uint64_t invc = readPtr(codeReg + 0x28);
        char b[220];
        snprintf(b, sizeof(b),
            "  CodeRegistration candidate @ 0x%llx: reversePInvokeWrapperCount=%llu genericMethodPointersCount=%llu invokerPointersCount=%llu",
            (unsigned long long)codeReg,
            (unsigned long long)rpwc, (unsigned long long)gmcp, (unsigned long long)invc);
        log(b);
    }
    // sanity: cgm pointer at +0x80 must equal arrStart
    if (readPtr(codeReg + 0x80) != arrStart) {
        // Try +0x78 layout (v29.1 older)
        if (readPtr(codeReg + 0x78) == arrStart) {
            codeReg = cgmFieldRuntime - 0x78;
            log("  adjusting CodeRegistration offset (-0x78)");
        }
    }

    codeRegAddr_ = codeReg;
    diag_.codeReg = codeReg;
    diag_.codeGenModulesCount = readPtr(codeReg + 0x78);
    {
        char b[160];
        snprintf(b, sizeof(b), "  CodeRegistration @ 0x%llx: codeGenModulesCount=%llu",
                 (unsigned long long)codeReg, (unsigned long long)diag_.codeGenModulesCount);
        log(b);
    }

    // MetadataRegistration: search .data.rel.ro for struct with plausible typesCount
    uint64_t metaReg = 0;
    uint64_t expectedTypes = 43956;
    uint64_t bestDelta = ~0ull;
    for (const auto& s : elf_.sections) {
        if (s.name != ".data.rel.ro" && s.name != ".data") continue;
        if (s.sh_offset + s.sh_size > data_.size()) continue;
        size_t i = (s.sh_offset + 7) & ~7ull;
        for (; i + 0x60 <= s.sh_offset + s.sh_size; i += 8) {
            uint64_t runtimeAddr = base_ + s.sh_addr + (i - s.sh_offset);
            uint64_t typesCount = readPtr(runtimeAddr + 0x30);
            uint64_t typesPtr   = readPtr(runtimeAddr + 0x38);
            if (typesCount < 1000 || typesCount > 500000) continue;
            // typesPtr must be runtime and land in a loaded section
            uint64_t nv = typesPtr - base_;
            bool ok = false;
            for (const auto& ss : elf_.sections) {
                if (nv >= ss.sh_addr && nv < ss.sh_addr + ss.sh_size) { ok = true; break; }
            }
            if (!ok) continue;
            uint64_t delta = typesCount > expectedTypes ? typesCount - expectedTypes : expectedTypes - typesCount;
            if (delta < bestDelta) { bestDelta = delta; metaReg = runtimeAddr; }
        }
    }
    if (metaReg == 0) {
        log("  ERROR: MetadataRegistration not found");
        return false;
    }
    diag_.metaReg = metaReg;
    diag_.typeCount = readPtr(metaReg + 0x30);
    diag_.genericInstsCount = readPtr(metaReg + 0x10);
    {
        char b[200];
        snprintf(b, sizeof(b),
            "  MetadataRegistration @ 0x%llx: typesCount=%llu genericInstsCount=%llu",
            (unsigned long long)metaReg,
            (unsigned long long)diag_.typeCount,
            (unsigned long long)diag_.genericInstsCount);
        log(b);
    }

    metaRegAddr_ = metaReg;
    return true;
}

bool Il2CppBinary::parseRegistrations(const Metadata& md, const LogFn& log) {
    (void)md;
    if (!codeRegAddr_ || !metaRegAddr_) { log("regs not found"); return false; }

    metadataRegistrationGenericInstsCount_ = readPtr(metaRegAddr_ + 0x10);
    metadataRegistrationGenericInsts_      = readPtr(metaRegAddr_ + 0x18);
    metadataRegistrationTypesCount_        = readPtr(metaRegAddr_ + 0x30);
    metadataRegistrationTypes_             = readPtr(metaRegAddr_ + 0x38);
    metadataRegistrationMethodSpecsCount_  = readPtr(metaRegAddr_ + 0x40);
    metadataRegistrationMethodSpecs_       = readPtr(metaRegAddr_ + 0x48);

    log("  parsing Il2CppType array (" + std::to_string(metadataRegistrationTypesCount_) + " types)...");
    types_.reserve((size_t)metadataRegistrationTypesCount_);
    for (uint64_t i = 0; i < metadataRegistrationTypesCount_; i++) {
        uint64_t ptr = readPtr(metadataRegistrationTypes_ + i * 8);
        if (ptr == 0) { types_.push_back({}); continue; }
        Il2CppType t;
        t.datapoint = readPtr(ptr);
        t.bits = readU32(ptr + 8);
        t.init();
        types_.push_back(t);
        typeByPtr_[ptr] = i;
    }
    log("  " + std::to_string(types_.size()) + " types parsed");

    genericInstPointers_.reserve((size_t)metadataRegistrationGenericInstsCount_);
    genericInsts_.reserve((size_t)metadataRegistrationGenericInstsCount_);
    for (uint64_t i = 0; i < metadataRegistrationGenericInstsCount_; i++) {
        uint64_t ptr = readPtr(metadataRegistrationGenericInsts_ + i * 8);
        genericInstPointers_.push_back(ptr);
        Il2CppGenericInst gi{};
        if (ptr) {
            gi.type_argc = (int64_t)readPtr(ptr);
            gi.type_argv = readPtr(ptr + 8);
        }
        genericInsts_.push_back(gi);
    }
    log("  " + std::to_string(genericInsts_.size()) + " genericInsts");

    methodSpecs_.reserve((size_t)metadataRegistrationMethodSpecsCount_);
    for (uint64_t i = 0; i < metadataRegistrationMethodSpecsCount_; i++) {
        uint64_t b = metadataRegistrationMethodSpecs_ + i * 12;
        Il2CppMethodSpec ms;
        ms.methodDefinitionIndex = readI32(b + 0);
        ms.classIndexIndex       = readI32(b + 4);
        ms.methodIndexIndex      = readI32(b + 8);
        methodSpecs_.push_back(ms);
    }
    log("  " + std::to_string(methodSpecs_.size()) + " methodSpecs");

    uint64_t cgmCount = readPtr(codeRegAddr_ + 0x78);
    uint64_t cgmAddr  = readPtr(codeRegAddr_ + 0x80);
    diag_.codeGenModulesCount = cgmCount;

    log("  parsing " + std::to_string(cgmCount) + " codeGenModules...");
    codeGenModules_.reserve((size_t)cgmCount);
    for (uint64_t i = 0; i < cgmCount; i++) {
        uint64_t modAddr = readPtr(cgmAddr + i * 8);
        if (!modAddr) continue;
        Il2CppCodeGenModule m;
        uint64_t namePtr = readPtr(modAddr);
        m.name = readCStr(namePtr);
        m.methodPointerCount = readPtr(modAddr + 8);
        m.methodPointersAddr = readPtr(modAddr + 16);
        if (m.methodPointerCount > 0 && m.methodPointerCount < 1000000) {
            m.methodPointers.reserve((size_t)m.methodPointerCount);
            for (uint64_t j = 0; j < m.methodPointerCount; j++) {
                m.methodPointers.push_back(readPtr(m.methodPointersAddr + j * 8));
            }
        }
        codeGenModuleByName_[m.name] = codeGenModules_.size();
        codeGenModules_.push_back(std::move(m));
    }
    log("  " + std::to_string(codeGenModules_.size()) + " modules");
    return true;
}

const Il2CppType* Il2CppBinary::typeAt(uint64_t pointer) const {
    auto it = typeByPtr_.find(pointer);
    if (it == typeByPtr_.end()) return nullptr;
    return &types_[it->second];
}

uint64_t Il2CppBinary::methodPointer(const std::string& imageName, uint32_t token) const {
    auto it = codeGenModuleByName_.find(imageName);
    if (it == codeGenModuleByName_.end()) return 0;
    const auto& mod = codeGenModules_[it->second];
    uint32_t idx = token & 0x00FFFFFFu;
    if (idx == 0 || idx - 1 >= mod.methodPointers.size()) return 0;
    return mod.methodPointers[idx - 1];
}
