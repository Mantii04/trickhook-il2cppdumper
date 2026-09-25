#include "il2cpp_binary.h"
#include "metadata.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <algorithm>

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

    imageBase_ = 0;
    return true;
}

uint64_t Il2CppBinary::mapVaddrToOffset(uint64_t vaddr) const {
    for (auto& s : elf_.sections) {
        if (s.sh_size == 0) continue;
        if (vaddr >= s.sh_addr && vaddr < s.sh_addr + s.sh_size) {
            return vaddr - s.sh_addr + s.sh_offset;
        }
    }
    return vaddr;
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

// ---- anchor-based registration search ----

// Find a null-terminated string inside a named section. Returns its vaddr.
static uint64_t find_string_vaddr(const uint8_t* data, size_t size,
                                  const ElfInfo& elf,
                                  const std::string& sectionName,
                                  const std::string& needle) {
    for (const auto& s : elf.sections) {
        if (s.name != sectionName) continue;
        if (s.sh_offset + s.sh_size > size) continue;
        const uint8_t* base = data + s.sh_offset;
        size_t nlen = needle.size();
        for (size_t i = 0; i + nlen < s.sh_size; i++) {
            if (std::memcmp(base + i, needle.data(), nlen) != 0) continue;
            // boundary check: preceding byte is NUL (or start), following byte is NUL
            bool leftOk  = (i == 0) || (base[i - 1] == 0);
            bool rightOk = (base[i + nlen] == 0);
            if (leftOk && rightOk) return s.sh_addr + i;
        }
    }
    return 0;
}

// Search given sections for a qword equal to target. Returns vaddr of that qword.
static uint64_t find_pointer_to(const uint8_t* data, size_t size,
                                const ElfInfo& elf,
                                const std::vector<std::string>& sectionNames,
                                uint64_t target) {
    for (const auto& s : elf.sections) {
        bool ok = false;
        for (const auto& n : sectionNames) if (s.name == n) { ok = true; break; }
        if (!ok) continue;
        if (s.sh_offset + s.sh_size > size) continue;
        size_t alignedStart = (s.sh_offset + 7) & ~7ull;
        for (size_t i = alignedStart; i + 8 <= s.sh_offset + s.sh_size; i += 8) {
            uint64_t v; std::memcpy(&v, data + i, 8);
            if (v == target) return s.sh_addr + (i - s.sh_offset);
        }
    }
    return 0;
}

bool Il2CppBinary::findRegistrations(const Metadata& md, const LogFn& log) {
    (void)md;

    std::vector<std::string> dataSections = {
        ".data", ".data.rel.ro", ".got", ".got.plt", ".bss"
    };

    // ---- Anchor: locate "Assembly-CSharp.dll" string ----
    uint64_t strVaddr = find_string_vaddr(data_.data(), data_.size(), elf_, ".rodata", "Assembly-CSharp.dll");
    if (strVaddr == 0) {
        // try any section
        for (const auto& s : elf_.sections) {
            strVaddr = find_string_vaddr(data_.data(), data_.size(), elf_, s.name, "Assembly-CSharp.dll");
            if (strVaddr) break;
        }
    }
    if (strVaddr == 0) {
        log("  ERROR: 'Assembly-CSharp.dll' anchor string not found");
        return false;
    }
    {
        char b[128];
        snprintf(b, sizeof(b), "  anchor: 'Assembly-CSharp.dll' at vaddr 0x%llx",
                 (unsigned long long)strVaddr);
        log(b);
    }

    // ---- Find pointer to the string: this is Il2CppCodeGenModule.moduleName (offset 0) ----
    uint64_t moduleNamePtrVaddr = find_pointer_to(data_.data(), data_.size(), elf_, dataSections, strVaddr);
    if (moduleNamePtrVaddr == 0) {
        log("  ERROR: no pointer to the anchor string found in data sections");
        return false;
    }
    uint64_t codeGenModuleAddr = moduleNamePtrVaddr;  // moduleName is at offset 0 of the struct
    {
        char b[128];
        snprintf(b, sizeof(b), "  first CodeGenModule at vaddr 0x%llx",
                 (unsigned long long)codeGenModuleAddr);
        log(b);
    }

    // Validate: read methodPointerCount and methodPointers from that module
    uint64_t mpc = readPtr(codeGenModuleAddr + 0x08);
    uint64_t mpp = readPtr(codeGenModuleAddr + 0x10);
    {
        char b[160];
        snprintf(b, sizeof(b), "    methodPointerCount=%llu methodPointers=0x%llx",
                 (unsigned long long)mpc, (unsigned long long)mpp);
        log(b);
    }
    if (mpc == 0 || mpc > 1000000) {
        log("  ERROR: CodeGenModule layout mismatch (methodPointerCount out of range)");
        return false;
    }

    // ---- Find a pointer to codeGenModuleAddr: that's an entry in codeGenModules array ----
    uint64_t arrayEntryVaddr = find_pointer_to(data_.data(), data_.size(), elf_, dataSections, codeGenModuleAddr);
    if (arrayEntryVaddr == 0) {
        log("  ERROR: no pointer to CodeGenModule in data sections");
        return false;
    }
    {
        char b[128];
        snprintf(b, sizeof(b), "  codeGenModules array entry at vaddr 0x%llx",
                 (unsigned long long)arrayEntryVaddr);
        log(b);
    }

    // The array entry could be anywhere in the array, not necessarily index 0.
    // Read backwards in 8-byte steps to find the array start (previous entries
    // should also point to valid CodeGenModule addresses).
    uint64_t arrayStart = arrayEntryVaddr;
    for (int back = 0; back < 200; back++) {
        uint64_t prev = arrayStart - 8;
        uint64_t v = readPtr(prev);
        // If the previous entry looks like a valid module pointer (points to
        // a null-terminated name inside .rodata), keep walking back.
        if (v == 0) break;
        // sanity: pointer must land in data or rodata
        bool plausible = false;
        for (const auto& s : elf_.sections) {
            if (v >= s.sh_addr && v < s.sh_addr + s.sh_size) { plausible = true; break; }
        }
        if (!plausible) break;
        arrayStart = prev;
    }
    {
        char b[128];
        snprintf(b, sizeof(b), "  codeGenModules array start at vaddr 0x%llx",
                 (unsigned long long)arrayStart);
        log(b);
    }

    // ---- Find a pointer to arrayStart: that's codeGenModules in CodeRegistration ----
    uint64_t cgmFieldVaddr = find_pointer_to(data_.data(), data_.size(), elf_, dataSections, arrayStart);
    if (cgmFieldVaddr == 0) {
        // maybe the array is referenced by a pointer at arrayStart itself as cgm
        log("  ERROR: no pointer to codeGenModules array found");
        return false;
    }
    // CodeRegistration base: cgm is at +0x80 in v31
    uint64_t codeReg = cgmFieldVaddr - 0x80;
    // sanity: reversePInvokeWrapperCount should be a plausible small count
    uint64_t rpwc = readPtr(codeReg + 0x00);
    uint64_t gmcp = readPtr(codeReg + 0x10);
    uint64_t invc = readPtr(codeReg + 0x28);
    {
        char b[200];
        snprintf(b, sizeof(b),
            "  CodeRegistration candidate @ 0x%llx: reversePInvokeWrapperCount=%llu genericMethodPointersCount=%llu invokerPointersCount=%llu",
            (unsigned long long)codeReg,
            (unsigned long long)rpwc,
            (unsigned long long)gmcp,
            (unsigned long long)invc);
        log(b);
    }
    // v31 detection: if genericMethodPointersCount > 0x50000, real base is +0x10
    // (the struct's first field is genericMethodPointersCount, not reversePInvokeWrapperCount).
    if (gmcp > 0x50000) {
        // try shifted layout: real CodeRegistration starts 16 bytes later
        uint64_t altReg = codeReg + 16;
        uint64_t altGmcp = readPtr(altReg + 0x10);
        uint64_t altCgm  = readPtr(altReg + 0x80);
        if (altCgm == arrayStart && altGmcp <= 0x50000) {
            codeReg = altReg;
            log("  v31 field-order adjustment applied (+0x10)");
        }
    }
    if (cgmFieldVaddr == 0) {
        log("  ERROR: could not locate codeGenModules field");
        return false;
    }

    codeRegAddr_ = codeReg;
    diag_.codeReg = codeReg;
    diag_.codeGenModulesCount = readPtr(codeReg + 0x78);
    {
        char b[160];
        snprintf(b, sizeof(b), "  CodeRegistration @ 0x%llx: codeGenModulesCount=%llu",
                 (unsigned long long)codeReg,
                 (unsigned long long)diag_.codeGenModulesCount);
        log(b);
    }

    // ---- MetadataRegistration ----
    // Anchor: "mscorlib.dll" string in .rodata, then pointer to it,
    // then backtrack to find MetadataRegistration.
    // Simpler: after locating CodeRegistration, the MetadataRegistration is
    // typically placed nearby in .data.rel.ro with a distinctive pattern:
    //   genericClassesCount, genericClasses, genericInstsCount, genericInsts,
    //   genericMethodTableCount, genericMethodTable, typesCount, types,
    //   methodSpecsCount, methodSpecs, ...
    // Search for a struct where typesCount matches expected ~= 43956.
    uint64_t expectedTypes = 43956;  // from prior run (was logged)
    uint64_t metaReg = 0;
    uint64_t metaRegBestDelta = ~0ull;
    for (const auto& s : elf_.sections) {
        if (s.name != ".data.rel.ro" && s.name != ".data") continue;
        if (s.sh_offset + s.sh_size > data_.size()) continue;
        size_t alignedStart = (s.sh_offset + 7) & ~7ull;
        for (size_t i = alignedStart; i + 80 <= s.sh_offset + s.sh_size; i += 8) {
            uint64_t vaddr = s.sh_addr + (i - s.sh_offset);
            uint64_t typesCount = readPtr(vaddr + 0x30);
            uint64_t typesPtr   = readPtr(vaddr + 0x38);
            if (typesCount < 1000 || typesCount > 500000) continue;
            if (!isInRange(typesPtr, 16)) continue;
            // types pointer must point into a loaded section
            bool ok = false;
            for (const auto& ss : elf_.sections) {
                if (typesPtr >= ss.sh_addr && typesPtr < ss.sh_addr + ss.sh_size) { ok = true; break; }
            }
            if (!ok) continue;
            // Prefer candidate closest to expectedTypes if we know it
            uint64_t delta = typesCount > expectedTypes ? typesCount - expectedTypes : expectedTypes - typesCount;
            if (delta < metaRegBestDelta) {
                metaRegBestDelta = delta;
                metaReg = vaddr;
            }
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

    // MetadataRegistration fields
    metadataRegistrationGenericInstsCount_ = readPtr(metaRegAddr_ + 0x10);
    metadataRegistrationGenericInsts_      = readPtr(metaRegAddr_ + 0x18);
    metadataRegistrationTypesCount_        = readPtr(metaRegAddr_ + 0x30);
    metadataRegistrationTypes_             = readPtr(metaRegAddr_ + 0x38);
    metadataRegistrationMethodSpecsCount_  = readPtr(metaRegAddr_ + 0x40);
    metadataRegistrationMethodSpecs_       = readPtr(metaRegAddr_ + 0x48);

    // Il2CppType array
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

    // GenericInsts
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

    // MethodSpecs
    methodSpecs_.reserve((size_t)metadataRegistrationMethodSpecsCount_);
    for (uint64_t i = 0; i < metadataRegistrationMethodSpecsCount_; i++) {
        uint64_t base = metadataRegistrationMethodSpecs_ + i * 12;
        Il2CppMethodSpec ms;
        ms.methodDefinitionIndex = readI32(base + 0);
        ms.classIndexIndex       = readI32(base + 4);
        ms.methodIndexIndex      = readI32(base + 8);
        methodSpecs_.push_back(ms);
    }
    log("  " + std::to_string(methodSpecs_.size()) + " methodSpecs");

    // CodeRegistration -> codeGenModules
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
