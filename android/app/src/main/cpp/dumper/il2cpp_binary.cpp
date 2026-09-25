#include "il2cpp_binary.h"
#include "metadata.h"
#include <cstdio>
#include <cstring>
#include <map>
#include <fstream>

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

    // image base: min vaddr of PT_LOAD with vaddr != 0
    for (auto& s : elf_.sections) {
        if (s.sh_addr != 0 && s.sh_size > 0) {
            if (imageBase_ == 0 || s.sh_addr < imageBase_) imageBase_ = s.sh_addr;
        }
    }
    log("  imageBase = 0x" + [&]{ char b[32]; snprintf(b,sizeof(b),"%llx",(unsigned long long)imageBase_); return std::string(b); }());

    return true;
}

uint64_t Il2CppBinary::mapVaddrToOffset(uint64_t vaddr) const {
    // In the memory-dumped .so, VA -> file offset is:
    //   find a section whose [sh_addr, sh_addr + sh_size) contains vaddr
    //   offset = vaddr - sh_addr + sh_offset
    // ELF sections in this dump have sh_addr != sh_offset for .text and .plt
    // (page alignment), so we must use section mapping, not identity.
    for (auto& s : elf_.sections) {
        if (s.sh_size == 0) continue;
        if (vaddr >= s.sh_addr && vaddr < s.sh_addr + s.sh_size) {
            return vaddr - s.sh_addr + s.sh_offset;
        }
    }
    return vaddr;  // fallback
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

// ---- registration scan ----

// v31 arm64 Il2CppCodeRegistration layout:
//   +0x00 ulong methodPointersCount     (only if Version <= 24.1)
//   ...
//   For v31, the fields present are:
//     +0x00 reversePInvokeWrapperCount  -> WAIT, no. Let me use the C# order:
//   Version >= 24.2 fields in order:
//     reversePInvokeWrapperCount : ulong
//     reversePInvokeWrappers     : ulong
//     genericMethodPointersCount : ulong
//     genericMethodPointers      : ulong
//     genericAdjustorThunks      : ulong       (v27.1+)
//     invokerPointersCount       : ulong
//     invokerPointers            : ulong
//     unresolvedVirtualCallCount : ulong
//     unresolvedVirtualCallPointers: ulong
//     unresolvedInstanceCallPointers: ulong    (v29.1+)
//     unresolvedStaticCallPointers  : ulong    (v29.1+)
//     interopDataCount           : ulong
//     interopData                : ulong
//     windowsRuntimeFactoryCount : ulong       (v24.3+)
//     windowsRuntimeFactoryTable : ulong       (v24.3+)
//     codeGenModulesCount        : ulong
//     codeGenModules             : ulong
//
// For v31, that's the field order.

struct CodeRegLayout {
    uint64_t reversePInvokeWrapperCount;
    uint64_t reversePInvokeWrappers;
    uint64_t genericMethodPointersCount;
    uint64_t genericMethodPointers;
    uint64_t genericAdjustorThunks;              // v27.1+ only
    uint64_t invokerPointersCount;
    uint64_t invokerPointers;
    uint64_t unresolvedVirtualCallCount;
    uint64_t unresolvedVirtualCallPointers;
    uint64_t unresolvedInstanceCallPointers;     // v29.1+
    uint64_t unresolvedStaticCallPointers;       // v29.1+
    uint64_t interopDataCount;
    uint64_t interopData;
    uint64_t windowsRuntimeFactoryCount;
    uint64_t windowsRuntimeFactoryTable;
    uint64_t codeGenModulesCount;
    uint64_t codeGenModules;
};

// v31 arm64 Il2CppMetadataRegistration layout:
//   genericClassesCount : long
//   genericClasses      : ulong
//   genericInstsCount   : long
//   genericInsts        : ulong
//   genericMethodTableCount : long
//   genericMethodTable  : ulong
//   typesCount          : long
//   types               : ulong
//   methodSpecsCount    : long
//   methodSpecs         : ulong
//   fieldOffsetsCount   : long
//   fieldOffsets        : ulong
//   typeDefinitionsSizesCount : long
//   typeDefinitionsSizes      : ulong
//   metadataUsagesCount : ulong
//   metadataUsages      : ulong

bool Il2CppBinary::findRegistrations(const Metadata& md, const LogFn& log) {
    // Scan data sections for CodeRegistration and MetadataRegistration.
    // Heuristic: CodeRegistration has plausible counts and its methodPointers
    // array points into .text. MetadataRegistration has plausible typeCount
    // and its types array points into .data or .data.rel.ro.

    // Section names we'll scan
    std::vector<ElfSection*> dataSections;
    for (auto& s : elf_.sections) {
        if (s.sh_size < 64) continue;
        if (s.name == ".data" || s.name == ".data.rel.ro" ||
            s.name == ".bss" || s.name == ".got" ||
            s.name.find(".data") == 0) {
            dataSections.push_back(&s);
        }
    }

    // Find .text range for validation
    uint64_t textStart = 0, textEnd = 0;
    for (auto& s : elf_.sections) {
        if (s.name == ".text") { textStart = s.sh_addr; textEnd = s.sh_addr + s.sh_size; break; }
    }
    if (textStart == 0) { log("  no .text section"); return false; }

    // Search for CodeRegistration: find a struct where:
    //   - codeGenModulesCount between 1 and 2000
    //   - codeGenModules points into a data section
    //   - genericMethodPointersCount reasonable
    //   - genericMethodPointers points into a data section

    auto plausibleData = [&](uint64_t vaddr) {
        for (auto* s : dataSections) {
            if (vaddr >= s->sh_addr && vaddr < s->sh_addr + s->sh_size) return true;
        }
        return false;
    };

    size_t codeRegCandidates = 0;
    size_t metaRegCandidates = 0;

    for (auto* sec : dataSections) {
        size_t count = sec->sh_size / 8;
        for (size_t i = 0; i + 18 <= count; i++) {
            uint64_t addr = sec->sh_addr + i * 8;
            // Try as CodeRegistration at various alignments
            for (int shift = 0; shift <= 8; shift += 8) {
                uint64_t base = addr + shift;
                uint64_t gmpCount  = readPtr(base + 0x10);
                uint64_t gmp       = readPtr(base + 0x18);
                uint64_t cgmCount  = readPtr(base + 0x70);
                uint64_t cgm       = readPtr(base + 0x78);

                if (cgmCount == 0 || cgmCount > 2000) continue;
                if (!plausibleData(cgm)) continue;
                if (gmpCount > 500000) continue;
                if (gmpCount > 0 && !plausibleData(gmp)) continue;

                // extra validation: first codeGenModule should point to a valid C string
                uint64_t firstMod = readPtr(cgm);
                std::string name = readCStr(firstMod);
                if (name.size() < 4 || name.find(".dll") == std::string::npos) continue;

                diag_.codeReg = base;
                diag_.codeGenModulesCount = cgmCount;
                diag_.methodPointerCount = gmpCount;
                codeRegCandidates++;
                char b[160];
                snprintf(b, sizeof(b),
                    "  CodeRegistration @ 0x%llx: codeGenModulesCount=%llu, first module=%s",
                    (unsigned long long)base, (unsigned long long)cgmCount, name.c_str());
                log(b);
                break;
            }
            if (diag_.codeReg) break;
        }
        if (diag_.codeReg) break;
    }

    if (!diag_.codeReg) {
        log("  ERROR: CodeRegistration not found");
        return false;
    }

    // Find MetadataRegistration: types count plausible, types points into data
    uint64_t expectedTypes = md.type_def_count();
    // The C# readme target showed 43627 types. Sanity bounds: 1000 - 500000.
    for (auto* sec : dataSections) {
        size_t count = sec->sh_size / 8;
        for (size_t i = 0; i + 18 <= count; i++) {
            uint64_t addr = sec->sh_addr + i * 8;
            int64_t  typesCount = (int64_t)readPtr(addr + 0x30);
            uint64_t types      = readPtr(addr + 0x38);
            int64_t  giCount    = (int64_t)readPtr(addr + 0x18);
            uint64_t gi         = readPtr(addr + 0x20);

            if (typesCount < 1000 || typesCount > 500000) continue;
            if (!plausibleData(types)) continue;
            if (giCount < 0 || giCount > 500000) continue;
            if (giCount > 0 && !plausibleData(gi)) continue;

            // Validate: first Il2CppType should have plausible type_enum
            uint64_t firstTypePtr = readPtr(types);
            if (!plausibleData(firstTypePtr) && !isInRange(firstTypePtr, 16)) continue;

            diag_.metaReg = addr;
            diag_.typeCount = typesCount;
            diag_.genericInstsCount = giCount;
            metaRegCandidates++;
            char b[160];
            snprintf(b, sizeof(b),
                "  MetadataRegistration @ 0x%llx: typesCount=%lld, genericInstsCount=%lld",
                (unsigned long long)addr, (long long)typesCount, (long long)giCount);
            log(b);
            break;
        }
        if (diag_.metaReg) break;
    }

    if (!diag_.metaReg) {
        log("  ERROR: MetadataRegistration not found");
        return false;
    }

    codeRegAddr_ = diag_.codeReg;
    metaRegAddr_ = diag_.metaReg;
    return true;
}

bool Il2CppBinary::parseRegistrations(const Metadata& md, const LogFn& log) {
    if (!codeRegAddr_ || !metaRegAddr_) { log("regs not found"); return false; }

    // ---- MetadataRegistration ----
    metadataRegistrationTypes_          = readPtr(metaRegAddr_ + 0x38);
    metadataRegistrationTypesCount_     = readPtr(metaRegAddr_ + 0x30);
    metadataRegistrationGenericInsts_   = readPtr(metaRegAddr_ + 0x20);
    metadataRegistrationGenericInstsCount_ = readPtr(metaRegAddr_ + 0x18);
    metadataRegistrationMethodSpecs_    = readPtr(metaRegAddr_ + 0x48);
    metadataRegistrationMethodSpecsCount_ = readPtr(metaRegAddr_ + 0x40);

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

    log("  parsing Il2CppGenericInst array...");
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

    log("  parsing Il2CppMethodSpec array...");
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

    // ---- CodeRegistration ----
    uint64_t cgmCount = readPtr(codeRegAddr_ + 0x70);
    uint64_t cgmAddr  = readPtr(codeRegAddr_ + 0x78);
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
