#include "il2cpp_binary.h"
#include "metadata.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <fstream>
#include <algorithm>

// ---- base detection ----

// filename parse fallback: *-<hex>-<hex>.bin
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

// Detect runtime base from .init_array: entries point into .text, Y must be page-aligned
static uint64_t detect_base_from_init_array(const std::vector<uint8_t>& data,
                                            const ElfInfo& elf, const LogFn& log) {
    const ElfSection* initArr = nullptr;
    const ElfSection* text = nullptr;
    for (const auto& s : elf.sections) {
        if (s.name == ".init_array") initArr = &s;
        if (s.name == ".text") text = &s;
    }
    if (!initArr || !text) { log("  no .init_array or .text"); return 0; }
    if (initArr->sh_offset + initArr->sh_size > data.size()) { log("  init_array OOB"); return 0; }
    if (initArr->sh_size < 16) { log("  init_array too small"); return 0; }

    std::vector<uint64_t> entries;
    for (size_t i = 0; i + 8 <= initArr->sh_size; i += 8) {
        size_t off = initArr->sh_offset + i;
        uint64_t v; std::memcpy(&v, data.data() + off, 8);
        if (v > 0x100000000ull && v < 0x800000000000ull) entries.push_back(v);
    }
    if (entries.size() < 2) { log("  too few plausible entries in init_array"); return 0; }
    {
        char b[200];
        snprintf(b, sizeof(b), "  init_array: %zu plausible entries", entries.size());
        log(b);
        for (size_t k = 0; k < std::min<size_t>(5, entries.size()); k++) {
            snprintf(b, sizeof(b), "    e[%zu] = 0x%llx", k, (unsigned long long)entries[k]);
            log(b);
        }
    }

    uint64_t textLo = text->sh_addr;
    uint64_t textHi = text->sh_addr + text->sh_size;
    uint64_t Ymin = 0, Ymax = ~0ull;
    for (uint64_t e : entries) {
        if (e <= textLo) continue;
        uint64_t lo = (e > textHi) ? (e - textHi + 1) : 0;
        uint64_t hi = e - textLo;
        if (lo > Ymin) Ymin = lo;
        if (hi < Ymax) Ymax = hi;
        if (Ymin > Ymax) { log("  inconsistent Y range across entries"); return 0; }
    }
    uint64_t Y = (Ymin + 0xFFF) & ~0xFFFull;
    if (Y > Ymax) { log("  no page-aligned Y"); return 0; }
    if (Y < 0x100000000ull || Y > 0x800000000000ull) { log("  Y out of range"); return 0; }
    {
        char b[200];
        snprintf(b, sizeof(b), "  base candidate: Ymin=0x%llx Ymax=0x%llx -> Y=0x%llx",
                 (unsigned long long)Ymin, (unsigned long long)Ymax, (unsigned long long)Y);
        log(b);
    }
    return Y;
}

// ---- load ----

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

    // 1. try filename parse
    base_ = parse_base_from_path(path);
    if (base_ != 0) log("  base from filename");

    // 2. fall back to init_array detection
    if (base_ == 0) {
        base_ = detect_base_from_init_array(data_, elf_, log);
        if (base_ != 0) log("  base from init_array");
    }

    if (base_ == 0) {
        log("  ERROR: cannot determine runtime base");
        return false;
    }
    {
        char b[64];
        snprintf(b, sizeof(b), "  runtime base = 0x%llx", (unsigned long long)base_);
        log(b);
    }
    imageBase_ = base_;
    return true;
}

// ---- reads: norm offset == file offset ----

uint64_t Il2CppBinary::readQwordAt(size_t normOffset) const {
    if (normOffset + 8 > data_.size()) return 0;
    uint64_t v; std::memcpy(&v, data_.data() + normOffset, 8); return v;
}

int32_t Il2CppBinary::readI32At(size_t normOffset) const {
    if (normOffset + 4 > data_.size()) return 0;
    int32_t v; std::memcpy(&v, data_.data() + normOffset, 4); return v;
}

uint16_t Il2CppBinary::readU16At(size_t normOffset) const {
    if (normOffset + 2 > data_.size()) return 0;
    uint16_t v; std::memcpy(&v, data_.data() + normOffset, 2); return v;
}

std::string Il2CppBinary::readCStrAt(size_t normOffset) const {
    if (normOffset >= data_.size()) return "";
    const char* p = (const char*)(data_.data() + normOffset);
    size_t max = data_.size() - normOffset;
    return std::string(p, strnlen(p, max));
}

uint64_t Il2CppBinary::readPtr(uint64_t runtimeAddr) const {
    size_t off = runtimeToOffset(runtimeAddr);
    if (off == SIZE_MAX) return 0;
    return readQwordAt(off);
}

uint32_t Il2CppBinary::readU32(uint64_t runtimeAddr) const {
    size_t off = runtimeToOffset(runtimeAddr);
    if (off == SIZE_MAX) return 0;
    return (uint32_t)readQwordAt(off);
}

uint16_t Il2CppBinary::readU16(uint64_t runtimeAddr) const {
    size_t off = runtimeToOffset(runtimeAddr);
    if (off == SIZE_MAX) return 0;
    return readU16At(off);
}

int32_t Il2CppBinary::readI32(uint64_t runtimeAddr) const {
    size_t off = runtimeToOffset(runtimeAddr);
    if (off == SIZE_MAX) return 0;
    return readI32At(off);
}

std::string Il2CppBinary::readCStr(uint64_t runtimeAddr) const {
    size_t off = runtimeToOffset(runtimeAddr);
    if (off == SIZE_MAX) return "";
    return readCStrAt(off);
}

size_t Il2CppBinary::runtimeToOffset(uint64_t runtimeAddr) const {
    if (runtimeAddr < base_) return SIZE_MAX;
    uint64_t off = runtimeAddr - base_;
    if (off >= data_.size()) return SIZE_MAX;
    return (size_t)off;
}

// ---- section search helpers ----

size_t Il2CppBinary::findStringInSection(const std::string& sectionName, const std::string& needle) const {
    for (const auto& s : elf_.sections) {
        if (s.name != sectionName) continue;
        if (s.sh_offset + s.sh_size > data_.size()) continue;
        const uint8_t* b = data_.data() + s.sh_offset;
        size_t nlen = needle.size();
        for (size_t i = 0; i + nlen < s.sh_size; i++) {
            if (std::memcmp(b + i, needle.data(), nlen) != 0) continue;
            bool leftOk  = (i == 0) || (b[i - 1] == 0);
            bool rightOk = (b[i + nlen] == 0);
            if (leftOk && rightOk) return s.sh_offset + i;
        }
    }
    return SIZE_MAX;
}

size_t Il2CppBinary::findQwordInSections(const std::vector<std::string>& names, uint64_t target) const {
    for (const auto& s : elf_.sections) {
        bool ok = false;
        for (const auto& n : names) if (s.name == n) { ok = true; break; }
        if (!ok) continue;
        if (s.sh_offset + s.sh_size > data_.size()) continue;
        size_t lo = (s.sh_offset + 7) & ~7ull;
        for (size_t i = lo; i + 8 <= s.sh_offset + s.sh_size; i += 8) {
            uint64_t v; std::memcpy(&v, data_.data() + i, 8);
            if (v == target) return i;
        }
    }
    return SIZE_MAX;
}

// ---- chain ----

bool Il2CppBinary::findRegistrations(const Metadata& md, const LogFn& log) {
    (void)md;
    std::vector<std::string> dataSecs = {".data", ".data.rel.ro", ".got", ".got.plt", ".bss"};
    char b[256];

    // 1. find anchor string norm offset
    size_t anchorNorm = findStringInSection(".rodata", "Assembly-CSharp.dll");
    if (anchorNorm == SIZE_MAX) {
        for (const auto& s : elf_.sections) {
            anchorNorm = findStringInSection(s.name, "Assembly-CSharp.dll");
            if (anchorNorm != SIZE_MAX) break;
        }
    }
    if (anchorNorm == SIZE_MAX) { log("  ERROR: anchor string not found"); return false; }
    uint64_t anchorRuntime = base_ + anchorNorm;
    snprintf(b, sizeof(b), "  anchor norm=0x%zx runtime=0x%llx",
             anchorNorm, (unsigned long long)anchorRuntime);
    log(b);

    // 2. find pointer to anchor -> location is CodeGenModule (moduleName at offset 0)
    size_t modNorm = findQwordInSections(dataSecs, anchorRuntime);
    if (modNorm == SIZE_MAX) { log("  ERROR: no pointer to anchor in data sections"); return false; }
    uint64_t modRuntime = base_ + modNorm;
    snprintf(b, sizeof(b), "  CodeGenModule norm=0x%zx runtime=0x%llx",
             modNorm, (unsigned long long)modRuntime);
    log(b);

    // 3. read methodPointerCount at +0x08 and methodPointers runtime at +0x10
    uint64_t mpc = readQwordAt(modNorm + 0x08);
    uint64_t mppRuntime = readQwordAt(modNorm + 0x10);
    snprintf(b, sizeof(b), "    methodPointerCount=%llu methodPointers=0x%llx",
             (unsigned long long)mpc, (unsigned long long)mppRuntime);
    log(b);
    if (mpc == 0 || mpc > 1000000) { log("  ERROR: bad methodPointerCount"); return false; }

    // 4. find pointer to CodeGenModule -> array entry
    size_t entryNorm = findQwordInSections(dataSecs, modRuntime);
    if (entryNorm == SIZE_MAX) { log("  ERROR: no pointer to CodeGenModule"); return false; }
    snprintf(b, sizeof(b), "  array entry norm=0x%zx runtime=0x%llx",
             entryNorm, (unsigned long long)(base_ + entryNorm));
    log(b);

    // 5. walk back to find array start
    size_t arrStart = entryNorm;
    for (int back = 0; back < 1000; back++) {
        if (arrStart < 8) break;
        uint64_t v = readQwordAt(arrStart - 8);
        if (v == 0 || v < base_) break;
        size_t target = runtimeToOffset(v);
        if (target == SIZE_MAX) break;
        // must be inside some loaded section
        bool ok = false;
        for (const auto& s : elf_.sections) {
            if (target >= s.sh_offset && target < s.sh_offset + s.sh_size) { ok = true; break; }
        }
        if (!ok) break;
        arrStart -= 8;
    }
    uint64_t arrStartRuntime = base_ + arrStart;
    snprintf(b, sizeof(b), "  array start norm=0x%zx runtime=0x%llx",
             arrStart, (unsigned long long)arrStartRuntime);
    log(b);

    // 6. find pointer to array start -> that's codeGenModules field of CodeRegistration
    size_t cgmFieldNorm = findQwordInSections(dataSecs, arrStartRuntime);
    if (cgmFieldNorm == SIZE_MAX) { log("  ERROR: no pointer to array start"); return false; }

    // v31: codeGenModules is at +0x80
    size_t codeRegNorm = cgmFieldNorm - 0x80;
    snprintf(b, sizeof(b), "  cgmField norm=0x%zx -> CodeRegistration norm=0x%zx",
             cgmFieldNorm, codeRegNorm);
    log(b);

    codeRegAddr_ = base_ + codeRegNorm;
    diag_.codeReg = codeRegAddr_;
    diag_.codeGenModulesCount = readQwordAt(codeRegNorm + 0x78);
    snprintf(b, sizeof(b), "  CodeRegistration @ runtime 0x%llx: codeGenModulesCount=%llu",
             (unsigned long long)codeRegAddr_, (unsigned long long)diag_.codeGenModulesCount);
    log(b);

    // ---- MetadataRegistration ----
    uint64_t expectedTypes = 43956;
    uint64_t bestDelta = ~0ull;
    size_t metaRegNorm = SIZE_MAX;
    for (const auto& s : elf_.sections) {
        if (s.name != ".data.rel.ro" && s.name != ".data") continue;
        if (s.sh_offset + s.sh_size > data_.size()) continue;
        size_t i = (s.sh_offset + 7) & ~7ull;
        for (; i + 0x60 <= s.sh_offset + s.sh_size; i += 8) {
            uint64_t typesCount = readQwordAt(i + 0x30);
            uint64_t typesPtr   = readQwordAt(i + 0x38);
            if (typesCount < 1000 || typesCount > 500000) continue;
            size_t nv = runtimeToOffset(typesPtr);
            if (nv == SIZE_MAX) continue;
            bool ok = false;
            for (const auto& ss : elf_.sections) {
                if (nv >= ss.sh_offset && nv < ss.sh_offset + ss.sh_size) { ok = true; break; }
            }
            if (!ok) continue;
            uint64_t delta = typesCount > expectedTypes ? typesCount - expectedTypes : expectedTypes - typesCount;
            if (delta < bestDelta) { bestDelta = delta; metaRegNorm = i; }
        }
    }
    if (metaRegNorm == SIZE_MAX) { log("  ERROR: MetadataRegistration not found"); return false; }

    metaRegAddr_ = base_ + metaRegNorm;
    diag_.metaReg = metaRegAddr_;
    diag_.typeCount = readQwordAt(metaRegNorm + 0x30);
    diag_.genericInstsCount = readQwordAt(metaRegNorm + 0x10);
    snprintf(b, sizeof(b),
        "  MetadataRegistration @ runtime 0x%llx: typesCount=%llu genericInstsCount=%llu",
        (unsigned long long)metaRegAddr_,
        (unsigned long long)diag_.typeCount,
        (unsigned long long)diag_.genericInstsCount);
    log(b);
    return true;
}

bool Il2CppBinary::parseRegistrations(const Metadata& md, const LogFn& log) {
    (void)md;
    if (!codeRegAddr_ || !metaRegAddr_) { log("regs not found"); return false; }

    size_t mReg = runtimeToOffset(metaRegAddr_);
    size_t cReg = runtimeToOffset(codeRegAddr_);

    metadataRegistrationGenericInstsCount_ = readQwordAt(mReg + 0x10);
    metadataRegistrationGenericInsts_      = readQwordAt(mReg + 0x18);
    metadataRegistrationTypesCount_        = readQwordAt(mReg + 0x30);
    metadataRegistrationTypes_             = readQwordAt(mReg + 0x38);
    metadataRegistrationMethodSpecsCount_  = readQwordAt(mReg + 0x40);
    metadataRegistrationMethodSpecs_       = readQwordAt(mReg + 0x48);

    // types array: mRTypes_ is runtime pointer to array of runtime pointers to Il2CppType structs
    size_t typesArrOff = runtimeToOffset(metadataRegistrationTypes_);
    log("  parsing Il2CppType array (" + std::to_string(metadataRegistrationTypesCount_) + " types)...");
    types_.reserve((size_t)metadataRegistrationTypesCount_);
    for (uint64_t i = 0; i < metadataRegistrationTypesCount_; i++) {
        uint64_t ptr = readQwordAt(typesArrOff + i * 8);
        size_t tOff = runtimeToOffset(ptr);
        if (tOff == SIZE_MAX) { types_.push_back({}); continue; }
        Il2CppType t;
        t.datapoint = readQwordAt(tOff);
        t.bits = (uint32_t)readQwordAt(tOff + 8);  // bits is uint32 but stored in 8-byte slot in struct (data ptr + bits)
        t.init();
        types_.push_back(t);
        typeByPtr_[ptr] = i;
    }
    log("  " + std::to_string(types_.size()) + " types parsed");

    size_t giArrOff = runtimeToOffset(metadataRegistrationGenericInsts_);
    genericInstPointers_.reserve((size_t)metadataRegistrationGenericInstsCount_);
    genericInsts_.reserve((size_t)metadataRegistrationGenericInstsCount_);
    for (uint64_t i = 0; i < metadataRegistrationGenericInstsCount_; i++) {
        uint64_t ptr = readQwordAt(giArrOff + i * 8);
        genericInstPointers_.push_back(ptr);
        size_t gOff = runtimeToOffset(ptr);
        Il2CppGenericInst gi{};
        if (gOff != SIZE_MAX) {
            gi.type_argc = (int64_t)readQwordAt(gOff);
            gi.type_argv = readQwordAt(gOff + 8);
        }
        genericInsts_.push_back(gi);
    }
    log("  " + std::to_string(genericInsts_.size()) + " genericInsts");

    size_t msArrOff = runtimeToOffset(metadataRegistrationMethodSpecs_);
    methodSpecs_.reserve((size_t)metadataRegistrationMethodSpecsCount_);
    for (uint64_t i = 0; i < metadataRegistrationMethodSpecsCount_; i++) {
        size_t b = msArrOff + i * 12;
        Il2CppMethodSpec ms;
        ms.methodDefinitionIndex = readI32At(b + 0);
        ms.classIndexIndex       = readI32At(b + 4);
        ms.methodIndexIndex      = readI32At(b + 8);
        methodSpecs_.push_back(ms);
    }
    log("  " + std::to_string(methodSpecs_.size()) + " methodSpecs");

    // codeGenModules array
    uint64_t cgmCount = readQwordAt(cReg + 0x78);
    uint64_t cgmArrRuntime = readQwordAt(cReg + 0x80);
    size_t cgmArrOff = runtimeToOffset(cgmArrRuntime);
    diag_.codeGenModulesCount = cgmCount;

    log("  parsing " + std::to_string(cgmCount) + " codeGenModules...");
    codeGenModules_.reserve((size_t)cgmCount);
    for (uint64_t i = 0; i < cgmCount; i++) {
        uint64_t modRuntime = readQwordAt(cgmArrOff + i * 8);
        size_t modOff = runtimeToOffset(modRuntime);
        if (modOff == SIZE_MAX) continue;
        Il2CppCodeGenModule m;
        uint64_t namePtr = readQwordAt(modOff);
        size_t nameOff = runtimeToOffset(namePtr);
        if (nameOff != SIZE_MAX) m.name = readCStrAt(nameOff);
        m.methodPointerCount = readQwordAt(modOff + 8);
        m.methodPointersAddr = readQwordAt(modOff + 16);
        if (m.methodPointerCount > 0 && m.methodPointerCount < 1000000) {
            size_t mpOff = runtimeToOffset(m.methodPointersAddr);
            if (mpOff != SIZE_MAX) {
                m.methodPointers.reserve((size_t)m.methodPointerCount);
                for (uint64_t j = 0; j < m.methodPointerCount; j++) {
                    m.methodPointers.push_back(readQwordAt(mpOff + j * 8));
                }
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
