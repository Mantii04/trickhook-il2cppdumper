#include "il2cpp_binary.h"
#include "metadata.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <fstream>
#include <algorithm>
#include <vector>

// ---- helpers ----

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

    base_ = parse_base_from_path(path);
    if (base_ != 0) {
        char b[64]; snprintf(b, sizeof(b), "  base from filename: 0x%llx", (unsigned long long)base_);
        log(b);
    }
    if (base_ == 0) {
        base_ = autoDetectY(log);
        if (base_ != 0) {
            char b[64]; snprintf(b, sizeof(b), "  base auto-detected: 0x%llx", (unsigned long long)base_);
            log(b);
        }
    }
    if (base_ == 0) {
        log("  ERROR: cannot determine runtime base");
        return false;
    }
    imageBase_ = base_;
    return true;
}

// ---- raw file access ----

uint64_t Il2CppBinary::readQwordAt(size_t off) const {
    if (off + 8 > data_.size()) return 0;
    uint64_t v; std::memcpy(&v, data_.data() + off, 8); return v;
}
int32_t Il2CppBinary::readI32At(size_t off) const {
    if (off + 4 > data_.size()) return 0;
    int32_t v; std::memcpy(&v, data_.data() + off, 4); return v;
}
uint16_t Il2CppBinary::readU16At(size_t off) const {
    if (off + 2 > data_.size()) return 0;
    uint16_t v; std::memcpy(&v, data_.data() + off, 2); return v;
}
std::string Il2CppBinary::readCStrAt(size_t off) const {
    if (off >= data_.size()) return "";
    const char* p = (const char*)(data_.data() + off);
    size_t max = data_.size() - off;
    return std::string(p, strnlen(p, max));
}

size_t Il2CppBinary::runtimeToOffset(uint64_t rt) const {
    if (rt < base_) return SIZE_MAX;
    uint64_t off = rt - base_;
    if (off >= data_.size()) return SIZE_MAX;
    return (size_t)off;
}

uint64_t Il2CppBinary::readPtr(uint64_t rt) const {
    size_t o = runtimeToOffset(rt); if (o == SIZE_MAX) return 0;
    return readQwordAt(o);
}
uint32_t Il2CppBinary::readU32(uint64_t rt) const {
    size_t o = runtimeToOffset(rt); if (o == SIZE_MAX) return 0;
    return (uint32_t)readQwordAt(o);
}
uint16_t Il2CppBinary::readU16(uint64_t rt) const {
    size_t o = runtimeToOffset(rt); if (o == SIZE_MAX) return 0;
    return readU16At(o);
}
int32_t Il2CppBinary::readI32(uint64_t rt) const {
    size_t o = runtimeToOffset(rt); if (o == SIZE_MAX) return 0;
    return readI32At(o);
}
std::string Il2CppBinary::readCStr(uint64_t rt) const {
    size_t o = runtimeToOffset(rt); if (o == SIZE_MAX) return "";
    return readCStrAt(o);
}

// ---- section search ----

size_t Il2CppBinary::findStringInSection(const std::string& sname, const std::string& needle) const {
    for (const auto& s : elf_.sections) {
        if (s.name != sname) continue;
        if (s.sh_offset + s.sh_size > data_.size()) continue;
        const uint8_t* b = data_.data() + s.sh_offset;
        size_t nlen = needle.size();
        for (size_t i = 0; i + nlen < s.sh_size; i++) {
            if (std::memcmp(b + i, needle.data(), nlen) != 0) continue;
            bool lok = (i == 0) || (b[i-1] == 0);
            bool rok = (b[i + nlen] == 0);
            if (lok && rok) return s.sh_offset + i;
        }
    }
    return SIZE_MAX;
}

size_t Il2CppBinary::findQwordInSections(const std::vector<std::string>& names, uint64_t target) const {
    for (const auto& s : elf_.sections) {
        bool ok = false;
        for (auto& n : names) if (s.name == n) { ok = true; break; }
        if (!ok) continue;
        if (s.sh_offset + s.sh_size > data_.size()) continue;
        size_t i = (s.sh_offset + 7) & ~7ull;
        for (; i + 8 <= s.sh_offset + s.sh_size; i += 8) {
            uint64_t v; std::memcpy(&v, data_.data() + i, 8);
            if (v == target) return i;
        }
    }
    return SIZE_MAX;
}

// ---- Y auto-detection ----
// Strategy: find a "runtime MetadataRegistration" pattern in the whole file:
//   7 consecutive pairs of (count, runtime_ptr) where counts are small
//   and pointers are >= 0x7000000000. Then derive Y from the pointer array.

struct MrPattern {
    size_t fileOff;
    uint64_t gcCount, gcPtr;
    uint64_t giCount, giPtr;
    uint64_t mtCount, mtPtr;
    uint64_t tCount,  tPtr;
    uint64_t msCount, msPtr;
    uint64_t foCount, foPtr;
    uint64_t tdsCount, tdsPtr;
};

static bool match_mr_at(const std::vector<uint8_t>& data, size_t off, MrPattern& out) {
    if (off + 0x70 > data.size()) return false;
    auto rq = [&](size_t o) { uint64_t v; std::memcpy(&v, data.data() + o, 8); return v; };
    uint64_t p[7], c[7];
    c[0] = rq(off + 0x00); p[0] = rq(off + 0x08);
    c[1] = rq(off + 0x10); p[1] = rq(off + 0x18);
    c[2] = rq(off + 0x20); p[2] = rq(off + 0x28);
    c[3] = rq(off + 0x30); p[3] = rq(off + 0x38);
    c[4] = rq(off + 0x40); p[4] = rq(off + 0x48);
    c[5] = rq(off + 0x50); p[5] = rq(off + 0x58);
    c[6] = rq(off + 0x60); p[6] = rq(off + 0x68);
    // counts must all be in plausible range
    for (int i = 0; i < 7; i++) if (c[i] < 1000 || c[i] > 500000) return false;
    // pointers must all share the top byte (same 2^56 region, e.g. all 0x75...)
    uint64_t top = p[0] >> 56;
    if (top < 0x60 || top > 0x7F) return false;
    for (int i = 1; i < 7; i++) if ((p[i] >> 56) != top) return false;
    // typesCount must be the largest count (largest type table in il2cpp)
    for (int i = 0; i < 7; i++) if (i != 3 && c[i] > c[3]) return false;
    if (c[3] < 10000 || c[3] > 500000) return false;
    out.fileOff = off;
    out.gcCount = c[0]; out.gcPtr = p[0];
    out.giCount = c[1]; out.giPtr = p[1];
    out.mtCount = c[2]; out.mtPtr = p[2];
    out.tCount  = c[3]; out.tPtr  = p[3];
    out.msCount = c[4]; out.msPtr = p[4];
    out.foCount = c[5]; out.foPtr = p[5];
    out.tdsCount= c[6]; out.tdsPtr= p[6];
    return true;
}

uint64_t Il2CppBinary::autoDetectY(const LogFn& log) {
    // scan whole file for MR patterns (aligned to 8)
    std::vector<MrPattern> cands;
    size_t i = 0;
    while (i + 0x70 <= data_.size()) {
        MrPattern p{};
        if (match_mr_at(data_, i, p)) {
            cands.push_back(p);
            i += 8;  // keep scanning, might be multiple
        } else {
            i += 8;
        }
    }
    if (cands.empty()) {
        log("  autoDetectY: no runtime MR pattern found");
        return 0;
    }
    {
        char b[128]; snprintf(b, sizeof(b), "  autoDetectY: found %zu MR candidates", cands.size());
        log(b);
    }

    uint64_t file_size = data_.size();
    for (size_t k = 0; k < cands.size(); k++) {
        auto& mr = cands[k];
        uint64_t allP[] = { mr.gcPtr, mr.giPtr, mr.mtPtr, mr.tPtr, mr.msPtr, mr.foPtr, mr.tdsPtr };
        uint64_t mn = allP[0], mx = allP[0];
        for (auto v : allP) { if (v < mn) mn = v; if (v > mx) mx = v; }
        if (mx - mn >= file_size) continue;

        uint64_t lo = (mx >= file_size) ? (mx - file_size) : 0;
        lo = (lo + 0xFFFull) & ~0xFFFull;
        uint64_t hi = mn & ~0xFFFull;
        if (lo > hi) continue;

        // sample Y candidates: first try hi (max Y = min pointer), then midpoints
        uint64_t range = hi - lo;
        uint64_t step = range / 64;
        if (step < 0x1000) step = 0x1000;

        int tried = 0;
        for (uint64_t Y = lo; Y <= hi && tried < 128; Y += step, tried++) {
            if (mr.tPtr < Y) continue;
            size_t toff = (size_t)(mr.tPtr - Y);
            if (toff + 0x20 > file_size) continue;
            uint64_t q0 = readQwordAt(toff);
            uint64_t q1 = readQwordAt(toff + 8);
            if (q0 < Y || q0 >= Y + file_size) continue;
            if (q1 < Y || q1 >= Y + file_size) continue;
            if (q1 - q0 != 0x10) continue;
            size_t t0off = (size_t)(q0 - Y);
            if (t0off + 16 > file_size) continue;
            uint32_t bits = (uint32_t)readQwordAt(t0off + 8);
            uint8_t te = (bits >> 16) & 0xFF;
            bool okEnum = (te <= 0x22) || (te == 0x55) || (te == 0xFF);
            if (!okEnum) continue;
            // extra: second type must also be valid
            uint64_t q2 = readQwordAt(toff + 0x10);
            if (q2 < Y || q2 >= Y + file_size) continue;
            if (q2 - q1 != 0x10) continue;
            metaRegFileOff_ = mr.fileOff;
            {
                char b[200]; snprintf(b, sizeof(b),
                    "  autoDetectY: hit at candidate %zu, Y=0x%llx, MR file=0x%zx",
                    k, (unsigned long long)Y, mr.fileOff);
                log(b);
            }
            return Y;
        }
    }
    log("  autoDetectY: no Y satisfied validation");
    return 0;
}

// ---- registration chain ----

bool Il2CppBinary::findRegistrations(const Metadata& md, const LogFn& log) {
    (void)md;
    char b[256];

    if (metaRegFileOff_ == 0) {
        log("  ERROR: no MR location recorded by autoDetectY");
        return false;
    }

    // read the MR fields at that file offset
    uint64_t gcCount = readQwordAt(metaRegFileOff_ + 0x00);
    uint64_t giCount = readQwordAt(metaRegFileOff_ + 0x10);
    uint64_t mtCount = readQwordAt(metaRegFileOff_ + 0x20);
    uint64_t tCount  = readQwordAt(metaRegFileOff_ + 0x30);
    uint64_t msCount = readQwordAt(metaRegFileOff_ + 0x40);

    metaRegAddr_ = base_ + metaRegFileOff_;
    diag_.metaReg = metaRegAddr_;
    diag_.typeCount = tCount;
    diag_.genericInstsCount = giCount;
    diag_.methodSpecsCount = msCount;

    snprintf(b, sizeof(b),
        "  MetadataRegistration @ file 0x%zx (runtime 0x%llx): typesCount=%llu genericInstsCount=%llu methodSpecsCount=%llu",
        metaRegFileOff_, (unsigned long long)metaRegAddr_,
        (unsigned long long)tCount,
        (unsigned long long)giCount,
        (unsigned long long)msCount);
    log(b);
    (void)gcCount; (void)mtCount;

    log("  CodeRegistration: not located (method addresses will be omitted)");
    return true;
}

bool Il2CppBinary::parseRegistrations(const Metadata& md, const LogFn& log) {
    (void)md;
    if (!metaRegAddr_) { log("MR missing"); return false; }

    size_t mReg = runtimeToOffset(metaRegAddr_);
    if (mReg == SIZE_MAX) { log("MR out of range"); return false; }

    metadataRegistrationGenericInstsCount_ = readQwordAt(mReg + 0x10);
    metadataRegistrationGenericInsts_      = readQwordAt(mReg + 0x18);
    metadataRegistrationTypesCount_        = readQwordAt(mReg + 0x30);
    metadataRegistrationTypes_             = readQwordAt(mReg + 0x38);
    metadataRegistrationMethodSpecsCount_  = readQwordAt(mReg + 0x40);
    metadataRegistrationMethodSpecs_       = readQwordAt(mReg + 0x48);

    // types array
    size_t typesArrOff = runtimeToOffset(metadataRegistrationTypes_);
    if (typesArrOff == SIZE_MAX) { log("types ptr invalid"); return false; }

    log("  parsing Il2CppType array (" + std::to_string(metadataRegistrationTypesCount_) + " types)...");
    types_.reserve((size_t)metadataRegistrationTypesCount_);
    for (uint64_t i = 0; i < metadataRegistrationTypesCount_; i++) {
        uint64_t ptr = readQwordAt(typesArrOff + i * 8);
        size_t tOff = runtimeToOffset(ptr);
        if (tOff == SIZE_MAX) { types_.push_back({}); continue; }
        Il2CppType t;
        t.datapoint = readQwordAt(tOff);
        t.bits = (uint32_t)readQwordAt(tOff + 8);
        t.init();
        types_.push_back(t);
        typeByPtr_[ptr] = i;
    }
    log("  " + std::to_string(types_.size()) + " types parsed");

    // genericInsts
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

    // methodSpecs
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
    return true;
}

const Il2CppType* Il2CppBinary::typeAt(uint64_t pointer) const {
    auto it = typeByPtr_.find(pointer);
    if (it == typeByPtr_.end()) return nullptr;
    return &types_[it->second];
}

uint64_t Il2CppBinary::methodPointer(const std::string&, uint32_t) const {
    return 0;  // codeGenModules not located
}
