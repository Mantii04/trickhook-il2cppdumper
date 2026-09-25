#pragma once
#include "common.h"
#include "elf_parser.h"
#include <map>
#include <string>
#include <vector>

struct Metadata;

// v31 il2cpp runtime layouts (arm64)
struct Il2CppType {
    uint64_t datapoint;
    uint32_t bits;
    // decoded from bits via Init()
    uint32_t attrs = 0;
    uint8_t  type_enum = 0;  // Il2CppTypeEnum
    uint8_t  num_mods = 0;
    uint8_t  byref = 0;
    uint8_t  pinned = 0;
    uint8_t  valuetype = 0;
    void init() {
        attrs = bits & 0xffff;
        type_enum = (bits >> 16) & 0xff;
        num_mods = (bits >> 24) & 0x1f;
        byref = (bits >> 29) & 1;
        pinned = (bits >> 30) & 1;
        valuetype = bits >> 31;
    }
};

struct Il2CppGenericInst {
    int64_t  type_argc;
    uint64_t type_argv;
};

struct Il2CppGenericClass {
    uint64_t type;      // v27+
    uint64_t class_inst;
    uint64_t method_inst;
    uint64_t cached_class;
};

struct Il2CppMethodSpec {
    int32_t methodDefinitionIndex;
    int32_t classIndexIndex;
    int32_t methodIndexIndex;
};

struct Il2CppCodeGenModule {
    std::string name;
    uint64_t methodPointerCount = 0;
    uint64_t methodPointersAddr = 0;
    std::vector<uint64_t> methodPointers;
};

class Il2CppBinary {
public:
    Il2CppBinary() = default;

    // load from file (memory dump or on-disk .so)
    bool load(const std::string& path, const LogFn& log);

    // after load: search for CodeRegistration + MetadataRegistration
    bool findRegistrations(const Metadata& md, const LogFn& log);
    bool parseRegistrations(const Metadata& md, const LogFn& log);

    // accessors
    const std::vector<Il2CppType>& types() const { return types_; }
    const Il2CppType* typeAt(uint64_t pointer) const;
    const std::vector<Il2CppGenericInst>& genericInsts() const { return genericInsts_; }
    const std::vector<Il2CppMethodSpec>& methodSpecs() const { return methodSpecs_; }
    const std::vector<Il2CppCodeGenModule>& codeGenModules() const { return codeGenModules_; }

    // method address lookup: (imageName, methodToken & 0xFFFFFF) - 1 -> real VA
    uint64_t methodPointer(const std::string& imageName, uint32_t token) const;

    // helpers
    uint64_t readPtr(uint64_t vaddr) const;
    int32_t  readI32(uint64_t vaddr) const;
    uint32_t readU32(uint64_t vaddr) const;
    uint16_t readU16(uint64_t vaddr) const;
    std::string readCStr(uint64_t vaddr) const;

    uint64_t mapVaddrToOffset(uint64_t vaddr) const;
    bool isInRange(uint64_t vaddr, size_t len) const;

    uint64_t imageBase() const { return imageBase_; }
    const std::vector<uint8_t>& data() const { return data_; }

    // diagnostic
    struct Diag {
        uint64_t codeReg = 0;
        uint64_t metaReg = 0;
        uint64_t methodPointerCount = 0;
        uint64_t typeCount = 0;
        uint64_t codeGenModulesCount = 0;
        uint64_t methodSpecsCount = 0;
        uint64_t genericInstsCount = 0;
    };
    const Diag& diag() const { return diag_; }

private:
    std::vector<uint8_t> data_;
    ElfInfo elf_;
    std::vector<ElfSection> sections_;
    uint64_t imageBase_ = 0;
    uint64_t base_ = 0;   // runtime load base (from memory dump)
    Diag diag_;

    uint64_t codeRegAddr_ = 0;
    uint64_t metaRegAddr_ = 0;

    // parsed structures
    std::vector<Il2CppType> types_;
    std::map<uint64_t, size_t> typeByPtr_;
    std::vector<Il2CppGenericInst> genericInsts_;
    std::vector<uint64_t> genericInstPointers_;
    std::vector<Il2CppMethodSpec> methodSpecs_;
    std::vector<Il2CppCodeGenModule> codeGenModules_;
    std::map<std::string, size_t> codeGenModuleByName_;

    // metadata registration fields we need
    uint64_t metadataRegistrationTypes_ = 0;
    uint64_t metadataRegistrationTypesCount_ = 0;
    uint64_t metadataRegistrationGenericInsts_ = 0;
    uint64_t metadataRegistrationGenericInstsCount_ = 0;
    uint64_t metadataRegistrationMethodSpecs_ = 0;
    uint64_t metadataRegistrationMethodSpecsCount_ = 0;
};
