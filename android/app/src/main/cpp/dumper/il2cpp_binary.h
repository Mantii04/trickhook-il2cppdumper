#pragma once
#include "common.h"
#include "elf_parser.h"
#include <map>
#include <string>
#include <vector>

struct Metadata;

struct Il2CppType {
    uint64_t datapoint;
    uint32_t bits;
    uint32_t attrs = 0;
    uint8_t  type_enum = 0;
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

    bool load(const std::string& path, const LogFn& log);
    bool findRegistrations(const Metadata& md, const LogFn& log);
    bool parseRegistrations(const Metadata& md, const LogFn& log);

    const std::vector<Il2CppType>& types() const { return types_; }
    const Il2CppType* typeAt(uint64_t pointer) const;
    const std::vector<Il2CppGenericInst>& genericInsts() const { return genericInsts_; }
    const std::vector<Il2CppMethodSpec>& methodSpecs() const { return methodSpecs_; }
    const std::vector<Il2CppCodeGenModule>& codeGenModules() const { return codeGenModules_; }

    uint64_t methodPointer(const std::string& imageName, uint32_t token) const;

    uint64_t readQwordAt(size_t normOffset) const;
    int32_t  readI32At(size_t normOffset) const;
    uint16_t readU16At(size_t normOffset) const;
    std::string readCStrAt(size_t normOffset) const;
    size_t runtimeToOffset(uint64_t runtimeAddr) const;

    size_t findStringInSection(const std::string& sectionName, const std::string& needle) const;
    size_t findQwordInSections(const std::vector<std::string>& names, uint64_t target) const;

    uint64_t imageBase() const { return imageBase_; }
    const std::vector<uint8_t>& data() const { return data_; }

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
    uint64_t imageBase_ = 0;
    uint64_t base_ = 0;
    Diag diag_;

    uint64_t codeRegAddr_ = 0;
    uint64_t metaRegAddr_ = 0;

    std::vector<Il2CppType> types_;
    std::map<uint64_t, size_t> typeByPtr_;
    std::vector<Il2CppGenericInst> genericInsts_;
    std::vector<uint64_t> genericInstPointers_;
    std::vector<Il2CppMethodSpec> methodSpecs_;
    std::vector<Il2CppCodeGenModule> codeGenModules_;
    std::map<std::string, size_t> codeGenModuleByName_;

    uint64_t metadataRegistrationTypes_ = 0;
    uint64_t metadataRegistrationTypesCount_ = 0;
    uint64_t metadataRegistrationGenericInsts_ = 0;
    uint64_t metadataRegistrationGenericInstsCount_ = 0;
    uint64_t metadataRegistrationMethodSpecs_ = 0;
    uint64_t metadataRegistrationMethodSpecsCount_ = 0;
};
