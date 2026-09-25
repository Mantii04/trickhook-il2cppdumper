#pragma once
#include "common.h"
#include "il2cpp_binary.h"

struct Metadata;
struct Il2CppTypeDefinition;

class TypeResolver {
public:
    TypeResolver(const Metadata& md, const Il2CppBinary& bin)
        : md_(md), bin_(bin) {}

    // Il2CppType -> readable name. addNamespace toggles "System.String" vs "String".
    // is_nested skips the generic-inst part for nested types.
    std::string typeName(const Il2CppType& t, bool addNamespace, bool isNested) const;

    // TypeDefinition -> readable name for class declarations.
    std::string typeDefName(const Il2CppTypeDefinition& td, bool addNamespace, bool genericParameter) const;

    // Generic <T, U> suffix from a Il2CppGenericContainer index.
    std::string genericContainerParams(int32_t containerIdx) const;

    // Resolve Il2CppType to a TypeDefinition (for CLASS / VALUETYPE / GENERICINST)
    const Il2CppTypeDefinition* typeDefFromType(const Il2CppType& t) const;

private:
    const Metadata& md_;
    const Il2CppBinary& bin_;
};
