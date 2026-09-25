#pragma once
#include "common.h"

struct MetadataHeader {
    uint32_t sanity = 0;
    int32_t version = 0;
    int32_t stringLiteralOffset = 0;
    int32_t stringLiteralSize = 0;
    int32_t stringLiteralDataOffset = 0;
    int32_t stringLiteralDataSize = 0;
    int32_t stringOffset = 0;
    int32_t stringSize = 0;
    int32_t eventsOffset = 0;
    int32_t eventsSize = 0;
    int32_t propertiesOffset = 0;
    int32_t propertiesSize = 0;
    int32_t methodsOffset = 0;
    int32_t methodsSize = 0;
    int32_t parameterDefaultValuesOffset = 0;
    int32_t parameterDefaultValuesSize = 0;
    int32_t fieldDefaultValuesOffset = 0;
    int32_t fieldDefaultValuesSize = 0;
    int32_t fieldAndParameterDefaultValueDataOffset = 0;
    int32_t fieldAndParameterDefaultValueDataSize = 0;
    int32_t fieldMarshaledSizesOffset = 0;
    int32_t fieldMarshaledSizesSize = 0;
    int32_t parametersOffset = 0;
    int32_t parametersSize = 0;
    int32_t fieldsOffset = 0;
    int32_t fieldsSize = 0;
    int32_t genericParametersOffset = 0;
    int32_t genericParametersSize = 0;
    int32_t genericParameterConstraintsOffset = 0;
    int32_t genericParameterConstraintsSize = 0;
    int32_t genericContainersOffset = 0;
    int32_t genericContainersSize = 0;
    int32_t nestedTypesOffset = 0;
    int32_t nestedTypesSize = 0;
    int32_t interfacesOffset = 0;
    int32_t interfacesSize = 0;
    int32_t vtableMethodsOffset = 0;
    int32_t vtableMethodsSize = 0;
    int32_t interfaceOffsetsOffset = 0;
    int32_t interfaceOffsetsSize = 0;
    int32_t typeDefinitionsOffset = 0;
    int32_t typeDefinitionsSize = 0;
    int32_t imagesOffset = 0;
    int32_t imagesSize = 0;
    int32_t assembliesOffset = 0;
    int32_t assembliesSize = 0;
    int32_t fieldRefsOffset = 0;
    int32_t fieldRefsSize = 0;
    int32_t referencedAssembliesOffset = 0;
    int32_t referencedAssembliesSize = 0;
    int32_t attributeDataOffset = 0;
    int32_t attributeDataSize = 0;
    int32_t attributeDataRangeOffset = 0;
    int32_t attributeDataRangeSize = 0;
    int32_t unresolvedVirtualCallParameterTypesOffset = 0;
    int32_t unresolvedVirtualCallParameterTypesSize = 0;
    int32_t unresolvedVirtualCallParameterRangesOffset = 0;
    int32_t unresolvedVirtualCallParameterRangesSize = 0;
    int32_t windowsRuntimeTypeNamesOffset = 0;
    int32_t windowsRuntimeTypeNamesSize = 0;
    int32_t windowsRuntimeStringsOffset = 0;
    int32_t windowsRuntimeStringsSize = 0;
    int32_t exportedTypeDefinitionsOffset = 0;
    int32_t exportedTypeDefinitionsSize = 0;
};

// Il2CppTypeDefinition v31 layout (88 bytes)
struct Il2CppTypeDefinition {
    uint32_t nameIndex;
    uint32_t namespaceIndex;
    int32_t byvalTypeIndex;
    int32_t declaringTypeIndex;
    int32_t parentIndex;
    int32_t elementTypeIndex;
    int32_t genericContainerIndex;
    uint32_t flags;
    int32_t fieldStart;
    int32_t methodStart;
    int32_t eventStart;
    int32_t propertyStart;
    int32_t nestedTypesStart;
    int32_t interfacesStart;
    int32_t vtableStart;
    int32_t interfaceOffsetsStart;
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint32_t bitfield;
    uint32_t token;
    bool isValueType() const { return (bitfield & 1) == 1; }
    bool isEnum() const { return ((bitfield >> 1) & 1) == 1; }
};

// Il2CppMethodDefinition v31 (36 standard, 40 on FF with padding at +24)
struct Il2CppMethodDefinition {
    uint32_t nameIndex;
    int32_t declaringType;
    int32_t returnType;
    int32_t returnParameterToken;
    int32_t parameterStart;
    int32_t genericContainerIndex;
    // FF: int32 pad at +24
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint16_t parameterCount;
};

// Il2CppParameterDefinition v31 (12 bytes)
struct Il2CppParameterDefinition {
    uint32_t nameIndex;
    uint32_t token;
    int32_t typeIndex;
};

// Il2CppFieldDefinition v31 (12 bytes)
struct Il2CppFieldDefinition {
    uint32_t nameIndex;
    int32_t typeIndex;
    uint32_t token;
};

// Il2CppPropertyDefinition v31 (20 bytes)
struct Il2CppPropertyDefinition {
    uint32_t nameIndex;
    int32_t get;
    int32_t set;
    uint32_t attrs;
    uint32_t token;
};

// Il2CppEventDefinition v31 (24 bytes)
struct Il2CppEventDefinition {
    uint32_t nameIndex;
    int32_t typeIndex;
    int32_t add;
    int32_t remove;
    int32_t raise;
    uint32_t token;
};

// Il2CppImageDefinition v31
struct Il2CppImageDefinition {
    uint32_t nameIndex;
    int32_t assemblyIndex;
    int32_t typeStart;
    uint32_t typeCount;
    int32_t exportedTypeStart;
    uint32_t exportedTypeCount;
    int32_t entryPointIndex;
    uint32_t token;
    int32_t customAttributeStart;
    uint32_t customAttributeCount;
};

// Il2CppGenericContainer (16 bytes)
struct Il2CppGenericContainer {
    int32_t ownerIndex;
    int32_t type_argc;
    int32_t is_method;
    int32_t genericParameterStart;
};

// Il2CppGenericParameter (16 bytes)
struct Il2CppGenericParameter {
    int32_t ownerIndex;
    uint32_t nameIndex;
    int16_t constraintsStart;
    int16_t constraintsCount;
    uint16_t num;
    uint16_t flags;
};

// Il2CppStringLiteral (8 bytes)
struct Il2CppStringLiteral {
    uint32_t length;
    int32_t dataIndex;
};

struct Metadata {
    const uint8_t* data = nullptr;
    size_t size = 0;
    MetadataHeader header{};
    size_t method_stride = 36;

    std::vector<Il2CppTypeDefinition> typeDefs;
    std::vector<Il2CppMethodDefinition> methodDefs;
    std::vector<Il2CppParameterDefinition> parameterDefs;
    std::vector<Il2CppFieldDefinition> fieldDefs;
    std::vector<Il2CppPropertyDefinition> propertyDefs;
    std::vector<Il2CppEventDefinition> eventDefs;
    std::vector<Il2CppImageDefinition> imageDefs;
    std::vector<Il2CppGenericContainer> genericContainers;
    std::vector<Il2CppGenericParameter> genericParameters;
    std::vector<Il2CppStringLiteral> stringLiterals;
    std::vector<int32_t> interfaceIndices;
    std::vector<int32_t> nestedTypeIndices;

    bool parse(const uint8_t* d, size_t n, const LogFn& log);
    std::string read_string(int32_t idx) const;
    std::string read_string_literal(uint32_t idx) const;

    int32_t type_def_count() const { return (int32_t)typeDefs.size(); }
    int32_t method_count_estimate() const;
};

void detect_ff_method_layout(Metadata& m, const LogFn& log);

// helpers to read sub-arrays of metadata
Il2CppTypeDefinition     read_typedef(const Metadata& m, size_t i);
Il2CppMethodDefinition   read_method(const Metadata& m, size_t i);
Il2CppParameterDefinition read_parameter(const Metadata& m, size_t i);
Il2CppFieldDefinition    read_field(const Metadata& m, size_t i);
Il2CppPropertyDefinition read_property(const Metadata& m, size_t i);
Il2CppEventDefinition    read_event(const Metadata& m, size_t i);
