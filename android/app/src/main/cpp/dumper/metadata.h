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
    int32_t exportedTypeDefinitionsOffset = 0;
    int32_t exportedTypeDefinitionsSize = 0;
};

struct Metadata {
    const uint8_t* data = nullptr;
    size_t size = 0;
    MetadataHeader header{};
    size_t method_stride = 36; // overwritten for FF

    bool parse(const uint8_t* d, size_t n, const LogFn& log);
    std::string read_string(int32_t idx) const;
    int32_t type_def_count() const { return header.typeDefinitionsSize / 88; }
    int32_t method_count_estimate() const;
};

struct MethodDefinition {
    int32_t nameIndex;
    int32_t declaringType;
    int32_t returnType;
    int32_t parameterStart;
    int32_t genericContainerIndex;
    int32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint16_t parameterCount;
};

struct TypeDefinition {
    int32_t nameIndex;
    int32_t namespaceIndex;
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
};

void detect_ff_method_layout(Metadata& m, const LogFn& log);

int write_dump_cs(const Metadata& m,
                  const std::string& out_path,
                  const LogFn& log);
