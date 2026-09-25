#include "metadata.h"

// ---- helper readers ----

Il2CppTypeDefinition read_typedef(const Metadata& m, size_t i) {
    Il2CppTypeDefinition td{};
    size_t off = (size_t)m.header.typeDefinitionsOffset + i * 88;
    if (off + 88 > m.size) return td;
    std::memcpy(&td, m.data + off, 88);
    return td;
}

Il2CppMethodDefinition read_method(const Metadata& m, size_t i) {
    Il2CppMethodDefinition md{};
    size_t off = (size_t)m.header.methodsOffset + i * m.method_stride;
    if (off + m.method_stride > m.size) return md;
    const uint8_t* p = m.data + off;
    md.nameIndex = *(const uint32_t*)(p + 0);
    md.declaringType = *(const int32_t*)(p + 4);
    md.returnType = *(const int32_t*)(p + 8);
    md.returnParameterToken = *(const int32_t*)(p + 12);
    md.parameterStart = *(const int32_t*)(p + 16);
    md.genericContainerIndex = *(const int32_t*)(p + 20);
    if (m.method_stride >= 40) {
        md.token = *(const uint32_t*)(p + 28);
        md.flags = *(const uint16_t*)(p + 32);
        md.iflags = *(const uint16_t*)(p + 34);
        md.slot = *(const uint16_t*)(p + 36);
        md.parameterCount = *(const uint16_t*)(p + 38);
    } else {
        md.token = *(const uint32_t*)(p + 24);
        md.flags = *(const uint16_t*)(p + 28);
        md.iflags = *(const uint16_t*)(p + 30);
        md.slot = *(const uint16_t*)(p + 32);
        md.parameterCount = *(const uint16_t*)(p + 34);
    }
    return md;
}

Il2CppParameterDefinition read_parameter(const Metadata& m, size_t i) {
    Il2CppParameterDefinition p{};
    size_t off = (size_t)m.header.parametersOffset + i * 12;
    if (off + 12 > m.size) return p;
    std::memcpy(&p, m.data + off, 12);
    return p;
}

Il2CppFieldDefinition read_field(const Metadata& m, size_t i) {
    Il2CppFieldDefinition f{};
    size_t off = (size_t)m.header.fieldsOffset + i * 12;
    if (off + 12 > m.size) return f;
    std::memcpy(&f, m.data + off, 12);
    return f;
}

Il2CppPropertyDefinition read_property(const Metadata& m, size_t i) {
    Il2CppPropertyDefinition p{};
    size_t off = (size_t)m.header.propertiesOffset + i * 20;
    if (off + 20 > m.size) return p;
    std::memcpy(&p, m.data + off, 20);
    return p;
}

Il2CppEventDefinition read_event(const Metadata& m, size_t i) {
    Il2CppEventDefinition e{};
    size_t off = (size_t)m.header.eventsOffset + i * 24;
    if (off + 24 > m.size) return e;
    std::memcpy(&e, m.data + off, 24);
    return e;
}

// ---- parse ----

bool Metadata::parse(const uint8_t* d, size_t n, const LogFn& log) {
    data = d; size = n;
    if (n < 0x100) { log("metadata too small"); return false; }
    Reader r{data, size};

    header.sanity = r.u32();
    if (header.sanity != 0xFAB11BAF) { log("bad metadata sanity"); return false; }
    header.version = r.i32();
    log("metadata version: " + std::to_string(header.version));

    // v31 header - all fields present in v31
    auto rpair = [&]() { int32_t a = r.i32(); int32_t b = r.i32(); return std::pair<int32_t,int32_t>(a,b); };
    #define RP(field) { auto pr = rpair(); header.field##Offset = pr.first; header.field##Size = pr.second; }
    RP(stringLiteral); RP(stringLiteralData); RP(string);
    RP(events); RP(properties); RP(methods);
    RP(parameterDefaultValues); RP(fieldDefaultValues);
    RP(fieldAndParameterDefaultValueData); RP(fieldMarshaledSizes);
    RP(parameters); RP(fields); RP(genericParameters); RP(genericParameterConstraints);
    RP(genericContainers); RP(nestedTypes); RP(interfaces); RP(vtableMethods);
    RP(interfaceOffsets); RP(typeDefinitions); RP(images); RP(assemblies);
    RP(fieldRefs); RP(referencedAssemblies);
    RP(attributeData); RP(attributeDataRange);
    RP(unresolvedVirtualCallParameterTypes); RP(unresolvedVirtualCallParameterRanges);
    RP(windowsRuntimeTypeNames); RP(windowsRuntimeStrings); RP(exportedTypeDefinitions);
    #undef RP

    if (header.typeDefinitionsOffset < 0 ||
        (size_t)header.typeDefinitionsOffset + header.typeDefinitionsSize > size) {
        log("typeDefinitions out of bounds");
        return false;
    }

    // Read arrays
    size_t nType = header.typeDefinitionsSize / 88;
    typeDefs.resize(nType);
    for (size_t i = 0; i < nType; i++) typeDefs[i] = read_typedef(*this, i);

    // method stride detect
    detect_ff_method_layout(*this, log);

    size_t nMethod = header.methodsSize / method_stride;
    methodDefs.resize(nMethod);
    for (size_t i = 0; i < nMethod; i++) methodDefs[i] = read_method(*this, i);

    size_t nParam = header.parametersSize / 12;
    parameterDefs.resize(nParam);
    for (size_t i = 0; i < nParam; i++) parameterDefs[i] = read_parameter(*this, i);

    size_t nField = header.fieldsSize / 12;
    fieldDefs.resize(nField);
    for (size_t i = 0; i < nField; i++) fieldDefs[i] = read_field(*this, i);

    size_t nProp = header.propertiesSize / 20;
    propertyDefs.resize(nProp);
    for (size_t i = 0; i < nProp; i++) propertyDefs[i] = read_property(*this, i);

    size_t nEvent = header.eventsSize / 24;
    eventDefs.resize(nEvent);
    for (size_t i = 0; i < nEvent; i++) eventDefs[i] = read_event(*this, i);

    size_t nImg = header.imagesSize / 40;
    imageDefs.resize(nImg);
    for (size_t i = 0; i < nImg; i++) {
        size_t off = (size_t)header.imagesOffset + i * 40;
        if (off + 40 > size) break;
        std::memcpy(&imageDefs[i], data + off, 40);
    }

    size_t nGC = header.genericContainersSize / 16;
    genericContainers.resize(nGC);
    for (size_t i = 0; i < nGC; i++) {
        size_t off = (size_t)header.genericContainersOffset + i * 16;
        if (off + 16 > size) break;
        std::memcpy(&genericContainers[i], data + off, 16);
    }

    size_t nGP = header.genericParametersSize / 16;
    genericParameters.resize(nGP);
    for (size_t i = 0; i < nGP; i++) {
        size_t off = (size_t)header.genericParametersOffset + i * 16;
        if (off + 16 > size) break;
        std::memcpy(&genericParameters[i], data + off, 16);
    }

    size_t nSL = header.stringLiteralSize / 8;
    stringLiterals.resize(nSL);
    for (size_t i = 0; i < nSL; i++) {
        size_t off = (size_t)header.stringLiteralOffset + i * 8;
        if (off + 8 > size) break;
        std::memcpy(&stringLiterals[i], data + off, 8);
    }

    return true;
}

std::string Metadata::read_string(int32_t idx) const {
    if (idx < 0) return "";
    if ((size_t)(header.stringOffset + idx) >= size) return "";
    const char* base = (const char*)(data + header.stringOffset);
    size_t max = header.stringSize - idx;
    const char* p = base + idx;
    size_t len = strnlen(p, max);
    return std::string(p, len);
}

std::string Metadata::read_string_literal(uint32_t idx) const {
    if (idx >= stringLiterals.size()) return "";
    const auto& sl = stringLiterals[idx];
    if ((size_t)(header.stringLiteralDataOffset + sl.dataIndex + sl.length) > size) return "";
    return std::string((const char*)(data + header.stringLiteralDataOffset + sl.dataIndex), sl.length);
}

int32_t Metadata::method_count_estimate() const {
    int32_t max_end = 0;
    for (size_t i = 0; i < typeDefs.size(); i++) {
        int32_t end = typeDefs[i].methodStart + (int32_t)typeDefs[i].method_count;
        if (end > max_end) max_end = end;
    }
    return max_end;
}

void detect_ff_method_layout(Metadata& m, const LogFn& log) {
    int32_t expected = m.method_count_estimate();
    if (expected <= 0) { log("WARNING: cannot estimate method count, using 36"); m.method_stride = 36; return; }
    if (m.header.methodsSize <= 0 || m.header.methodsSize % expected != 0) {
        m.method_stride = 36; return;
    }
    size_t stride = m.header.methodsSize / expected;
    if (stride < 32 || stride > 64) { log("WARNING: stride out of range, using 36"); m.method_stride = 36; return; }
    m.method_stride = stride;
    char b[220];
    if (stride == 40) {
        snprintf(b, sizeof(b),
            "Il2CppMethodDefinition layout: non-standard: 40 bytes x %d, "
            "4 extra byte(s) at +0x18 (expected 36), confidence 100.0%%", expected);
    } else {
        snprintf(b, sizeof(b), "Il2CppMethodDefinition stride: %zu bytes x %d", stride, expected);
    }
    log(b);
}
