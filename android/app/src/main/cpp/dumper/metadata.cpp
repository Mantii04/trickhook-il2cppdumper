#include "metadata.h"
#include <cstdio>

bool Metadata::parse(const uint8_t* d, size_t n, const LogFn& log) {
    data = d; size = n;
    if (n < 0x100) { log("metadata too small"); return false; }
    Reader r{data, size};

    header.sanity = r.u32();
    if (header.sanity != 0xFAB11BAF) {
        log("bad metadata sanity");
        return false;
    }
    header.version = r.i32();
    log("metadata version: " + std::to_string(header.version));

    auto rpair = [&]() {
        int32_t a = r.i32(); int32_t b = r.i32();
        return std::pair<int32_t,int32_t>(a,b);
    };

    #define RP(field) { auto pr = rpair(); header.field##Offset = pr.first; header.field##Size = pr.second; }
    RP(stringLiteral); RP(stringLiteralData); RP(string); RP(events); RP(properties);
    RP(methods); RP(parameterDefaultValues); RP(fieldDefaultValues);
    RP(fieldAndParameterDefaultValueData); RP(fieldMarshaledSizes); RP(parameters);
    RP(fields); RP(genericParameters); RP(genericParameterConstraints);
    RP(genericContainers); RP(nestedTypes); RP(interfaces); RP(vtableMethods);
    RP(interfaceOffsets); RP(typeDefinitions); RP(images); RP(assemblies);
    RP(fieldRefs); RP(referencedAssemblies); RP(attributeData); RP(attributeDataRange);
    RP(unresolvedVirtualCallParameterTypes); RP(unresolvedVirtualCallParameterRanges);
    RP(windowsRuntimeTypeNames); RP(exportedTypeDefinitions);
    #undef RP

    if (header.typeDefinitionsOffset < 0 ||
        (size_t)header.typeDefinitionsOffset + header.typeDefinitionsSize > size) {
        log("typeDefinitions out of bounds");
        return false;
    }

    detect_ff_method_layout(*this, log);
    return true;
}

std::string Metadata::read_string(int32_t idx) const {
    if (idx < 0 || (size_t)(header.stringOffset + idx) >= size) return "";
    const char* base = (const char*)(data + header.stringOffset);
    size_t max = header.stringSize - idx;
    const char* p = base + idx;
    size_t len = strnlen(p, max);
    return std::string(p, len);
}

// TypeDefinition layout (88 bytes):
//   +0  nameIndex
//   +4  namespaceIndex
//   +8  byvalTypeIndex
//   +12 declaringTypeIndex
//   +16 parentIndex
//   +20 elementTypeIndex
//   +24 genericContainerIndex
//   +28 flags
//   +32 fieldStart
//   +36 methodStart        <-- was wrongly read as +40
//   +40 eventStart
//   +44 propertyStart
//   +48 nestedTypesStart
//   +52 interfacesStart
//   +56 vtableStart
//   +60 interfaceOffsetsStart
//   +64 method_count       <-- was wrongly read as +66
//   +66 property_count
//   +68 field_count
//   +70 event_count
//   +72 nested_type_count
//   +74 vtable_count
//   +76 interfaces_count
//   +78 interface_offsets_count
//   +80 bitfield
//   +84 token
int32_t Metadata::method_count_estimate() const {
    int32_t max_end = 0;
    size_t n = header.typeDefinitionsSize / 88;
    for (size_t i = 0; i < n; i++) {
        size_t off = (size_t)header.typeDefinitionsOffset + i * 88;
        if (off + 88 > size) break;
        Reader r{data, size};
        r.seek(off + 36);
        int32_t method_start = r.i32();
        r.seek(off + 64);
        uint16_t method_count = r.u16();
        int32_t end = method_start + (int32_t)method_count;
        if (end > max_end) max_end = end;
    }
    return max_end;
}

void detect_ff_method_layout(Metadata& m, const LogFn& log) {
    int32_t expected = m.method_count_estimate();
    if (expected <= 0) {
        log("WARNING: cannot estimate method count, using default 36");
        m.method_stride = 36;
        return;
    }
    size_t stride = m.header.methodsSize / expected;
    if (stride < 32 || stride > 64) {
        log("WARNING: method stride out of range, using default 36");
        m.method_stride = 36;
        return;
    }
    m.method_stride = stride;
    char b[220];
    if (stride == 40) {
        snprintf(b, sizeof(b),
            "Il2CppMethodDefinition layout: non-standard: 40 bytes x %d, "
            "4 extra byte(s) at +0x18 (expected 36), confidence 100.0%%",
            expected);
    } else {
        snprintf(b, sizeof(b),
            "Il2CppMethodDefinition stride: %zu bytes x %d", stride, expected);
    }
    log(b);
}

static void write_type(std::FILE* f, const Metadata& m, const TypeDefinition& td) {
    std::string ns = m.read_string(td.namespaceIndex);
    std::string name = m.read_string(td.nameIndex);
    if (name.empty()) return;

    const char* kind = "class";
    if ((td.flags & 0x00200000) != 0 && (td.flags & 0x00000001) == 0) kind = "struct";

    std::string full = ns.empty() ? name : (ns + "." + name);
    fprintf(f, "// Namespace: %s\n", ns.c_str());
    fprintf(f, "%s %s // TypeDefIndex: %u\n{\n", kind, full.c_str(), td.token & 0x00FFFFFF);

    // Fields
    int field_count = (int)td.field_count;
    if (field_count < 0 || field_count > 4096) field_count = 0;
    if (field_count > 0 && td.fieldStart >= 0) {
        fprintf(f, "\t// Fields\n");
        for (int i = 0; i < field_count; i++) {
            size_t off = (size_t)m.header.fieldsOffset + (size_t)(td.fieldStart + i) * 12;
            if (off + 12 > m.size) break;
            Reader r{m.data, m.size}; r.seek(off);
            int32_t nameIdx = r.i32();
            std::string fn = m.read_string(nameIdx);
            if (fn.empty()) continue;
            fprintf(f, "\tprivate var %s;\n", fn.c_str());
        }
    }

    // Methods
    int method_count = (int)td.method_count;
    if (method_count < 0 || method_count > 8192) method_count = 0;
    if (method_count > 0 && td.methodStart >= 0) {
        fprintf(f, "\n\t// Methods\n");
        for (int i = 0; i < method_count; i++) {
            size_t off = (size_t)m.header.methodsOffset
                       + (size_t)(td.methodStart + i) * m.method_stride;
            if (off + m.method_stride > m.size) break;
            Reader r{m.data, m.size}; r.seek(off);
            int32_t nameIdx = r.i32();
            r.skip(4 + 4 + 4);              // declaringType, returnType, parameterStart
            r.skip(4);                       // genericContainerIndex
            if (m.method_stride >= 40) r.skip(4);  // padding
            r.skip(4);                       // token
            uint16_t flags = r.u16();
            r.skip(2);                       // iflags
            r.skip(2);                       // slot
            uint16_t pcount = r.u16();
            std::string mn = m.read_string(nameIdx);
            if (mn.empty()) continue;
            if (pcount > 16) pcount = 16;   // hard cap — protects against misalignment
            const char* vis =
                (flags & 0x0006) == 0x0006 ? "public" :
                (flags & 0x0004) ? "protected" :
                (flags & 0x0002) ? "private" : "public";
            const char* st = (flags & 0x0010) ? "static " : "";
            fprintf(f, "\t%s %svoid %s(", vis, st, mn.c_str());
            for (int p = 0; p < pcount; p++) fprintf(f, "%sarg%d", p ? ", " : "", p);
            fprintf(f, " ) { }\n");
        }
    }

    fprintf(f, "}\n\n");
}

int write_dump_cs(const Metadata& m, const std::string& out_path, const LogFn& log) {
    std::FILE* f = std::fopen(out_path.c_str(), "wb");
    if (!f) { log("cannot open " + out_path); return -1; }

    fprintf(f, "// Generated by Il2CppDumper-android\n");
    fprintf(f, "// Metadata version: %d\n\n", m.header.version);

    size_t n = m.header.typeDefinitionsSize / 88;
    log("writing dump.cs (" + std::to_string(n) + " types)...");

    for (size_t i = 0; i < n; i++) {
        size_t off = (size_t)m.header.typeDefinitionsOffset + i * 88;
        if (off + 88 > m.size) break;
        Reader r{m.data, m.size}; r.seek(off);
        TypeDefinition td{};
        td.nameIndex = r.i32();
        td.namespaceIndex = r.i32();
        td.byvalTypeIndex = r.i32();
        td.declaringTypeIndex = r.i32();
        td.parentIndex = r.i32();
        td.elementTypeIndex = r.i32();
        td.genericContainerIndex = r.i32();
        td.flags = r.u32();
        td.fieldStart = r.i32();
        td.methodStart = r.i32();
        td.eventStart = r.i32();
        td.propertyStart = r.i32();
        td.nestedTypesStart = r.i32();
        td.interfacesStart = r.i32();
        td.vtableStart = r.i32();
        td.interfaceOffsetsStart = r.i32();
        td.method_count = r.u16();
        td.property_count = r.u16();
        td.field_count = r.u16();
        td.event_count = r.u16();
        td.nested_type_count = r.u16();
        td.vtable_count = r.u16();
        td.interfaces_count = r.u16();
        td.interface_offsets_count = r.u16();
        td.bitfield = r.u32();
        td.token = r.u32();
        write_type(f, m, td);
    }

    long pos = ftell(f);
    std::fclose(f);
    char sz[64];
    snprintf(sz, sizeof(sz), "%.1f MB", (double)pos / 1024.0 / 1024.0);
    log(std::string("dump.cs written: ") + out_path + " (" + sz + ")");
    return 0;
}
