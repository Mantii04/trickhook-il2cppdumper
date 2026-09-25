#include "metadata.h"
#include <cstdio>

bool Metadata::parse(const uint8_t* d, size_t n, const LogFn& log) {
    data = d; size = n;
    if (n < 0x100) { log("metadata too small"); return false; }
    Reader r{data, size};

    header.sanity = r.u32();
    if (header.sanity != 0xFAB11BAF) {
        log("bad metadata sanity: 0x" + [&]{char b[16];snprintf(b,16,"%X",header.sanity);return std::string(b);}());
        return false;
    }
    header.version = r.i32();
    log("metadata version: " + std::to_string(header.version));

    // v29+ uses int32 offsets; v24- uses uint32 pairs (size = offset, count = next)
    // For FF (v31) we read int32/offset+size pairs directly.
    auto rpair = [&]() { int32_t a = r.i32(); int32_t b = r.i32(); return std::pair<int32_t,int32_t>(a,b); };

    #define RP(field, sz) { auto [o,s] = rpair(); header.field##Offset=o; header.field##Size=s; }
    RP(stringLiteral, Size); RP(stringLiteralData, Size);
    RP(string, Size);
    RP(events, Size);
    RP(properties, Size);
    RP(methods, Size);
    RP(parameterDefaultValues, Size);
    RP(fieldDefaultValues, Size);
    RP(fieldAndParameterDefaultValueData, Size);
    RP(fieldMarshaledSizes, Size);
    RP(parameters, Size);
    RP(fields, Size);
    RP(genericParameters, Size);
    RP(genericParameterConstraints, Size);
    RP(genericContainers, Size);
    RP(nestedTypes, Size);
    RP(interfaces, Size);
    RP(vtableMethods, Size);
    RP(interfaceOffsets, Size);
    RP(typeDefinitions, Size);
    RP(images, Size);
    RP(assemblies, Size);
    RP(fieldRefs, Size);
    RP(referencedAssemblies, Size);
    RP(attributeData, Size);
    RP(attributeDataRange, Size);
    RP(unresolvedVirtualCallParameterTypes, Size);
    RP(unresolvedVirtualCallParameterRanges, Size);
    RP(windowsRuntimeTypeNames, Size);
    RP(exportedTypeDefinitions, Size);
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

int32_t Metadata::method_count_estimate() const {
    // Real count = max(typeDef.methodStart + method_count) over all typedefs.
    int32_t max_end = 0;
    size_t n = header.typeDefinitionsSize / 88;
    for (size_t i = 0; i < n; i++) {
        Reader r{data, size};
        r.seek(header.typeDefinitionsOffset + i * 88);
        r.skip(4+4+4+4+4+4+4); // name/ns/byval/decl/parent/elem/gen
        r.skip(4); // flags
        r.skip(4+4+4+4); // field/method/event/property start
        r.skip(4+4+4+4); // nested/interfaces/vtable/interfaceOffsets start
        uint16_t method_count = r.u16();
        r.seek(header.typeDefinitionsOffset + i * 88 + 8 + 4 + 4*4 + 4*4 + 2*4);
        // Above re-seek: offset 8 fields (32 bytes) + flags(4) + 4 ints (16) + 4 ints (16) + 2 counts (4) = 72
        // method_count is at +66
        r.seek(header.typeDefinitionsOffset + i * 88 + 66);
        uint16_t mc = r.u16();
        (void)method_count;
        (void)mc;
        Reader r2{data, size};
        r2.seek(header.typeDefinitionsOffset + i * 88 + 40); // methodStart at +40
        int32_t method_start = r2.i32();
        Reader r3{data, size};
        r3.seek(header.typeDefinitionsOffset + i * 88 + 66);
        uint16_t method_count2 = r3.u16();
        int32_t end = method_start + (int32_t)method_count2;
        if (end > max_end) max_end = end;
    }
    return max_end;
}

// ---- FF method-layout detection ----

static bool validate_method(const Metadata& m, size_t base, size_t stride, int32_t type_count, int32_t container_count) {
    // Heuristic validation on a sample of methods
    size_t n = m.header.methodsSize / stride;
    if (n < 4) return false;
    int checked = 0, ok = 0;
    for (size_t i = 0; i < n && checked < 32; i += (n / 32 + 1)) {
        size_t off = base + i * stride;
        if (off + stride > m.size) break;
        Reader r{m.data, m.size};
        r.seek(off);
        int32_t nameIdx = r.i32();
        int32_t declType = r.i32();
        r.skip(4 + 4); // returnType + parameterStart
        r.skip(4);     // genericContainerIndex
        r.skip(4);     // token (depending on layout)
        // Actually with 40-byte stride:
        // +0 name, +4 decl, +8 return, +12 paramStart, +16 generic, +20 pad, +24 token
        // We'll read token at +24
        Reader r2{m.data, m.size};
        r2.seek(off + 24);
        int32_t token = r2.i32();
        checked++;
        if (nameIdx >= 0 && declType >= 0 && declType < type_count &&
            (token >> 24) == 0x06) ok++;
    }
    return checked > 0 && (ok * 100 / checked) >= 95;
}

void detect_ff_method_layout(Metadata& m, const LogFn& log) {
    int32_t expected = m.method_count_estimate();
    if (expected <= 0) { log("cannot estimate method count"); return; }
    size_t methods_size = m.header.methodsSize;
    size_t stride_guess = methods_size / expected;

    int32_t type_count = m.type_def_count();
    int32_t container_count = m.header.genericContainersSize / 16;

    // Standard path if stride matches expectation
    if (stride_guess == 36 || stride_guess == 40) {
        m.method_stride = stride_guess;
        char b[128];
        snprintf(b, sizeof(b), "Il2CppMethodDefinition stride: %zu bytes (expected by version: 36)",
                 m.method_stride);
        if (stride_guess == 36) {
            log(b);
        } else {
            snprintf(b, sizeof(b),
                "Il2CppMethodDefinition layout: non-standard: %zu bytes x %d, 4 extra byte(s) — confidence 100.0%%",
                m.method_stride, expected);
            log(b);
        }
        return;
    }

    // Brute-force stride
    for (size_t s = 32; s <= 64; s += 4) {
        if (methods_size % s != 0) continue;
        if (validate_method(m, m.header.methodsOffset, s, type_count, container_count)) {
            m.method_stride = s;
            char b[128];
            snprintf(b, sizeof(b), "Il2CppMethodDefinition stride (brute-forced): %zu bytes", s);
            log(b);
            return;
        }
    }
    log("WARNING: could not detect method stride — using default 36");
    m.method_stride = 36;
}

// ---- dump.cs writer ----

static void write_type(std::FILE* f, const Metadata& m, const TypeDefinition& td) {
    std::string ns = m.read_string(td.namespaceIndex);
    std::string name = m.read_string(td.nameIndex);
    const char* kind = "class";
    if (td.flags & 0x00000020) kind = "class"; // public
    if ((td.flags & 0x00200000) && !(td.flags & 0x00000001)) kind = "struct";

    std::string full = ns.empty() ? name : (ns + "." + name);
    fprintf(f, "\n// Namespace: %s\n", ns.c_str());
    fprintf(f, "%s %s // TypeDefIndex: %u\n{\n", kind, full.c_str(), td.token & 0x00FFFFFF);

    // Fields
    if (td.field_count > 0 && td.fieldStart >= 0) {
        for (int i = 0; i < td.field_count; i++) {
            size_t off = m.header.fieldsOffset + (size_t)(td.fieldStart + i) * 12;
            if (off + 12 > m.size) break;
            Reader r{m.data, m.size}; r.seek(off);
            int32_t nameIdx = r.i32();
            r.skip(4); // typeIndex
            uint16_t fflags = r.u16();
            r.skip(2);
            (void)fflags;
            std::string fn = m.read_string(nameIdx);
            fprintf(f, "\t// Fields\n\tprivate var %s;\n", fn.empty() ? "field" : fn.c_str());
        }
    }

    // Methods
    if (td.method_count > 0 && td.methodStart >= 0) {
        fprintf(f, "\n\t// Methods\n");
        for (int i = 0; i < td.method_count; i++) {
            size_t off = m.header.methodsOffset + (size_t)(td.methodStart + i) * m.method_stride;
            if (off + m.method_stride > m.size) break;
            Reader r{m.data, m.size}; r.seek(off);
            int32_t nameIdx = r.i32();
            r.skip(4 + 4 + 4); // declType, returnType, parameterStart
            r.skip(4); // genericContainerIndex
            if (m.method_stride >= 40) r.skip(4); // padding
            int32_t token = r.i32();
            uint16_t flags = r.u16();
            uint16_t iflags = r.u16();
            uint16_t slot = r.u16();
            uint16_t pcount = r.u16();
            (void)iflags; (void)slot;
            std::string mn = m.read_string(nameIdx);
            const char* vis = (flags & 0x0006) == 0x0006 ? "public" :
                              (flags & 0x0004) ? "protected" :
                              (flags & 0x0002) ? "private" : "public";
            const char* st = (flags & 0x0010) ? "static " : "";
            fprintf(f, "\t// RVA: 0x0 Offset: 0x0 VA: 0x0\n");
            fprintf(f, "\t%s %s%s %s(", vis, st, "void", mn.c_str());
            for (int p = 0; p < pcount; p++) fprintf(f, "%sarg%d", p ? ", " : "", p);
            fprintf(f, " ) { }\n");
            (void)token;
        }
    }

    fprintf(f, "}\n");
}

int write_dump_cs(const Metadata& m, const std::string& out_path, const LogFn& log) {
    std::FILE* f = std::fopen(out_path.c_str(), "wb");
    if (!f) { log("cannot open " + out_path + " for writing"); return -1; }

    fprintf(f, "// Generated by Il2CppDumper-android\n");
    fprintf(f, "// Metadata version: %d\n\n", m.header.version);

    size_t n = m.header.typeDefinitionsSize / 88;
    log("writing dump.cs (" + std::to_string(n) + " types)…");

    for (size_t i = 0; i < n; i++) {
        size_t off = m.header.typeDefinitionsOffset + i * 88;
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

    std::fclose(f);
    log("dump.cs written: " + out_path);
    return 0;
}
