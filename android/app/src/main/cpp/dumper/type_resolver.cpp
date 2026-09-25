#include "type_resolver.h"
#include "metadata.h"

// Il2CppTypeEnum values
enum {
    TYPE_END = 0x00, TYPE_VOID = 0x01, TYPE_BOOLEAN = 0x02, TYPE_CHAR = 0x03,
    TYPE_I1 = 0x04, TYPE_U1 = 0x05, TYPE_I2 = 0x06, TYPE_U2 = 0x07,
    TYPE_I4 = 0x08, TYPE_U4 = 0x09, TYPE_I8 = 0x0a, TYPE_U8 = 0x0b,
    TYPE_R4 = 0x0c, TYPE_R8 = 0x0d, TYPE_STRING = 0x0e,
    TYPE_PTR = 0x0f, TYPE_BYREF = 0x10, TYPE_VALUETYPE = 0x11, TYPE_CLASS = 0x12,
    TYPE_VAR = 0x13, TYPE_ARRAY = 0x14, TYPE_GENERICINST = 0x15, TYPE_TYPEDBYREF = 0x16,
    TYPE_I = 0x18, TYPE_U = 0x19, TYPE_FNPTR = 0x1b, TYPE_OBJECT = 0x1c,
    TYPE_SZARRAY = 0x1d, TYPE_MVAR = 0x1e,
    TYPE_ENUM = 0x55, TYPE_IL2CPP_TYPE_INDEX = 0xff
};

static const std::map<int, const char*> g_primitives = {
    {1,"void"},{2,"bool"},{3,"char"},{4,"sbyte"},{5,"byte"},{6,"short"},{7,"ushort"},
    {8,"int"},{9,"uint"},{10,"long"},{11,"ulong"},{12,"float"},{13,"double"},
    {14,"string"},{22,"TypedReference"},{24,"IntPtr"},{25,"UIntPtr"},{28,"object"},
};

// read Il2CppGenericClass
struct GenericClassView {
    uint64_t type;
    uint64_t class_inst;
    uint64_t method_inst;
    uint64_t cached_class;
};

static GenericClassView readGenericClass(const Il2CppBinary& bin, uint64_t ptr) {
    GenericClassView g{};
    g.type = bin.readPtr(ptr);
    g.class_inst = bin.readPtr(ptr + 8);
    g.method_inst = bin.readPtr(ptr + 16);
    g.cached_class = bin.readPtr(ptr + 24);
    return g;
}

// read Il2CppArrayType (for TYPE_ARRAY)
struct ArrayTypeView {
    uint64_t etype;
    uint8_t rank;
};
static ArrayTypeView readArrayType(const Il2CppBinary& bin, uint64_t ptr) {
    ArrayTypeView a{};
    a.etype = bin.readPtr(ptr);
    a.rank = (uint8_t)bin.readU16(ptr + 8) & 0xff;
    return a;
}

const Il2CppTypeDefinition* TypeResolver::typeDefFromType(const Il2CppType& t) const {
    if (t.type_enum == TYPE_CLASS || t.type_enum == TYPE_VALUETYPE) {
        int64_t idx = (int64_t)t.datapoint;
        if (idx < 0 || (size_t)idx >= md_.typeDefs.size()) return nullptr;
        return &md_.typeDefs[idx];
    }
    return nullptr;
}

std::string TypeResolver::genericContainerParams(int32_t containerIdx) const {
    if (containerIdx < 0 || (size_t)containerIdx >= md_.genericContainers.size()) return "";
    const auto& gc = md_.genericContainers[containerIdx];
    std::string out = "<";
    for (int i = 0; i < gc.type_argc; i++) {
        int32_t pi = gc.genericParameterStart + i;
        if (pi < 0 || (size_t)pi >= md_.genericParameters.size()) continue;
        if (i) out += ", ";
        out += md_.read_string(md_.genericParameters[pi].nameIndex);
    }
    out += ">";
    return out;
}

std::string TypeResolver::typeName(const Il2CppType& t, bool addNamespace, bool isNested) const {
    switch (t.type_enum) {
        case TYPE_ARRAY: {
            auto at = readArrayType(bin_, t.datapoint);
            const Il2CppType* elem = bin_.typeAt(at.etype);
            std::string inner = elem ? typeName(*elem, addNamespace, false) : "?";
            std::string commas;
            for (int i = 0; i + 1 < at.rank; i++) commas += ",";
            return inner + "[" + commas + "]";
        }
        case TYPE_SZARRAY: {
            const Il2CppType* elem = bin_.typeAt(t.datapoint);
            std::string inner = elem ? typeName(*elem, addNamespace, false) : "?";
            return inner + "[]";
        }
        case TYPE_PTR: {
            const Il2CppType* pointee = bin_.typeAt(t.datapoint);
            std::string inner = pointee ? typeName(*pointee, addNamespace, false) : "?";
            return inner + "*";
        }
        case TYPE_VAR:
        case TYPE_MVAR: {
            int64_t idx = (int64_t)t.datapoint;
            if (idx < 0 || (size_t)idx >= md_.genericParameters.size()) return "?";
            return md_.read_string(md_.genericParameters[idx].nameIndex);
        }
        case TYPE_CLASS:
        case TYPE_VALUETYPE:
        case TYPE_GENERICINST: {
            std::string str;
            const Il2CppTypeDefinition* td = nullptr;
            GenericClassView gc{};
            bool hasGc = false;
            if (t.type_enum == TYPE_GENERICINST) {
                gc = readGenericClass(bin_, t.datapoint);
                hasGc = true;
                // resolve to typedef: for v27+, gc.type points to a Il2CppType
                const Il2CppType* innerType = bin_.typeAt(gc.type);
                if (innerType && innerType->type_enum != TYPE_GENERICINST) {
                    // innerType.data.klassIndex -> typedef
                    if (innerType->type_enum == TYPE_CLASS || innerType->type_enum == TYPE_VALUETYPE) {
                        int64_t idx = (int64_t)innerType->datapoint;
                        if (idx >= 0 && (size_t)idx < md_.typeDefs.size())
                            td = &md_.typeDefs[idx];
                    }
                }
            } else {
                td = typeDefFromType(t);
            }
            if (!td) return "?";

            if (td->declaringTypeIndex != -1 &&
                (size_t)td->declaringTypeIndex < bin_.types().size()) {
                str += typeName(bin_.types()[td->declaringTypeIndex], addNamespace, true);
                str += ".";
            } else if (addNamespace) {
                std::string ns = md_.read_string(td->namespaceIndex);
                if (!ns.empty()) str += ns + ".";
            }

            std::string tn = md_.read_string(td->nameIndex);
            auto bp = tn.find('`');
            if (bp != std::string::npos) tn = tn.substr(0, bp);
            str += tn;

            if (isNested) return str;

            if (hasGc) {
                // Read the class_inst (generic instance)
                if (gc.class_inst) {
                    Il2CppGenericInst gi{};
                    gi.type_argc = (int64_t)bin_.readPtr(gc.class_inst);
                    gi.type_argv = bin_.readPtr(gc.class_inst + 8);
                    std::string out = "<";
                    for (int64_t k = 0; k < gi.type_argc; k++) {
                        uint64_t tp = bin_.readPtr(gi.type_argv + k * 8);
                        const Il2CppType* tt = bin_.typeAt(tp);
                        if (k) out += ", ";
                        out += tt ? typeName(*tt, false, false) : "?";
                    }
                    out += ">";
                    str += out;
                }
            } else if (td->genericContainerIndex >= 0) {
                str += genericContainerParams(td->genericContainerIndex);
            }
            return str;
        }
        default: {
            auto it = g_primitives.find((int)t.type_enum);
            if (it != g_primitives.end()) return it->second;
            return "?";
        }
    }
}

std::string TypeResolver::typeDefName(const Il2CppTypeDefinition& td, bool addNamespace, bool genericParameter) const {
    std::string prefix;
    if (td.declaringTypeIndex != -1 && (size_t)td.declaringTypeIndex < bin_.types().size()) {
        prefix = typeName(bin_.types()[td.declaringTypeIndex], addNamespace, true) + ".";
    } else if (addNamespace) {
        std::string ns = md_.read_string(td.namespaceIndex);
        if (!ns.empty()) prefix = ns + ".";
    }
    std::string tn = md_.read_string(td.nameIndex);
    if (td.genericContainerIndex >= 0) {
        auto bp = tn.find('`');
        if (bp != std::string::npos) tn = tn.substr(0, bp);
        if (genericParameter) tn += genericContainerParams(td.genericContainerIndex);
    }
    return prefix + tn;
}
