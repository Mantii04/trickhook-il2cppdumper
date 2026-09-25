#include "main.h"
#include "elf_parser.h"
#include "ff_protector.h"
#include "metadata.h"
#include "output_writer.h"
#include <cstdio>
#include <fstream>

static std::vector<uint8_t> read_file(const std::string& p, const LogFn& log) {
    std::ifstream f(p, std::ios::binary);
    if (!f) { log("cannot open " + p); return {}; }
    f.seekg(0, std::ios::end);
    std::streamoff n = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> b((size_t)n);
    f.read((char*)b.data(), n);
    return b;
}

int run_dump(const std::string& so_path,
             const std::string& meta_path,
             const std::string& out_dir,
             const LogFn& log) {

    log("loading libil2cpp.so…");
    auto so = read_file(so_path, log);
    if (so.empty()) return 2;
    log("  " + std::to_string(so.size() / 1024 / 1024) + " MB");

    ElfInfo elf = parse_elf(so.data(), so.size());
    if (!elf.valid) { log("not a valid ELF"); return 3; }

    log("parsed ELF, " + std::to_string(elf.sections.size()) + " sections");

    if (!ff_unpack(elf, so, log)) {
        log("unpack failed");
        return 4;
    }

    log("loading global-metadata.dat…");
    auto meta = read_file(meta_path, log);
    if (meta.empty()) return 5;

    Metadata md;
    if (!md.parse(meta.data(), meta.size(), log)) {
        log("metadata parse failed");
        return 6;
    }

    // Diagnostic block
    {
        char b[200];
        snprintf(b, sizeof(b), "  stringOffset=0x%x stringSize=0x%x methodsOffset=0x%x methodsSize=0x%x",
                 md.header.stringOffset, md.header.stringSize,
                 md.header.methodsOffset, md.header.methodsSize);
        log(b);
        log("  first 5 strings:");
        for (int i = 0; i < 5; i++) {
            int idx = i * 1024;
            std::string s = md.read_string(idx);
            snprintf(b, sizeof(b), "    idx=%d -> '%s'", idx, s.c_str());
            log(b);
        }
        log("  raw hex of first 4 method structs (40 bytes each):");
        for (int mi = 0; mi < 4; mi++) {
            size_t base = (size_t)md.header.methodsOffset + (size_t)mi * md.method_stride;
            if (base + md.method_stride > meta.size()) break;
            const uint8_t* p = meta.data() + base;
            char line[256]; int off = 0;
            off += snprintf(line + off, sizeof(line) - off, "    m[%d] ", mi);
            for (size_t k = 0; k < md.method_stride; k++) {
                off += snprintf(line + off, sizeof(line) - off, "%02x", p[k]);
                if (k % 4 == 3) off += snprintf(line + off, sizeof(line) - off, " ");
            }
            log(line);
        }

        log("  first 8 methods (nameIdx, declType, token, flags, pcount):");
        for (int i = 0; i < 8; i++) {
            size_t off = (size_t)md.header.methodsOffset + (size_t)i * md.method_stride;
            if (off + md.method_stride > meta.size()) break;
            Reader r{meta.data(), meta.size()};
            r.seek(off);
            int32_t nameIdx = r.i32();
            int32_t declType = r.i32();
            r.seek(off + 24);
            int32_t token = r.i32();
            r.seek(off + md.method_stride - 8);
            uint16_t flags = r.u16(); r.skip(2);
            r.skip(2);
            uint16_t pcount = r.u16();
            std::string nm = md.read_string(nameIdx);
            snprintf(b, sizeof(b), "    m[%d] nameIdx=%d declType=%d token=0x%x flags=0x%x pcount=%u name='%s'",
                     i, nameIdx, declType, token, flags, pcount, nm.c_str());
            log(b);
        }
    }

    std::string dump_path = out_dir + "/dump.cs";
    if (write_dump_cs(md, dump_path, log) != 0) return 7;

    log("done");
    return 0;
}
