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

    std::string dump_path = out_dir + "/dump.cs";
    if (write_dump_cs(md, dump_path, log) != 0) return 7;

    log("done");
    return 0;
}
