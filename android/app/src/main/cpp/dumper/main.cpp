#include "main.h"
#include "metadata.h"
#include "il2cpp_binary.h"
#include "output_writer.h"
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
    Il2CppBinary bin;
    if (!bin.load(so_path, log)) return 2;

    log("loading global-metadata.dat…");
    auto meta = read_file(meta_path, log);
    if (meta.empty()) return 3;
    log("  " + std::to_string(meta.size() / 1024 / 1024) + " MB");

    Metadata md;
    if (!md.parse(meta.data(), meta.size(), log)) return 4;

    log("finding registrations…");
    if (!bin.findRegistrations(md, log)) {
        log("registration scan failed — cannot resolve addresses or types");
        // fall through: still try to write dump.cs without types
    } else {
        if (!bin.parseRegistrations(md, log)) {
            log("registration parse failed");
        } else {
            log("registrations parsed OK");
        }
    }

    write_dump_cs(md, bin, out_dir + "/dump.cs", log);
    write_stringliteral_json(md, out_dir + "/stringliteral.json", log);
    write_script_json(md, bin, out_dir + "/script.json", log);
    write_il2cpp_h(out_dir + "/il2cpp.h", log);

    log("done");
    return 0;
}
