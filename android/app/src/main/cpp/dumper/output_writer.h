#pragma once
#include "common.h"
#include "metadata.h"
#include "il2cpp_binary.h"
#include "type_resolver.h"

int write_dump_cs(const Metadata& m, const Il2CppBinary& bin, const std::string& out_path, const LogFn& log);
int write_stringliteral_json(const Metadata& m, const std::string& out_path, const LogFn& log);
int write_script_json(const Metadata& m, const Il2CppBinary& bin, const std::string& out_path, const LogFn& log);
int write_il2cpp_h(const std::string& out_path, const LogFn& log);
