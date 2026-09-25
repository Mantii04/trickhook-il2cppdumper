cmake_minimum_required(VERSION 3.22.1)
project(il2cppdumper C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(il2cppdumper SHARED
    jni_bridge.cpp
    dumper/main.cpp
    dumper/elf_parser.cpp
    dumper/ff_protector.cpp
    dumper/metadata.cpp
    dumper/output_writer.cpp
    dumper/il2cpp_binary.cpp
    dumper/type_resolver.cpp
    dumper/aes.c
)

target_compile_options(il2cppdumper PRIVATE -O2 -fno-exceptions -fno-rtti -Wall)
target_link_libraries(il2cppdumper PRIVATE log android)
