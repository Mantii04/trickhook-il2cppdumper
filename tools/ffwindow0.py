#!/usr/bin/env python3
"""Extrai o conteudo em claro da janela 0 de um dump de memoria e grava um
sidecar .w0 que o Il2CppDumper aplica depois em cima do .so do APK.

A janela 0 e os primeiros 0x4000 bytes da regiao empacotada e usa uma cifra que
nao da pra inverter offline. Ela e fixa por build, entao basta capturar uma vez.

Uso tipico:
    python tools/ffwindow0.py --disk libil2cpp.so --mem libil2cpp_memdump.so --out ffpatches/

O sidecar e indexado pelo CRC32 da secao em claro, que vem do proprio descritor
do protector, entao ele nunca e aplicado no build errado.
"""
import argparse, os, struct, sys, zlib

MAGIC = 0x30574646          # "FFW0"
VERSION = 1
WINDOW = 0x4000
PHASE = 0x2000

def find_descriptor(data):
    pat = struct.pack("<I", 0x12345678)
    pos = data.find(pat)
    while pos != -1:
        if pos + 0x34 <= len(data):
            name = data[pos + 4:pos + 0x14].split(b"\0")[0]
            if name.startswith(b".") and all(0x20 <= c <= 0x7e for c in name):
                off, va, size, crc = struct.unpack_from("<IIII", data, pos + 0x14)
                if size and off and off + size <= len(data):
                    return dict(pos=pos, name=name.decode(), offset=off,
                                vaddr=va, size=size, crc=crc)
        pos = data.find(pat, pos + 4)
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--disk", required=True, help="libil2cpp.so do APK (empacotado)")
    ap.add_argument("--mem", required=True, help="dump de memoria (ver ffdump.py)")
    ap.add_argument("--out", required=True, help="diretorio de saida pros sidecars")
    a = ap.parse_args()

    disk = open(a.disk, "rb").read()
    mem = open(a.mem, "rb").read()

    d = find_descriptor(disk)
    if not d:
        sys.exit("nao achei o descritor do protector (magic 0x12345678) no .so de disco")
    print(f"descritor @ {d['pos']:#x}: {d['name']} offset={d['offset']:#x} "
          f"size={d['size']:#x} crc32={d['crc']:#010x}")

    w0 = (d["offset"] & ~0xfff) + PHASE
    ln = min(WINDOW, d["offset"] + d["size"] - w0)
    if w0 + ln > len(mem):
        sys.exit(f"o dump de memoria e curto demais: precisa de {w0+ln} bytes, tem {len(mem)}")

    # No dump de memoria a secao ja esta em claro. Confere pelo CRC do descritor
    # antes de extrair, senao o sidecar nasce errado.
    section = mem[d["offset"]:d["offset"] + d["size"]]
    crc = zlib.crc32(section) & 0xffffffff
    if crc != d["crc"]:
        sys.exit(f"CRC32 da secao no dump de memoria ({crc:#010x}) nao bate com o "
                 f"descritor ({d['crc']:#010x}). O dump nao corresponde a este .so, "
                 f"ou nao esta descriptografado.")
    print(f"CRC32 do dump de memoria confere: {crc:#010x}")

    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, f"{d['crc']:08x}.w0")
    with open(path, "wb") as f:
        f.write(struct.pack("<IIIII", MAGIC, VERSION, d["crc"], w0, ln))
        f.write(mem[w0:w0 + ln])
    print(f"gravado {path} ({os.path.getsize(path)} bytes) "
          f"- janela 0 em {w0:#x}, {ln} bytes")
    print("\nPonha esse arquivo em ffpatches/ ao lado do Il2CppDumper.exe, ou do .so de entrada.")

main()
