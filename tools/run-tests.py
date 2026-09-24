import json, subprocess, sys, os, shutil, io
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
D = r"C:\Users\danie\Desktop\dump"
MD32 = D + r"\com.dts.freefireth-cfc67000-d32bd000.dat"
MD64 = D + r"\arm64\global-metadata.dat"
TESTS = [
    ("ARM32 disco (APK)",  D + r"\libil2cpp.so",                  MD32, "",           False),
    ("ARM64 disco (APK)",  D + r"\arm64\libil2cpp.so",            MD64, "",           False),
    ("ARM32 memoria",      D + r"\libil2cpp_memdump.so",          MD32, "c9976000",   True),
    ("ARM64 memoria",      D + r"\arm64\libil2cpp_memdump.so",    MD64, "74e2814000", True),
]
for name, so, md, base, force in TESTS:
    out = os.path.join(D, "test_" + name.split()[0] + "_" + name.split()[1].strip("()"))
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out, exist_ok=True)
    c = json.load(open("config.json"))
    c.update(ForceDump=force, ImageBase=base, RequireAnyKey=False,
             GenerateDummyDll=False, GenerateStruct=False)
    json.dump(c, open("config.json", "w"), indent=2)
    r = subprocess.run(["./Il2CppDumper.exe", so, md, out], capture_output=True,
                       text=True, encoding="utf-8", errors="replace", input="0\n")
    so_out = r.stdout or ""
    print(f"\n{'='*66}\n### {name}\n{'='*66}")
    for ln in so_out.splitlines():
        if any(k in ln for k in ("layout:", "Detected packed", "Unpacked", "CRC32",
                                 "already looks", "Window 0", "WARNING", "ERROR")):
            print("  " + ln.strip())
    f = os.path.join(out, "dump.cs")
    if os.path.exists(f):
        t = io.open(f, encoding="utf-8", errors="replace").read()
        print(f"  --> tipos={t.count('TypeDefIndex:')}  metodos={t.count('RVA: 0x')}  "
              f"erros={so_out.count('ERROR: Some errors in dumping')}  bytes={len(t)}")
    else:
        print("  --> dump.cs AUSENTE")
