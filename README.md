# Il2CppDumper — Free Fire support (armeabi-v7a + arm64-v8a)

A fork of [Perfare/Il2CppDumper](https://github.com/Perfare/Il2CppDumper) (base commit `4741d46`)
that dumps `com.dts.freefireth` / `com.dts.freefiremax` **complete, on both ABIs, straight from the
APK** — no manual patching, no per-run memory dump.

Upstream fails on this target for two independent reasons. Both are fixed by *detection*, not by
hardcoding anything about the game, so the fork still works on ordinary Unity titles and should
survive game updates.

🇧🇷 [README.pt-BR.md](README.pt-BR.md) · Upstream: [README.upstream.md](README.upstream.md)

```
Il2CppMethodDefinition layout: non-standard: 40 bytes x 336329, 4 extra byte(s) at +0x18 (expected 36), confidence 100.0%
Detected packed ELF (stub_decrypt_elf): .rodata offset=0x194a210 vaddr=0x194a210 size=0x7f335b
  Unpacked with key 0xE0 (from descriptor): 128/128 windows recovered
  Window 0 restored from ffpatches/6876e3c7.w0
  CRC32 matches the descriptor (0x6876E3C7) - section is byte-exact.
Dumping...
Done!
```

## Download

Every push builds three packages on CI — grab one from the **Actions** tab, newest run, *Artifacts*:

| artifact | what it is |
|---|---|
| `Il2CppDumper-win-x64-standalone` | single `.exe`, ~68 MB, runs on Windows with **no .NET installed** |
| `Il2CppDumper-win-x64` | single `.exe`, ~1 MB, needs the .NET 8 runtime |
| `Il2CppDumper-portable` | `dotnet Il2CppDumper.dll`, any OS with .NET 8 |

Each package ships `config.json`, the `ffpatches/` sidecars, `tools/` and the READMEs.
Pushing a `v*` tag also publishes them as a GitHub Release.

## Results

Free Fire OB-era build, metadata v31. `dump.cs` compared line by line against the one produced from a
live memory dump, ignoring the address comments (which differ by definition):

| input | windows recovered | CRC32 | types | methods | errors | identical to memory dump |
|---|---|---|---|---|---|---|
| arm64 APK `.so` | 128/128 | ✅ match | 43627 | 403993 | 0 | **1650704 / 1650704 = 100.0000%** |
| armeabi-v7a APK `.so` | 126/126 | ✅ match | 43627 | 403993 | 0 | **1650704 / 1650704 = 100.0000%** |
| either, memory dump | n/a | n/a | 43627 | 403993 | 0 | — |

The CRC32 in the last column is not our own check — the packer's descriptor carries the CRC32 of the
plaintext section, so a match is proof the unpacked `.rodata` is byte-identical to what the loader
produces at runtime.

Full arm64 run from the APK: ~56 s, `dump.cs` 79 MB, `il2cpp.h` 131 MB, `script.json` 174 MB, 57 dummy DLLs.

---

## What upstream does on this target

```
ERROR: This file may be protected.
CodeRegistration : a1b9ff4
MetadataRegistration : a28fc80
System.ArgumentOutOfRangeException: Number was less than the array's lower bound
   at Il2CppDumper.Il2Cpp.Init(...) in Il2Cpp.cs:line 257
```

The two addresses it finds are **correct**. The crash happens later, in
`Array.Copy(rgctxs, rgctxRange.range.start, ...)`, because `range.start` reads back as `0x95959595`
= −1785358955 out of still-packed bytes.

---

## Problem 1 — the on-disk `.so` is packed

A stub is appended to the ELF — a stripped embedded ELF named `libunpacker_16k_align.so`. Several
`PT_LOAD`s map the same file offset, `DT_INIT` chains into it, and it exports `stub_decrypt_elf`,
`stub_mmap`, `stub_dlsym`, `g_acf_array`, plus `ELF_HOOK_il2cpp_init`,
`ELF_HOOK_MetadataCache_Register`, `ELF_HOOK_InitializeAllMethodMetadata`, `ELF_HOOK_JNI_OnLoad`.
The transform itself is **not** in `libil2cpp.so` — the stub calls
`g_acf_array[1](...)`, an undefined import resolved from `libanort.so`.

The stub carries a descriptor with magic `0x12345678` naming the packed section:

```
+0x00  u32   0x12345678
+0x04  char  section name[16]        ".rodata"
+0x14  u32   file offset
+0x18  u32   vaddr
+0x1c  u32   size
+0x20  u32   CRC32 of the plaintext section
+0x28  u32   p_filesz of LOAD[1]
+0x2c  u32   containing PT_LOAD's p_flags
+0x186 u8    section XOR key, obfuscated with 0x4F
+0x188 u32   algorithm id (1)
+0x18c u32   feature flags (3)
+0x1a8 char  base64 key blob
```

### The scheme

Measured by diffing the on-disk file against a live memory dump, on both ABIs. Only `.rodata` is
touched — `.text`, `.data`, `.data.rel.ro`, `.got`, `.dynstr` and `.gcc_except_table` come out
byte-identical.

- **Windows** of `0x4000` bytes, one every `0x10000`, the first at `(section_start & ~0xFFF) + 0x2000`.
- Each window is **XOR'd with a one-byte key** *and* **permuted** between `0x10000` slots:

  ```
  source_window(i) = i + D8[i % 8]          D8 = [-1, 0, +4, -1, +4, -1, -3, -2]
  ```

  Equivalently: windows are grouped 8 at a time starting at `i % 8 == 2` (`{2..9}`, `{10..17}`, …),
  and inside a group the permutation is `sigma = [4, 0, 6, 2, 1, 3, 5, 7]`, cycle structure
  `(0 4 1)(2 6 5 3)(7)`.

- The **trailing partial group** is not permuted — plain XOR in place. It starts at
  `2 + 8 * ((N - 2) / 8)`, which is window 122 on both binaries.
- The **last window is not clipped** to `0x4000`; it runs to the section end. On arm32 that is
  `0x9FEC`, and missing it leaves ~24 KB packed.
- **Window 0** belongs to no group and uses a different cipher — see below.

`D8` is byte-for-byte identical on armeabi-v7a and arm64-v8a even though the keys differ, so it is
neither key- nor content-derived. There is no table for it anywhere in the file.

### The key

Stored twice in the descriptor, obfuscated with the constant `0x4F`:

```
descriptor+0x186      one byte, XOR 0x4F
  arm32: 0x25 ^ 0x4F = 0x6A      arm64: 0xAF ^ 0x4F = 0xE0

descriptor+0x1a8      base64 string, decode then XOR every byte with 0x4F
  arm32: "b2tHZk9PT05PT09OiiXHwIolx8E="
  arm64: "b2tHZk9PT05PT09OhK8JSoSvCUs="
  ->  20 24 08 29 | 00 00 00 01 | 00 00 00 01 | .. KEY .. .. | .. KEY .. ..
      ^^^^^^^^^^^ packer build date, big-endian "20240829"
  byte[13] is the section key.
```

`0x4F` is the only one of 256 candidates that turns the blob into `0x20240829` followed by two
big-endian `1`s, identically in two independently packed binaries whose section keys differ.

The fork cross-checks against a third, independent signal: the **most frequent byte** of the packed
region also yields the key (plaintext `.rodata` is dominated by `0x00`, by 4× over the runner-up).
A `0x00` histogram result means the section is already plaintext — that is how a memory dump passes
through untouched. It only unpacks when two independent sources agree.

Implemented in [`Il2CppDumper/FF/FFProtector.cs`](Il2CppDumper/FF/FFProtector.cs).

### Window 0 — the one piece that is not offline-invertible

The first `0x4000` bytes of the packed region use a real cipher, keyed per binary, implemented in
`libanort.so`. What was measured:

- keystream entropy **7.989**, no period at 16/32/…/8192
- the arm32 and arm64 keystreams agree on 63/16384 bytes — exactly chance
- **not ECB**: in arm32 the plaintext block `696e652e5061727469636c6553797374` occurs 7 times and maps
  to 7 different ciphertext blocks
- XOR-invariant preimage search over the entire file at `0x1000`/`0x400`/`0x100` granularity: 0 hits —
  the plaintext is not a permuted copy of anything in the binary
- ~250 000 candidate keys drawn from the descriptor, the stub blob and the key blob (raw, base64-decoded
  and XOR-`0x4F`, plus md5/sha256 of each) tested against AES-128/192/256 ECB/CBC/CTR and RC4: no hit

So it is captured once per build instead. `tools/ffwindow0.py` extracts those 16 KB from a memory
dump into a sidecar named after the section CRC32; the dumper picks it up automatically from
`ffpatches/` and then the descriptor CRC32 confirms the result is byte-exact. One memory dump per
game build, and every static run after that is complete.

Sidecars for the builds tested here are in
[`Il2CppDumper/bin/Release/net8.0/ffpatches/`](Il2CppDumper/bin/Release/net8.0/ffpatches).
Without a sidecar the arm64 dump is still complete (window 0 holds nothing the dumper reads there)
and the arm32 dump is short by 93 types out of 43627.

Implemented in [`Il2CppDumper/FF/FFWindow0Patch.cs`](Il2CppDumper/FF/FFWindow0Patch.cs).

---

## Problem 2 — non-standard `Il2CppMethodDefinition`

Free Fire's v31 metadata has a **40-byte** `Il2CppMethodDefinition`; v31 calls for 36. There is one
extra `int32` between `genericContainerIndex` and `token`. With the wrong stride, `dump.cs` is garbage
from the second method onward:

```
stride 36:  m[8]=''       m[9]='mbly-CSharp'  m[10]='Update'  declType=134217728
stride 40:  m[8]='Start'  m[9]='Update'       m[10]='.ctor'   declType=4,4,4
```

Metadata is all 32-bit fields, so this is ABI-independent. Only this one table is off — typeDef 88,
image 40, assembly 64, field 12, parameter 12, property 20, event 24 are all standard.

Detection assumes nothing about the game:

1. real method count = `max(typeDef.methodStart + method_count)`
2. stride = `methodsSize / that count`
3. if it matches what the version expects, take the normal path
4. otherwise brute-force the padding position, validating every candidate against metadata invariants:
   `declaringType` points at the owning typeDef, `token >> 24 == 0x06`, `nameIndex` inside the string
   table, `parameterStart` in `[-1, nParams]`, `genericContainerIndex` in `[-1, nContainers)`,
   `returnParameterToken` tagged `0x08`
5. accept only at ≥95 % confidence; below that, warn and fall back

Implemented in [`Il2CppDumper/FF/FFMethodLayout.cs`](Il2CppDumper/FF/FFMethodLayout.cs), hooked from
`Metadata.ReadMethodDefs()`.

> `genericContainerIndex` is the invariant that matters. Checking only
> `nameIndex`/`declaringType`/`token` does not separate padding at `+0x8` from padding at `+0x18` —
> both leave those three fields aligned by coincidence. The first version of this picked the wrong one
> at "100 % confidence".

---

## Other changes

- **`Il2Cpp.cs`** — corrupt RGCTX ranges and generic-method-table entries are skipped with a warning
  instead of taking down the process. That was the original `ArgumentOutOfRangeException`.
- **`Config.cs` / `Program.cs`** — `"ImageBase"` in `config.json` replaces the interactive dump-address
  prompt; `"UnpackProtected"` toggles unpacking.

---

## Usage

### From the APK

```bash
Il2CppDumper.exe libil2cpp.so global-metadata.dat out/
```

Free Fire's `global-metadata.dat` is **not** encrypted and lives in
`split_asset_pack_install_time.apk`, at `assets/bin/Data/Managed/Metadata/`. The same file serves both
ABIs. `libil2cpp.so` is in `split_config.<abi>.apk` under `lib/<abi>/`.

> The output directory must already exist — upstream silently falls back to the executable's own
> directory if it does not.

### Capturing window 0 for a new build (once)

With the game running and root on the device:

```bash
adb shell "su -c 'pidof com.dts.freefireth'"

python tools/ffdump.py --serial <serial> --pid <pid> \
    --lib "lib/arm64/libil2cpp.so" --elf libil2cpp.so --out libil2cpp_memdump.so

python tools/ffwindow0.py --disk libil2cpp.so --mem libil2cpp_memdump.so \
    --out Il2CppDumper/bin/Release/net8.0/ffpatches/
```

`ffwindow0.py` refuses to write a sidecar unless the memory dump's section CRC32 matches the
descriptor, so it cannot silently produce a wrong one.

### Dumping from memory directly

`ffdump.py` derives the load base by consensus against the on-disk program headers. That matters:
Android's linker leaves a read-only mapping of the *whole file* at a different address, which is a
decoy. The script prints the real base — put it in `config.json`:

```json
{ "ForceDump": true, "ImageBase": "74e2814000" }
```

Reading 168 MB out of `/proc/pid/mem` as root did not trip the anti-cheat in testing; what gets
processes killed is repeated polling, not volume. Your mileage may vary.

## Build

```bash
dotnet build Il2CppDumper/Il2CppDumper.csproj -c Release -f net8.0
```

Output in `Il2CppDumper/bin/Release/net8.0/`.

## License & credit

MIT, same as upstream. All the heavy lifting is [Perfare](https://github.com/Perfare)'s; this fork
adds the two detectors above, the window-0 sidecar, and some defensive error handling.
