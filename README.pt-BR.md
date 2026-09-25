# Il2CppDumper — suporte a Free Fire (armeabi-v7a + arm64-v8a)

Fork do [Perfare/Il2CppDumper](https://github.com/Perfare/Il2CppDumper) (commit base `4741d46`) que
dumpa o `com.dts.freefireth` / `com.dts.freefiremax` **completo, nas duas ABIs, direto do APK** — sem
patch manual e sem precisar de dump de memória a cada rodada.

O upstream quebra nesse alvo por dois motivos independentes. Os dois estão resolvidos por *detecção*,
não por hardcode do jogo, então o fork continua funcionando em jogo Unity normal e deve aguentar
atualização.

🇺🇸 [README.md](README.md) · Upstream: [README.upstream.md](README.upstream.md)

## Download

Todo push gera três pacotes no CI — pegue na aba **Actions**, na run mais recente, em *Artifacts*:

| artefato | o que é |
|---|---|
| `Il2CppDumper-win-x64-standalone` | `.exe` único, ~68 MB, roda no Windows **sem .NET instalado** |
| `Il2CppDumper-win-x64` | `.exe` único, ~1 MB, precisa do runtime .NET 8 |
| `Il2CppDumper-portable` | `dotnet Il2CppDumper.dll`, qualquer SO com .NET 8 |

Cada pacote já vem com `config.json`, o `tools/` e os READMEs.
Subir uma tag `v*` também publica tudo como Release do GitHub.

## Resultado

Build OB do Free Fire, metadata v31. `dump.cs` comparado linha a linha com o gerado a partir de um
dump de memória, ignorando os comentários de endereço (que mudam por definição):

| entrada | janelas recuperadas | CRC32 | tipos | métodos | erros | idêntico ao dump de memória |
|---|---|---|---|---|---|---|
| `.so` arm64 do APK | 128/128 | ✅ bate | 43627 | 403993 | 0 | **1650704 / 1650704 = 100,0000%** |
| `.so` armeabi-v7a do APK | 126/126 | ✅ bate | 43627 | 403993 | 0 | **1650704 / 1650704 = 100,0000%** |
| qualquer um, da memória | — | — | 43627 | 403993 | 0 | — |

Não precisa de mais nada além do APK — sem dump de memória, sem dado capturado, sem preparo por build.

O CRC32 não é conferência nossa: o descritor do próprio packer carrega o CRC32 da seção em claro, então
ele batendo é prova de que o `.rodata` desempacotado é byte a byte igual ao que o loader produz em
runtime.

Rodada arm64 completa a partir do APK: ~56 s, `dump.cs` 79 MB, `il2cpp.h` 131 MB, `script.json` 174 MB,
57 dummy DLLs.

---

## O que o upstream faz nesse alvo

```
ERROR: This file may be protected.
CodeRegistration : a1b9ff4
MetadataRegistration : a28fc80
System.ArgumentOutOfRangeException: Number was less than the array's lower bound
   at Il2CppDumper.Il2Cpp.Init(...) in Il2Cpp.cs:line 257
```

Os endereços que ele acha estão **certos**. O crash é depois, em
`Array.Copy(rgctxs, rgctxRange.range.start, ...)`, porque `range.start` lê `0x95959595` =
−1785358955 de bytes ainda empacotados.

---

## Problema 1 — o `.so` do disco está empacotado

Tem um stub anexado ao ELF — um ELF embutido e stripado chamado `libunpacker_16k_align.so`. Vários
`PT_LOAD` apontam pro mesmo file offset, o `DT_INIT` encadeia pra dentro dele, e ele exporta
`stub_decrypt_elf`, `stub_mmap`, `stub_dlsym`, `g_acf_array`, além de `ELF_HOOK_il2cpp_init`,
`ELF_HOOK_MetadataCache_Register`, `ELF_HOOK_InitializeAllMethodMetadata`, `ELF_HOOK_JNI_OnLoad`.
A transformação em si **não** está no `libil2cpp.so`: o stub chama `g_acf_array[1](...)`, um import
indefinido resolvido a partir do `libanort.so`.

O stub carrega um descritor com magic `0x12345678` que diz qual seção está empacotada:

```
+0x00  u32   0x12345678
+0x04  char  nome da seção[16]       ".rodata"
+0x14  u32   file offset
+0x18  u32   vaddr
+0x1c  u32   size
+0x20  u32   CRC32 da seção em claro
+0x28  u32   p_filesz do LOAD[1]
+0x2c  u32   p_flags do PT_LOAD que o contém
+0x186 u8    chave XOR da seção, ofuscada com 0x4F
+0x188 u32   id do algoritmo (1)
+0x18c u32   flags de feature (3)
+0x1a8 char  blob de chave em base64
```

### O esquema

Medido por diff do arquivo de disco contra dump de memória, nas duas ABIs. Só o `.rodata` é alterado —
`.text`, `.data`, `.data.rel.ro`, `.got`, `.dynstr` e `.gcc_except_table` saem byte a byte iguais.

- **Janelas** de `0x4000` bytes, uma a cada `0x10000`, a primeira em `(início_da_seção & ~0xFFF) + 0x2000`.
- Cada janela é **XOR com uma chave de 1 byte** *e* **permutada** entre slots de `0x10000`:

  ```
  janela_origem(i) = i + D8[i % 8]          D8 = [-1, 0, +4, -1, +4, -1, -3, -2]
  ```

  Ou, de forma mais limpa: as janelas são agrupadas de 8 em 8 começando em `i % 8 == 2` (`{2..9}`,
  `{10..17}`, …), e dentro de cada grupo a permutação é `sigma = [4, 0, 6, 2, 1, 3, 5, 7]`, com
  estrutura de ciclos `(0 4 1)(2 6 5 3)(7)`.

- O **grupo parcial do fim** não é permutado — só XOR no lugar. Começa em `2 + 8 * ((N - 2) / 8)`, que
  dá janela 122 nos dois binários.
- A **última janela não é cortada** em `0x4000`; ela vai até o fim da seção. No arm32 isso é `0x9FEC`,
  e sem isso sobram ~24 KB empacotados.
- A **janela 0** não pertence a grupo nenhum e usa outra cifra — veja abaixo.

`D8` é byte a byte igual em armeabi-v7a e arm64-v8a mesmo com as chaves sendo diferentes, então não
depende nem de chave nem de conteúdo. Não existe tabela dela em lugar nenhum do arquivo.

### A chave

Guardada duas vezes no descritor, ofuscada com a constante `0x4F`:

```
descritor+0x186      byte solto, XOR 0x4F
  arm32: 0x25 ^ 0x4F = 0x6A      arm64: 0xAF ^ 0x4F = 0xE0

descritor+0x1a8      string base64; decodifica e faz XOR 0x4F em cada byte
  arm32: "b2tHZk9PT05PT09OiiXHwIolx8E="
  arm64: "b2tHZk9PT05PT09OhK8JSoSvCUs="
  ->  20 24 08 29 | 00 00 00 01 | 00 00 00 01 | .. CHAVE .. .. | .. CHAVE .. ..
      ^^^^^^^^^^^ data de build do packer, big-endian "20240829"
  byte[13] é a chave da seção.
```

`0x4F` é a única das 256 candidatas que transforma o blob em `0x20240829` seguido de dois `1`s
big-endian, identicamente em dois binários empacotados de forma independente e com chaves diferentes.

Todo o material de chave é um dword só. Com `K` = o `uint32` big-endian em `keyblob[12:16]`, a chave
XOR do bulk é `(K >> 16) & 0xFF` — que é exatamente o byte do `descritor+0x186` — e a chave AES da
janela 0 também sai de `K` (abaixo). O fork cruza as duas.

O fork ainda cruza com um terceiro sinal independente: o **byte mais frequente** da região empacotada
também entrega a chave (o `.rodata` em claro é dominado por `0x00`, com 4× de folga pro segundo).
Histograma dando `0x00` significa que a seção já está em claro — é assim que um dump de memória passa
batido. Ele só desempacota quando duas fontes independentes concordam.

Implementado em [`Il2CppDumper/FF/FFProtector.cs`](Il2CppDumper/FF/FFProtector.cs).

### Janela 0 — AES-128-CBC

Os primeiros `0x4000` bytes da região não levam XOR nenhum. São **AES-128-CBC**, aplicados em
**8 blocos independentes de `0x800`** com o IV reiniciado a cada um:

```
chave = ASCII de "%08x%08x" % (K, K)      # 16 chars = AES-128
iv    = 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11
padding = nenhum
```

arm32 `K = 0xc56a888f` → chave `"c56a888fc56a888f"`; arm64 `K = 0xcbe04605` → chave `"cbe04605cbe04605"`.
Os dois reproduzem a janela byte a byte, 16384/16384. Decifrar com o dword vizinho do blob de chave
dá 0,39%, ou seja, acaso.

É mbedTLS dentro do `libanort.so`, alcançado pelo `g_acf_array[1]`. Passa batido por busca de
constante porque não existe instrução `AESE`/`AESD` de ARMv8 no `.text` e a S-box do AES fica gravada
com passo de 4 bytes — procurar a S-box contígua de 16 bytes não acha nada.

O `tools/ffwindow0.py` e o `FF/FFWindow0Patch.cs` continuam como rede de segurança: se um build futuro
mudar essa cifra, você captura os 16 KB uma vez de um dump de memória pra um sidecar
`ffpatches/<crc32-da-seção>.w0` e o dumper aplica sozinho. Com o caminho AES funcionando, não precisa
de sidecar nenhum.

---

## Problema 2 — `Il2CppMethodDefinition` fora do padrão

O metadata v31 do Free Fire tem `Il2CppMethodDefinition` de **40 bytes**; a v31 pede 36. Tem um `int32`
a mais entre `genericContainerIndex` e `token`. Com o stride errado o `dump.cs` vira lixo a partir do
segundo método:

```
stride 36:  m[8]=''       m[9]='mbly-CSharp'  m[10]='Update'  declType=134217728
stride 40:  m[8]='Start'  m[9]='Update'       m[10]='.ctor'   declType=4,4,4
```

O metadata é composto só de campos de 32 bits, então isso vale igual pras duas ABIs. Só essa tabela é
fora do padrão — typeDef 88, image 40, assembly 64, field 12, parameter 12, property 20, event 24 são
todas normais.

A detecção não assume nada:

1. número real de métodos = `max(typeDef.methodStart + method_count)`
2. stride = `methodsSize / esse número`
3. se bater com o esperado da versão, segue o caminho normal
4. senão, testa cada posição possível pro padding e valida contra invariantes do metadata:
   `declaringType` aponta pra typeDef dona, `token >> 24 == 0x06`, `nameIndex` dentro da tabela de
   strings, `parameterStart` em `[-1, nParams]`, `genericContainerIndex` em `[-1, nContainers)`,
   `returnParameterToken` com tag `0x08`
5. só aceita com ≥95% de confiança; abaixo disso avisa e usa o layout padrão

Implementado em [`Il2CppDumper/FF/FFMethodLayout.cs`](Il2CppDumper/FF/FFMethodLayout.cs), enganchado em
`Metadata.ReadMethodDefs()`.

> `genericContainerIndex` é o discriminador que importa. Checar só
> `nameIndex`/`declaringType`/`token` não distingue padding em `+0x8` de padding em `+0x18` — as duas
> posições deixam esses três campos alinhados por acaso. A primeira versão disso escolheu errado com
> "100% de confiança".

---

## Outras mudanças

- **`Il2Cpp.cs`** — ranges de RGCTX e entradas da tabela de métodos genéricos corrompidas são puladas
  com aviso em vez de derrubar o processo. Era esse o `ArgumentOutOfRangeException` original.
- **`Config.cs` / `Program.cs`** — `"ImageBase"` no `config.json` substitui o prompt interativo de dump
  address; `"UnpackProtected"` liga/desliga o desempacotamento.

---

## Uso

### A partir do APK

```bash
Il2CppDumper.exe libil2cpp.so global-metadata.dat out/
```

O `global-metadata.dat` do Free Fire **não** é criptografado e fica em
`split_asset_pack_install_time.apk`, em `assets/bin/Data/Managed/Metadata/`. O mesmo arquivo serve pras
duas ABIs. O `libil2cpp.so` fica em `split_config.<abi>.apk`, em `lib/<abi>/`.

> O diretório de saída precisa existir antes — o upstream cai calado no diretório do executável se não
> existir.

### Se um build futuro quebrar o desempacotador

Se o CRC32 parar de bater, capture a janela 0 uma vez de um processo vivo e o dumper aplica:

```bash
adb shell "su -c 'pidof com.dts.freefireth'"

python tools/ffdump.py --serial <serial> --pid <pid> \
    --lib "lib/arm64/libil2cpp.so" --elf libil2cpp.so --out libil2cpp_memdump.so

python tools/ffwindow0.py --disk libil2cpp.so --mem libil2cpp_memdump.so \
    --out ffpatches/
```

O `ffwindow0.py` se recusa a gravar o sidecar se o CRC32 da seção no dump de memória não bater com o do
descritor, então ele não consegue gerar um errado calado.

### Dumpando direto da memória

O `ffdump.py` deriva a base de carga por consenso contra os program headers do arquivo de disco. Isso
importa: o linker do Android deixa um mapeamento read-only do *arquivo inteiro* num endereço diferente,
que é isca. O script imprime a base real — ponha no `config.json`:

```json
{ "ForceDump": true, "ImageBase": "74e2814000" }
```

Ler 168 MB de `/proc/pid/mem` como root não disparou o anti-cheat nos testes; o que mata processo é
polling repetido, não volume. Sem garantias.

## Build

```bash
dotnet build Il2CppDumper/Il2CppDumper.csproj -c Release -f net8.0
```

Saída em `Il2CppDumper/bin/Release/net8.0/`.

## Licença e crédito

MIT, igual ao upstream. O trabalho pesado todo é do [Perfare](https://github.com/Perfare); este fork
só acrescenta os dois detectores acima, o desempacotador do protector e tratamento de erro defensivo.
