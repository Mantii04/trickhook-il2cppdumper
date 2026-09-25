using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Il2CppDumper
{
    /// <summary>
    /// Desempacota o protector ELF usado pelo Free Fire (com.dts.freefireth /
    /// com.dts.freefiremax) e por outros alvos empacotados com o mesmo stub.
    ///
    /// O stub e anexado no fim do .so (varios PT_LOAD apontando pro mesmo file
    /// offset) e roda via DT_INIT. Ele exporta "stub_decrypt_elf" e carrega um
    /// descritor com magic 0x12345678. O codigo que faz a transformacao nao
    /// esta no libil2cpp: o stub chama g_acf_array[1], um import resolvido do
    /// libanort.so.
    ///
    /// Esquema completo, reversado do libanort e validado byte a byte contra
    /// dump de memoria nas duas ABIs:
    ///
    ///   K = uint32 big-endian em keyblob[12:16], onde keyblob e o base64 do
    ///       descritor+0x1a8 decodificado e XOR 0x4F. Todo o material de chave
    ///       sai desse dword: a chave XOR do bulk e (K &gt;&gt; 16) &amp; 0xFF e a chave
    ///       AES e o ASCII de "%08x%08x" % (K, K).
    ///
    ///   Regiao = a secao do descritor, comecando em (inicio &amp; ~0xFFF) + 0x2000.
    ///
    ///   Secao menor que 1 MB: XOR puro na regiao inteira, sem AES nem permuta.
    ///
    ///   Senao:
    ///     janela 0 (0x4000 bytes) = AES-128-CBC, IV fixo 02..11, em 8 blocos
    ///       independentes de 0x800 com o IV reiniciado a cada bloco;
    ///     do +0x10000 em diante = XOR de 1 byte + permutacao entre slots de
    ///       0x10000, em grupos de 8 janelas de 0x4000 (algo 1), ou XOR puro
    ///       sem permutacao (algo 2, descritor+0x188).
    ///
    /// O descritor carrega em +0x20 o CRC32 da secao em claro, entao o
    /// resultado se verifica sozinho.
    /// </summary>
    public static class FFProtector
    {
        public const uint Magic = 0x12345678;

        /// Setado quando o desempacotamento rodou e o CRC32 do descritor
        /// fechou. A partir dai o aviso de "file may be protected" do upstream
        /// so confunde: a protecao ja foi tratada.
        public static bool Handled;

        /// Constante do packer que ofusca os parametros do descritor. Ela
        /// transforma o blob de chave em big-endian 0x20240829 (a data de build
        /// do packer) seguido de dois 1s - e a unica das 256 candidatas que faz
        /// isso, identicamente, em binarios com chaves diferentes.
        private const byte ObfuscationConstant = 0x4F;

        private const int WindowSize = 0x4000;
        private const int SlotStride = 0x10000;
        private const int FirstWindowPhase = 0x2000;

        /// Abaixo disso o packer nem usa AES nem permuta: XOR puro na regiao.
        private const long SmallSectionLimit = 0x100000;

        private const int KeyByteOffset = 0x186;   // chave XOR, ofuscada
        private const int AlgoOffset = 0x188;
        private const int KeyBlobOffset = 0x1a8;   // base64 com o material de chave

        /// Chave XOR usada quando o byte correspondente de K e zero.
        private const byte FallbackXorKey = 0x87;

        private const int Window0ChunkSize = 0x800;
        private static readonly byte[] Window0Iv =
        {
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11
        };

        /// Deslocamento, em slots de 0x10000, da janela de ORIGEM em relacao a
        /// janela de DESTINO, indexado por (indice_da_janela % 8). Equivale a
        /// permutar cada grupo de 8 janelas consecutivas por
        /// sigma = [4, 0, 6, 2, 1, 3, 5, 7].
        private static readonly int[] SlotDelta = { -1, 0, 4, -1, 4, -1, -3, -2 };

        public sealed class Descriptor
        {
            public long FilePosition;
            public string Name;
            public uint Offset;
            public uint VirtualAddress;
            public uint Size;
            public uint Checksum;
            public uint FirstLoadFileSize;
            public uint Kind;
            public uint Algo;

            public override string ToString() =>
                $"{Name} offset=0x{Offset:x} vaddr=0x{VirtualAddress:x} size=0x{Size:x}";
        }

        public sealed class Result
        {
            public bool Detected;
            public bool Unpacked;
            public Descriptor Descriptor;
            public byte Key;
            public string KeySource = "";
            public uint AesSeed;
            public string Window0Method = "not attempted";
            public int WindowsTotal;
            public int WindowsRecovered;
            public int WindowsSkipped;
            public bool ChecksumVerified;
            public uint ExpectedCrc;
            public uint ActualCrc;
            public long BytesUnrecovered;
            public string Window0PatchFrom;
            public byte[] Data;
        }

        /// <summary>Procura o descritor do protector no arquivo inteiro.</summary>
        public static Descriptor FindDescriptor(byte[] data)
        {
            for (long i = 0; i + 0x34 <= data.Length; i += 4)
            {
                if (BitConverter.ToUInt32(data, (int)i) != Magic) continue;

                var name = ReadName(data, (int)i + 4);
                if (name == null) continue;

                var d = new Descriptor
                {
                    FilePosition = i,
                    Name = name,
                    Offset = BitConverter.ToUInt32(data, (int)i + 0x14),
                    VirtualAddress = BitConverter.ToUInt32(data, (int)i + 0x18),
                    Size = BitConverter.ToUInt32(data, (int)i + 0x1c),
                    Checksum = BitConverter.ToUInt32(data, (int)i + 0x20),
                    FirstLoadFileSize = BitConverter.ToUInt32(data, (int)i + 0x28),
                    Kind = BitConverter.ToUInt32(data, (int)i + 0x2c),
                };
                if (i + AlgoOffset + 4 <= data.Length)
                    d.Algo = BitConverter.ToUInt32(data, (int)i + AlgoOffset);

                if (d.Size == 0 || d.Offset == 0) continue;
                if ((long)d.Offset + d.Size > data.Length) continue;
                return d;
            }
            return null;
        }

        private static string ReadName(byte[] data, int at)
        {
            var sb = new StringBuilder();
            for (int k = 0; k < 16; k++)
            {
                byte b = data[at + k];
                if (b == 0) break;
                if (b < 0x20 || b > 0x7e) return null;
                sb.Append((char)b);
            }
            if (sb.Length < 2 || sb[0] != '.') return null;   // nome de secao, ex ".rodata"
            return sb.ToString();
        }

        /// <summary>
        /// Detecta e, se o conteudo estiver mesmo embaralhado, desempacota.
        /// Devolve sempre um Result; Data e o buffer a usar daqui pra frente.
        /// </summary>
        public static Result TryUnpack(byte[] data, bool enabled = true, string inputPath = null)
        {
            var r = new Result { Data = data };
            var d = FindDescriptor(data);
            if (d == null) return r;

            r.Detected = true;
            r.Descriptor = d;
            if (!enabled) return r;

            long start = d.Offset;
            long end = start + d.Size;
            var windows = EnumerateWindows(start, end);
            r.WindowsTotal = windows.Count;
            if (windows.Count == 0) return r;

            // O byte mais frequente da regiao decide SE ha o que desempacotar:
            // no texto claro de um .rodata o mais comum e 0x00 com varias vezes
            // de folga, entao o byte dominante do ciphertext e a propria chave,
            // e 0x00 significa que a secao ja esta em claro (dump de memoria).
            byte hist = MostFrequentByte(data, windows, start, end);
            if (hist == 0) return r;

            var blob = ReadKeyBlob(data, d);
            byte fromByte = KeyFromDescriptorByte(data, d);
            byte fromBlob = blob != null ? blob[13] : (byte)0;

            // Exigir que duas fontes independentes concordem evita corromper o
            // arquivo se o layout do descritor mudar num build futuro.
            byte key;
            string src;
            if (fromByte != 0 && fromByte == fromBlob) { key = fromByte; src = "descriptor"; }
            else if (fromByte != 0 && fromByte == hist) { key = fromByte; src = "descriptor + histogram"; }
            else if (fromBlob != 0 && fromBlob == hist) { key = fromBlob; src = "key blob + histogram"; }
            else if (BestByTextScore(data, windows, start, end) == hist) { key = hist; src = "histogram"; }
            else
            {
                Console.WriteLine("WARNING: packed section detected but the key could not be confirmed; leaving it alone.");
                return r;
            }
            if (key == 0) key = FallbackXorKey;

            r.Key = key;
            r.KeySource = src;

            var outBuf = (byte[])data.Clone();

            if (d.Size < SmallSectionLimit)
            {
                // Secao pequena: o packer so faz XOR, sem AES e sem permuta.
                for (long i = windows[0].start; i < end; i++)
                    outBuf[i] = (byte)(data[i] ^ key);
                r.WindowsRecovered = windows.Count;
                r.Window0Method = "n/a (small section, plain XOR)";
            }
            else
            {
                // Janela 0: AES-128-CBC com a chave derivada de K.
                long w0 = windows[0].start;
                int w0Len = (int)Math.Min(WindowSize, end - w0);
                uint seed = blob != null
                    ? (uint)((blob[12] << 24) | (blob[13] << 16) | (blob[14] << 8) | blob[15])
                    : 0u;

                if (seed != 0 && TryDecryptWindow0(data, outBuf, w0, w0Len, seed))
                {
                    r.AesSeed = seed;
                    r.Window0Method = "AES-128-CBC";
                    r.WindowsRecovered++;
                }
                else
                {
                    r.Window0Method = "failed";
                    r.WindowsSkipped++;
                    r.BytesUnrecovered += w0Len;
                }

                // Resto: XOR + permutacao entre slots (algo 1) ou XOR puro (algo 2).
                bool permute = d.Algo != 2;
                int n = windows.Count;
                int lastGroupStart = 2 + 8 * ((n - 2) / 8);

                foreach (var (index, dst) in windows)
                {
                    if (index == 0) continue;   // ja tratada acima

                    long delta = (!permute || index >= lastGroupStart)
                        ? 0
                        : (long)SlotDelta[index % SlotDelta.Length] * SlotStride;
                    long srcPos = dst + delta;

                    // A ULTIMA janela nao e cortada em 0x4000: ela vai ate o fim
                    // da secao. No build arm32 isso e 0x9FEC em vez de 0x4000.
                    int len = (int)(index == n - 1 ? end - dst : Math.Min(WindowSize, end - dst));

                    if (srcPos < start || srcPos + len > end)
                    {
                        r.WindowsSkipped++;
                        r.BytesUnrecovered += len;
                        continue;
                    }
                    for (int i = 0; i < len; i++)
                        outBuf[dst + i] = (byte)(data[srcPos + i] ^ key);
                    r.WindowsRecovered++;
                }
            }

            // descritor+0x20 e o CRC32 da secao em claro, entao da pra conferir
            // o resultado sem precisar de um dump de memoria pra comparar.
            r.ExpectedCrc = d.Checksum;
            r.ActualCrc = Crc32(outBuf, start, end - start);
            r.ChecksumVerified = r.ActualCrc == r.ExpectedCrc;

            // Rede de seguranca: se a cifra da janela 0 mudar num build futuro,
            // um sidecar capturado de dump de memoria ainda resolve.
            if (!r.ChecksumVerified &&
                FFWindow0Patch.TryApply(outBuf, d.Checksum, inputPath, out var patchFrom))
            {
                r.ActualCrc = Crc32(outBuf, start, end - start);
                r.ChecksumVerified = r.ActualCrc == r.ExpectedCrc;
                if (r.ChecksumVerified)
                {
                    r.Window0PatchFrom = patchFrom;
                    r.BytesUnrecovered = 0;
                }
            }

            r.Unpacked = true;
            r.Data = outBuf;
            return r;
        }

        /// Janela 0: AES-128-CBC em blocos independentes de 0x800, IV fixo
        /// reiniciado a cada bloco, sem padding.
        private static bool TryDecryptWindow0(byte[] src, byte[] dst, long offset, int length, uint k)
        {
            try
            {
                if (length < Window0ChunkSize || offset + length > src.Length) return false;
                var key = Encoding.ASCII.GetBytes($"{k:x8}{k:x8}");
                if (key.Length != 16) return false;

                using var aes = Aes.Create();
                aes.Key = key;
                var chunk = new byte[Window0ChunkSize];
                for (int off = 0; off + Window0ChunkSize <= length; off += Window0ChunkSize)
                {
                    Buffer.BlockCopy(src, (int)offset + off, chunk, 0, Window0ChunkSize);
                    var plain = aes.DecryptCbc(chunk, Window0Iv, PaddingMode.None);
                    Buffer.BlockCopy(plain, 0, dst, (int)offset + off, Window0ChunkSize);
                }
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        /// Blob base64 do descritor, decodificado e desofuscado. Contem a data de
        /// build do packer, dois 1s e o material de chave.
        private static byte[] ReadKeyBlob(byte[] data, Descriptor d)
        {
            long at = d.FilePosition + KeyBlobOffset;
            if (at < 0 || at + 28 > data.Length) return null;

            var sb = new StringBuilder();
            for (long i = at; i < data.Length && i < at + 64; i++)
            {
                byte b = data[i];
                if (b == 0) break;
                if (b < 0x20 || b > 0x7e) return null;
                sb.Append((char)b);
            }
            try
            {
                var raw = Convert.FromBase64String(sb.ToString());
                if (raw.Length < 16) return null;
                for (int i = 0; i < raw.Length; i++) raw[i] ^= ObfuscationConstant;
                if (raw[0] != 0x20) return null;   // data de build, sempre 20xx
                return raw;
            }
            catch (FormatException)
            {
                return null;
            }
        }

        /// Chave XOR guardada como byte solto no descritor, ofuscada com 0x4F.
        private static byte KeyFromDescriptorByte(byte[] data, Descriptor d)
        {
            long at = d.FilePosition + KeyByteOffset;
            if (at < 0 || at >= data.Length) return 0;
            return (byte)(data[at] ^ ObfuscationConstant);
        }

        private static List<(int index, long start)> EnumerateWindows(long sectionStart, long sectionEnd)
        {
            var list = new List<(int, long)>();
            long first = (sectionStart & ~0xfffL) + FirstWindowPhase;
            int i = 0;
            for (long w = first; w < sectionEnd; w += SlotStride, i++)
                list.Add((i, w));
            return list;
        }

        /// Byte mais frequente nas janelas de origem da regiao empacotada.
        private static byte MostFrequentByte(byte[] data, List<(int index, long start)> windows,
                                             long start, long end)
        {
            var hist = new long[256];
            foreach (var (index, dst) in windows)
            {
                long src = dst + (long)SlotDelta[index % SlotDelta.Length] * SlotStride;
                if (src < start) continue;
                long len = Math.Min(WindowSize, end - src);
                for (long i = 0; i < len; i++) hist[data[src + i]]++;
            }
            byte best = 0;
            for (int i = 1; i < 256; i++) if (hist[i] > hist[best]) best = (byte)i;
            return best;
        }

        /// Chave que maximiza NUL*4 + ASCII imprimivel, amostrando o inicio das janelas.
        private static byte BestByTextScore(byte[] data, List<(int index, long start)> windows,
                                            long start, long end)
        {
            const int Sample = 512;
            byte best = 0;
            long bestScore = -1;
            for (int k = 0; k < 256; k++)
            {
                long score = 0;
                foreach (var (index, dst) in windows)
                {
                    long src = dst + (long)SlotDelta[index % SlotDelta.Length] * SlotStride;
                    if (src < start || src + Sample > end) continue;
                    for (int i = 0; i < Sample; i++)
                    {
                        byte v = (byte)(data[src + i] ^ (byte)k);
                        if (v == 0) score += 4;
                        else if (v >= 0x20 && v <= 0x7e) score++;
                    }
                }
                if (score > bestScore) { bestScore = score; best = (byte)k; }
            }
            return best;
        }

        private static readonly uint[] CrcTable = BuildCrcTable();

        private static uint[] BuildCrcTable()
        {
            var t = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
                t[i] = c;
            }
            return t;
        }

        private static uint Crc32(byte[] data, long offset, long length)
        {
            uint c = 0xFFFFFFFFu;
            for (long i = 0; i < length; i++)
                c = CrcTable[(c ^ data[offset + i]) & 0xFF] ^ (c >> 8);
            return c ^ 0xFFFFFFFFu;
        }

        public static void Report(Result r)
        {
            if (!r.Detected) return;
            Console.WriteLine($"Detected packed ELF (stub_decrypt_elf): {r.Descriptor}");
            if (!r.Unpacked)
            {
                Console.WriteLine("  Section content already looks unpacked, leaving it alone.");
                return;
            }
            Console.WriteLine($"  Unpacked with key 0x{r.Key:X2} (from {r.KeySource}), " +
                              $"window 0 via {r.Window0Method}" +
                              (r.AesSeed != 0 ? $" seed 0x{r.AesSeed:x8}" : "") +
                              $": {r.WindowsRecovered}/{r.WindowsTotal} windows recovered");
            if (r.Window0PatchFrom != null)
                Console.WriteLine($"  Window 0 restored from {r.Window0PatchFrom}");
            if (r.ChecksumVerified)
            {
                Console.WriteLine($"  CRC32 matches the descriptor (0x{r.ExpectedCrc:X8}) - section is byte-exact.");
            }
            else
            {
                Console.WriteLine($"  CRC32 0x{r.ActualCrc:X8} != descriptor 0x{r.ExpectedCrc:X8}; " +
                                  $"{r.BytesUnrecovered} byte(s) could not be recovered.");
                Console.WriteLine("  Dump the library from memory instead (see tools/ffdump.py), or capture " +
                                  "window 0 once with tools/ffwindow0.py.");
            }
        }
    }
}
