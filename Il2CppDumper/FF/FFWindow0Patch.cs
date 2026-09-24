using System;
using System.IO;

namespace Il2CppDumper
{
    /// <summary>
    /// A primeira janela da secao empacotada (0x4000 bytes) usa uma cifra de
    /// verdade, com chave por binario, implementada em libanort.so. O keystream
    /// tem entropia 7.99, nao tem periodo, e os keystreams das duas ABIs sao
    /// independentes entre si - ou seja, nao da pra inverter offline a partir do
    /// arquivo. Nenhuma das ~250 mil chaves candidatas extraidas do descritor e
    /// do blob do stub funciona com AES (ECB/CBC/CTR), RC4 ou ChaCha.
    ///
    /// Como a janela e pequena e fixa por build, a saida pra ter dump 100%
    /// completo so do APK e capturar esses 16 KB uma vez de um dump de memoria
    /// e guardar num sidecar. O sidecar e indexado pelo CRC32 da secao em claro,
    /// que o proprio descritor carrega em +0x20, entao ele so e aplicado no
    /// build certo e o resultado e verificavel: depois de aplicar, o CRC da
    /// secao tem que fechar com o do descritor.
    ///
    /// Gere um sidecar com tools/ffwindow0.py.
    /// </summary>
    public static class FFWindow0Patch
    {
        public const uint Magic = 0x30_57_46_46;   // "FFW0"
        public const int HeaderSize = 20;
        public const string PatchDirName = "ffpatches";

        /// <summary>
        /// Procura um sidecar que case com esta secao e aplica. Devolve true se
        /// aplicou. Nao valida o CRC aqui - quem chama recalcula e confere.
        /// </summary>
        public static bool TryApply(byte[] image, uint sectionCrc, string inputPath, out string appliedFrom)
        {
            appliedFrom = null;
            foreach (var candidate in Candidates(sectionCrc, inputPath))
            {
                if (!File.Exists(candidate)) continue;
                try
                {
                    var blob = File.ReadAllBytes(candidate);
                    if (blob.Length < HeaderSize) continue;
                    if (BitConverter.ToUInt32(blob, 0) != Magic) continue;
                    if (BitConverter.ToUInt32(blob, 4) != 1) continue;              // versao
                    if (BitConverter.ToUInt32(blob, 8) != sectionCrc) continue;     // build errado
                    var offset = BitConverter.ToUInt32(blob, 12);
                    var length = BitConverter.ToUInt32(blob, 16);
                    if (blob.Length < HeaderSize + length) continue;
                    if (offset + (long)length > image.Length) continue;

                    Buffer.BlockCopy(blob, HeaderSize, image, (int)offset, (int)length);
                    appliedFrom = candidate;
                    return true;
                }
                catch (IOException)
                {
                    // sidecar ilegivel: segue sem ele
                }
            }
            return false;
        }

        private static System.Collections.Generic.IEnumerable<string> Candidates(uint sectionCrc, string inputPath)
        {
            var name = $"{sectionCrc:x8}.w0";

            if (!string.IsNullOrEmpty(inputPath))
            {
                yield return inputPath + ".w0";
                var dir = Path.GetDirectoryName(Path.GetFullPath(inputPath));
                if (!string.IsNullOrEmpty(dir))
                {
                    yield return Path.Combine(dir, name);
                    yield return Path.Combine(dir, PatchDirName, name);
                }
            }

            var exeDir = AppDomain.CurrentDomain.BaseDirectory;
            if (!string.IsNullOrEmpty(exeDir))
            {
                yield return Path.Combine(exeDir, name);
                yield return Path.Combine(exeDir, PatchDirName, name);
            }
        }
    }
}
