using System;
using System.Collections.Generic;

namespace Il2CppDumper
{
    /// <summary>
    /// Alguns jogos embaralham o layout de Il2CppMethodDefinition inserindo um
    /// campo extra no meio do struct. O Free Fire faz isso: no metadata v31 o
    /// struct tem 40 bytes em vez dos 36 que a versao pede, com um int32 a mais
    /// entre genericContainerIndex e token. Com o stride errado todo o dump.cs
    /// sai lixo a partir do segundo metodo.
    ///
    /// A deteccao aqui nao assume nada sobre o jogo: o numero real de metodos
    /// sai das proprias typeDefs (max de methodStart + method_count), o stride
    /// sai de methodsSize / esse numero, e a posicao do padding e encontrada
    /// testando cada posicao possivel e validando contra invariantes do
    /// metadata. Isso vale pra 32 e 64 bits, ja que o metadata e sempre
    /// composto de campos de 32 bits independente da ABI.
    /// </summary>
    public static class FFMethodLayout
    {
        /// Padding maximo que aceitamos antes de desistir e usar o layout padrao.
        public const int MaxPadding = 64;

        public sealed class Layout
        {
            public int Count;
            public int Stride;
            public int ExpectedSize;
            public int PadOffset;
            public int PadSize;
            public double Confidence;

            public bool IsStandard => PadSize == 0;

            public override string ToString() =>
                IsStandard
                    ? $"standard ({Stride} bytes x {Count})"
                    : $"non-standard: {Stride} bytes x {Count}, {PadSize} extra byte(s) at +0x{PadOffset:x} " +
                      $"(expected {ExpectedSize}), confidence {Confidence:P1}";
        }

        /// <summary>
        /// Numero real de metodos, derivado das typeDefs. Retorna 0 se nao der
        /// pra determinar.
        /// </summary>
        public static int CountFromTypeDefs(Il2CppTypeDefinition[] typeDefs)
        {
            int count = 0;
            foreach (var t in typeDefs)
            {
                if (t.methodStart < 0) continue;
                int end = t.methodStart + t.method_count;
                if (end > count) count = end;
            }
            return count;
        }

        /// <summary>Indice da typeDef dona de cada metodo, pra validacao.</summary>
        public static int[] BuildOwnerTable(Il2CppTypeDefinition[] typeDefs, int methodCount)
        {
            var owner = new int[methodCount];
            for (int i = 0; i < owner.Length; i++) owner[i] = -1;
            for (int t = 0; t < typeDefs.Length; t++)
            {
                var td = typeDefs[t];
                if (td.methodStart < 0) continue;
                int end = Math.Min(td.methodStart + td.method_count, methodCount);
                for (int m = td.methodStart; m < end; m++) owner[m] = t;
            }
            return owner;
        }

        /// <summary>
        /// Posicoes de padding a testar, em bytes, alinhadas em 4.
        /// </summary>
        public static IEnumerable<int> CandidateOffsets(int expectedSize)
        {
            for (int p = 0; p <= expectedSize; p += 4) yield return p;
        }

        /// <summary>
        /// Tira os bytes de padding de cada registro, produzindo um buffer no
        /// layout que o parser da versao espera.
        /// </summary>
        public static byte[] Repack(byte[] raw, int count, int stride, int expectedSize,
                                    int padOffset, int padSize)
        {
            var outBuf = new byte[(long)count * expectedSize <= int.MaxValue
                ? count * expectedSize
                : throw new InvalidOperationException("method table too large to repack")];
            int tail = expectedSize - padOffset;
            for (int i = 0; i < count; i++)
            {
                int src = i * stride;
                int dst = i * expectedSize;
                if (padOffset > 0) Buffer.BlockCopy(raw, src, outBuf, dst, padOffset);
                if (tail > 0) Buffer.BlockCopy(raw, src + padOffset + padSize, outBuf, dst + padOffset, tail);
            }
            return outBuf;
        }

        /// <summary>
        /// Indices de metodo usados pra sondar: blocos contiguos espalhados pelo
        /// array, pra nao dar sorte com uma regiao so.
        /// </summary>
        public static List<(int start, int length)> SampleBlocks(int count, int blocks = 8, int blockSize = 256)
        {
            var list = new List<(int, int)>();
            if (count <= blocks * blockSize)
            {
                list.Add((0, count));
                return list;
            }
            int step = count / blocks;
            for (int b = 0; b < blocks; b++)
            {
                int start = b * step;
                int len = Math.Min(blockSize, count - start);
                if (len > 0) list.Add((start, len));
            }
            return list;
        }

        /// <summary>
        /// Fracao dos metodos amostrados que satisfazem as invariantes do
        /// metadata. Precisa ser exigente: checar so nameIndex, declaringType e
        /// token nao distingue posicoes de padding que por acaso deixam esses
        /// tres campos alinhados. genericContainerIndex e parameterStart sao os
        /// discriminadores fortes, porque tem faixa conhecida e apertada.
        /// </summary>
        public static double Score(Il2CppMethodDefinition[] parsed, int firstIndex, int[] owner,
                                   int stringSize, int parametersCount, int genericContainersCount)
        {
            if (parsed == null || parsed.Length == 0) return 0;
            int ok = 0, total = 0;
            for (int i = 0; i < parsed.Length; i++)
            {
                int mi = firstIndex + i;
                if (mi >= owner.Length) break;
                total++;
                var m = parsed[i];
                if (m.nameIndex >= (uint)stringSize) continue;
                if (owner[mi] >= 0 && m.declaringType != owner[mi]) continue;
                if ((m.token >> 24) != 0x06) continue;
                if (m.parameterStart < -1 || m.parameterStart > parametersCount) continue;
                if (m.genericContainerIndex < -1 || m.genericContainerIndex >= genericContainersCount) continue;
                // returnParameterToken so existe a partir da v31; em versoes
                // anteriores o campo nao e lido e fica 0.
                var rpt = (uint)m.returnParameterToken;
                if (rpt != 0 && rpt != 0xFFFFFFFF && (rpt >> 24) != 0x08) continue;
                if (m.parameterCount > 0x400) continue;
                ok++;
            }
            return total == 0 ? 0 : (double)ok / total;
        }
    }
}
