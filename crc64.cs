using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace crc
{
    public static class Crc64
    {
        /// <summary>
        /// The size of a CRC-64 checksum in bytes.
        /// </summary>
        private const int Size = 8;

        /// <summary>
        /// The ISO polynomial, defined in ISO 3309 and used in HDLC.
        /// </summary>
        private const ulong ISO = 0xD800000000000000;

        /// <summary>
        /// The ECMA polynomial, defined in ECMA 182.
        /// </summary>
        public const ulong ECMA = 0xC96C5795D7870F42;

        private static ulong[][] slicing8TableISO;
        private static ulong[][] slicing8TableECMA;

        static Crc64()
        {
            slicing8TableISO = makeSlicingBy8Table(makeTable(ISO));
            slicing8TableECMA = makeSlicingBy8Table(makeTable(ECMA));
        }

        public static ulong[] MakeTable(ulong poly)
        {
            switch (poly)
            {
                case ISO:
                    return slicing8TableISO[0];
                case ECMA:
                    return slicing8TableECMA[0];
                default:
                    return makeTable(poly);
            }
        }

        static ulong[] makeTable(ulong poly)
        {
            var t = new ulong[256];
            for (int i = 0; i < 256; i++)
            {
                var crc = (ulong) i;
                for (int j = 0; j < 8; j++)
                {
                    if ((crc & 1) == 1)
                        crc = (crc >> 1) ^ poly;
                    else
                        crc >>= 1;
                }

                t[i] = crc;
            }

            return t;
        }

        static ulong[][] makeSlicingBy8Table(ulong[] t)
        {
            var helperTable = createTables(256, 8);
            helperTable[0] = t;
            for (int i = 0; i < 256; i++)
            {
                var crc = t[i];
                for (int j = 1; j < 8; j++)
                {
                    crc = t[crc & 0xff] ^ (crc >> 8);
                    helperTable[j][i] = crc;
                }
            }

            return helperTable;
        }

        static ulong[][] createTables(int sizeInner, int sizeOuter)
        {
            var l = new List<ulong[]>();
            for (int i = 0; i < sizeOuter; i++)
            {
                l.Add(new ulong[sizeInner]);
            }

            return l.ToArray();
        }

//        public static digest New(){}

        class digest
        {
            public ulong crc;
            public ulong[] tab;

            public int Size() => Crc64.Size;
            public int BlockSize() => 1;
            public ulong Sum64() => crc;
            public void Reset() => crc = 0;


            public byte[] Sum(byte[] @in)
            {
                var s = Sum64();
                var list = @in.ToList();
                list.AddRange(new[]
                    {(byte) (s >> 56), (byte) (s >> 48), (byte) (s >> 40), (byte) (s >> 32), (byte) (s >> 24), (byte) (s >> 16), (byte) (s >> 8), (byte) (s)});
                return list.ToArray();
            }

            public byte[] MarshalBinary()
            {
                var b = new byte[marshaledSize];
                var list = b.ToList();
                list.AddRange(magic.Select(d => (byte) d));
                b = list.ToArray();
                b = appendUint64(b, tableSum(tab));
                b = appendUint64(b, crc);
                return b;
            }

            public void UnmarshalBinary(ReadOnlySpan<byte> b)
            {
                if (b.Length < magic.Length || new string(b.Slice(0, magic.Length).ToArray().Select(d => (char) d).ToArray()) != magic)
                {
                    throw new Exception("hash/crc64: invalid hash state identifier");
                }

                if (b.Length != marshaledSize)
                {
                    throw new Exception("hash/crc64: invalid hash state size");
                }

                if (tableSum(tab) != readUint64(b.Slice(4)))
                {
                    throw new Exception("hash/crc64: tables do not match");
                }
            }

            public int Write(byte[] p)
            {
                crc = update(crc, tab, p);
                return p.Length;
            }
        }

        private const string magic = "crc\x02";
        private static int marshaledSize = magic.Length + 8 + 8;

        static byte[] appendUint64(byte[] b, ulong x)
        {
            var a = new[]
            {
                (byte) (x >> 56),
                (byte) (x >> 48),
                (byte) (x >> 40),
                (byte) (x >> 32),
                (byte) (x >> 24),
                (byte) (x >> 16),
                (byte) (x >> 8),
                (byte) (x),
            };
            var l = b.ToList();
            l.AddRange(a);
            return l.ToArray();
        }

        static ulong readUint64(ReadOnlySpan<byte> b)
        {
            _ = b[7];
            return ((ulong) b[7]) | ((ulong) b[6]) << 8 | ((ulong) b[5]) << 16 | ((ulong) b[4]) << 24 |
                ((ulong) b[3]) << 32 | ((ulong) b[2]) << 40 | ((ulong) b[1]) << 48 | ((ulong) b[0]) << 56;
        }


        static ulong update(ulong crc, ulong[] tab, ReadOnlySpan<byte> p)
        {
            crc = ~crc;
            while (p.Length >= 64)
            {
                ulong[][] helperTable;
                if (tab == slicing8TableECMA[0])
                    helperTable = slicing8TableECMA;
                else if (tab == slicing8TableISO[0])
                    helperTable = slicing8TableISO;
                else if (p.Length > 16384)
                    helperTable = makeSlicingBy8Table(tab);
                else
                    break;
                while (p.Length > 8)
                {
                    crc ^= ((ulong) p[0]) | ((ulong) p[1]) << 8 | ((ulong) p[2]) << 16 | ((ulong) p[3]) << 24 |
                        ((ulong) p[4]) << 32 | ((ulong) p[5]) << 40 | ((ulong) p[6]) << 48 | ((ulong) p[7]) << 56;
                    crc = helperTable[7][crc & 0xff] ^
                        helperTable[6][(crc >> 8) & 0xff] ^
                        helperTable[5][(crc >> 16) & 0xff] ^
                        helperTable[4][(crc >> 24) & 0xff] ^
                        helperTable[3][(crc >> 32) & 0xff] ^
                        helperTable[2][(crc >> 40) & 0xff] ^
                        helperTable[1][(crc >> 48) & 0xff] ^
                        helperTable[0][crc >> 56];

                    p = p.Slice(8);
                }
            }

            foreach (var v in p)
            {
                crc = tab[((byte) crc) ^ v] ^ (crc >> 8);
            }

            return ~crc;
        }

        /// <summary>
        /// Update returns the result of adding the bytes in p to the crc.
        /// </summary>
        /// <param name="crc"></param>
        /// <param name="tab"></param>
        /// <param name="p"></param>
        /// <returns></returns>
        public static ulong Update(ulong crc, ulong[] tab, byte[] p)
        {
            return update(crc, tab, p);
        }

        /// <summary>
        /// Checksum returns the CRC-64 checksum of data using the polynomial represented by the Table.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="tab"></param>
        /// <returns></returns>
        public static ulong Checksum(byte[] data, ulong[] tab)
        {
            return update(0, tab, data);
        }

        /// <summary>
        /// tableSum returns the ISO checksum of table t.
        /// </summary>
        /// <param name="t"></param>
        /// <returns></returns>
        static ulong tableSum(ulong[] t)
        {
            var a = new byte[2048];
            var b = new byte[0];
            if (t != null)
            {
                foreach (var x in t)
                {
                    appendUint64(b, x);
                }
            }

            return Checksum(b, MakeTable(ISO));
        }

    }
}
