using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace KrbRelay.HiveParser
{
    internal static class Crypto
    {
        //https://rosettacode.org/wiki/MD4
        public static byte[] Md4Hash2(this byte[] input)
        {
            // get padded uints from bytes
            List<byte> bytes = input.ToList();
            uint bitCount = (uint)(bytes.Count) * 8;
            bytes.Add(128);
            while (bytes.Count % 64 != 56) bytes.Add(0);
            var uints = new List<uint>();
            for (int i = 0; i + 3 < bytes.Count; i += 4)
                uints.Add(bytes[i] | (uint)bytes[i + 1] << 8 | (uint)bytes[i + 2] << 16 | (uint)bytes[i + 3] << 24);
            uints.Add(bitCount);
            uints.Add(0);

            // run rounds
            uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
            Func<uint, uint, uint> rol = (x, y) => x << (int)y | x >> 32 - (int)y;
            for (int q = 0; q + 15 < uints.Count; q += 16)
            {
                var chunk = uints.GetRange(q, 16);
                uint aa = a, bb = b, cc = c, dd = d;
                Action<Func<uint, uint, uint, uint>, uint[]> round = (f, y) =>
                {
                    foreach (uint i in new[] { y[0], y[1], y[2], y[3] })
                    {
                        a = rol(a + f(b, c, d) + chunk[(int)(i + y[4])] + y[12], y[8]);
                        d = rol(d + f(a, b, c) + chunk[(int)(i + y[5])] + y[12], y[9]);
                        c = rol(c + f(d, a, b) + chunk[(int)(i + y[6])] + y[12], y[10]);
                        b = rol(b + f(c, d, a) + chunk[(int)(i + y[7])] + y[12], y[11]);
                    }
                };
                round((x, y, z) => (x & y) | (~x & z), new uint[] { 0, 4, 8, 12, 0, 1, 2, 3, 3, 7, 11, 19, 0 });
                round((x, y, z) => (x & y) | (x & z) | (y & z), new uint[] { 0, 1, 2, 3, 0, 4, 8, 12, 3, 5, 9, 13, 0x5a827999 });
                round((x, y, z) => x ^ y ^ z, new uint[] { 0, 2, 1, 3, 0, 8, 4, 12, 3, 9, 11, 15, 0x6ed9eba1 });
                a += aa; b += bb; c += cc; d += dd;
            }
            // return hex encoded string
            byte[] outBytes = new[] { a, b, c, d }.SelectMany(BitConverter.GetBytes).ToArray();
            return outBytes;
        }

        //https://stackoverflow.com/questions/28613831/encrypt-decrypt-querystring-values-using-aes-256
        public static byte[] DecryptAES_ECB(byte[] value, byte[] key)
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.BlockSize = 128;
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            using (ICryptoTransform decrypt = aes.CreateDecryptor())
            {
                byte[] dest = decrypt.TransformFinalBlock(value, 0, value.Length);
                return dest;
            }
        }

        public static byte[] DecryptAES_CBC(byte[] value, byte[] key, byte[] iv)
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.BlockSize = 128;
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.IV = iv;
            //you would think this would work to pad out the rest of the final block to 16, but it doesnt? ¯\_(ツ)_/¯
            aes.Padding = PaddingMode.Zeros;

            int tailLength = value.Length % 16;
            if (tailLength != 0)
            {
                List<byte> manualPadding = new List<byte>();
                for (int i = 16 - tailLength; i > 0; i--)
                {
                    manualPadding.Add(0x00);
                }
                byte[] concat = new byte[value.Length + manualPadding.Count];
                System.Buffer.BlockCopy(value, 0, concat, 0, value.Length);
                System.Buffer.BlockCopy(manualPadding.ToArray(), 0, concat, value.Length, manualPadding.Count);
                value = concat;
            }

            using (ICryptoTransform decrypt = aes.CreateDecryptor())
            {
                byte[] dest = decrypt.TransformFinalBlock(value, 0, value.Length);
                return dest;
            }
        }

        public static byte[] ComputeSha256(byte[] key, byte[] value)
        {
            MemoryStream memStream = new MemoryStream();
            memStream.Write(key, 0, key.Length);
            for (int i = 0; i < 1000; i++)
            {
                memStream.Write(value, 0, 32);
            }
            byte[] shaBase = memStream.ToArray();
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] newSha = sha256Hash.ComputeHash(shaBase);
                return newSha;
            }
        }

        //https://stackoverflow.com/questions/7217627/is-there-anything-wrong-with-this-rc4-encryption-code-in-c-sharp
        public static byte[] RC4Encrypt(byte[] pwd, byte[] data)
        {
            int a, i, j, k, tmp;
            int[] key, box;
            byte[] cipher;

            key = new int[256];
            box = new int[256];
            cipher = new byte[data.Length];

            for (i = 0; i < 256; i++)
            {
                key[i] = pwd[i % pwd.Length];
                box[i] = i;
            }
            for (j = i = 0; i < 256; i++)
            {
                j = (j + box[i] + key[i]) % 256;
                tmp = box[i];
                box[i] = box[j];
                box[j] = tmp;
            }
            for (a = j = i = 0; i < data.Length; i++)
            {
                a++;
                a %= 256;
                j += box[a];
                j %= 256;
                tmp = box[a];
                box[a] = box[j];
                box[j] = tmp;
                k = box[((box[a] + box[j]) % 256)];
                cipher[i] = (byte)(data[i] ^ k);
            }
            return cipher;
        }

        //method from SidToKey - https://github.com/woanware/ForensicUserInfo/blob/master/Source/SamParser.cs
        private static void RidToKey(string hexRid, ref List<byte> key1, ref List<byte> key2)
        {
            int rid = Int32.Parse(hexRid, System.Globalization.NumberStyles.HexNumber);
            List<byte> temp1 = new List<byte>();

            byte temp = (byte)(rid & 0xFF);
            temp1.Add(temp);

            temp = (byte)(((rid >> 8) & 0xFF));
            temp1.Add(temp);

            temp = (byte)(((rid >> 16) & 0xFF));
            temp1.Add(temp);

            temp = (byte)(((rid >> 24) & 0xFF));
            temp1.Add(temp);

            temp1.Add(temp1[0]);
            temp1.Add(temp1[1]);
            temp1.Add(temp1[2]);

            List<byte> temp2 = new List<byte>();
            temp2.Add(temp1[3]);
            temp2.Add(temp1[0]);
            temp2.Add(temp1[1]);
            temp2.Add(temp1[2]);

            temp2.Add(temp2[0]);
            temp2.Add(temp2[1]);
            temp2.Add(temp2[2]);

            key1 = TransformKey(temp1);
            key2 = TransformKey(temp2);
        }

        private static List<byte> TransformKey(List<byte> inputData)
        {
            List<byte> data = new List<byte>();
            data.Add(Convert.ToByte(((inputData[0] >> 1) & 0x7f) << 1));
            data.Add(Convert.ToByte(((inputData[0] & 0x01) << 6 | ((inputData[1] >> 2) & 0x3f)) << 1));
            data.Add(Convert.ToByte(((inputData[1] & 0x03) << 5 | ((inputData[2] >> 3) & 0x1f)) << 1));
            data.Add(Convert.ToByte(((inputData[2] & 0x07) << 4 | ((inputData[3] >> 4) & 0x0f)) << 1));
            data.Add(Convert.ToByte(((inputData[3] & 0x0f) << 3 | ((inputData[4] >> 5) & 0x07)) << 1));
            data.Add(Convert.ToByte(((inputData[4] & 0x1f) << 2 | ((inputData[5] >> 6) & 0x03)) << 1));
            data.Add(Convert.ToByte(((inputData[5] & 0x3f) << 1 | ((inputData[6] >> 7) & 0x01)) << 1));
            data.Add(Convert.ToByte((inputData[6] & 0x7f) << 1));
            return data;
        }

        //from https://github.com/woanware/ForensicUserInfo/blob/master/Source/SamParser.cs
        private static byte[] DeObfuscateHashPart(byte[] obfuscatedHash, List<byte> key)
        {
            DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
            cryptoProvider.Padding = PaddingMode.None;
            cryptoProvider.Mode = CipherMode.ECB;
            ICryptoTransform transform = cryptoProvider.CreateDecryptor(key.ToArray(), new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
            MemoryStream memoryStream = new MemoryStream(obfuscatedHash);
            CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[obfuscatedHash.Length];
            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            return plainTextBytes;
        }

        public static string DecryptSingleHash(byte[] obfuscatedHash, string user)
        {
            List<byte> key1 = new List<byte>();
            List<byte> key2 = new List<byte>();

            RidToKey(user, ref key1, ref key2);

            byte[] hashBytes1 = new byte[8];
            byte[] hashBytes2 = new byte[8];
            Buffer.BlockCopy(obfuscatedHash, 0, hashBytes1, 0, 8);
            Buffer.BlockCopy(obfuscatedHash, 8, hashBytes2, 0, 8);

            byte[] plain1 = DeObfuscateHashPart(hashBytes1, key1);
            byte[] plain2 = DeObfuscateHashPart(hashBytes2, key2);

            return (BitConverter.ToString(plain1) + BitConverter.ToString(plain2));
        }
    }
}