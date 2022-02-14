/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * Based on: https://bitlush.com/blog/rc4-encryption-in-c-sharp
 */

namespace System.Security.Cryptography
{
    public class RC4
    {
        public static byte[] Encrypt(byte[] key, byte[] data)
        {
            return EncryptOutput(key, data);
        }

        public static byte[] Decrypt(byte[] key, byte[] data)
        {
            return EncryptOutput(key, data);
        }

        private static byte[] EncryptInitalize(byte[] key)
        {
            byte[] s = new byte[256];
            for (int index = 0; index < 256; index++)
            {
                s[index] = (byte)index;
            }

            for (int i = 0, j = 0; i < 256; i++)
            {
                j = (j + key[i % key.Length] + s[i]) & 255;

                Swap(s, i, j);
            }

            return s;
        }

        private static byte[] EncryptOutput(byte[] key, byte[] data)
        {
            byte[] s = EncryptInitalize(key);

            int i = 0;
            int j = 0;

            byte[] output = new byte[data.Length];
            for (int index = 0; index < data.Length; index++)
            {
                i = (i + 1) & 255;
                j = (j + s[i]) & 255;

                Swap(s, i, j);
                output[index] = (byte)(data[index] ^ s[(s[i] + s[j]) & 255]);
            }
            return output;
        }

        private static void Swap(byte[] s, int i, int j)
        {
            byte c = s[i];

            s[i] = s[j];
            s[j] = c;
        }
    }
}