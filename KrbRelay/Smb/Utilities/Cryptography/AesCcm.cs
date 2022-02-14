/* Copyright (C) 2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using System.Security.Cryptography;

namespace Utilities
{
    /// <summary>
    /// Implements the Counter with CBC-MAC (CCM) detailed in RFC 3610
    /// </summary>
    public static class AesCcm
    {
        private static byte[] CalculateMac(byte[] key, byte[] nonce, byte[] data, byte[] associatedData, int signatureLength)
        {
            byte[] messageToAuthenticate = BuildB0Block(nonce, true, signatureLength, data.Length);
            if (associatedData.Length > 0)
            {
                if (associatedData.Length >= 65280)
                {
                    throw new NotSupportedException("Associated data length of 65280 or more is not supported");
                }

                byte[] associatedDataLength = BigEndianConverter.GetBytes((ushort)associatedData.Length);
                messageToAuthenticate = ByteUtils.Concatenate(messageToAuthenticate, associatedDataLength);
                messageToAuthenticate = ByteUtils.Concatenate(messageToAuthenticate, associatedData);
                int associatedDataPaddingLength = (16 - (messageToAuthenticate.Length % 16)) % 16;
                messageToAuthenticate = ByteUtils.Concatenate(messageToAuthenticate, new byte[associatedDataPaddingLength]);
            }

            messageToAuthenticate = ByteUtils.Concatenate(messageToAuthenticate, data);

            int dataPaddingLength = (16 - (messageToAuthenticate.Length % 16)) % 16;
            messageToAuthenticate = ByteUtils.Concatenate(messageToAuthenticate, new byte[dataPaddingLength]);

            byte[] encrypted = AesEncrypt(key, new byte[16], messageToAuthenticate, CipherMode.CBC);

            return ByteReader.ReadBytes(encrypted, messageToAuthenticate.Length - 16, signatureLength);
        }

        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] data, byte[] associatedData, int signatureLength, out byte[] signature)
        {
            if (nonce.Length < 7 || nonce.Length > 13)
            {
                throw new ArgumentException("nonce length must be between 7 and 13 bytes");
            }

            if (signatureLength < 4 || signatureLength > 16 || (signatureLength % 2 == 1))
            {
                throw new ArgumentException("signature length must be an even number between 4 and 16 bytes");
            }

            byte[] keyStream = BuildKeyStream(key, nonce, data.Length);

            byte[] mac = CalculateMac(key, nonce, data, associatedData, signatureLength);
            signature = ByteUtils.XOR(keyStream, 0, mac, 0, mac.Length);
            return ByteUtils.XOR(data, 0, keyStream, 16, data.Length);
        }

        public static byte[] DecryptAndAuthenticate(byte[] key, byte[] nonce, byte[] encryptedData, byte[] associatedData, byte[] signature)
        {
            if (nonce.Length < 7 || nonce.Length > 13)
            {
                throw new ArgumentException("nonce length must be between 7 and 13 bytes");
            }

            if (signature.Length < 4 || signature.Length > 16 || (signature.Length % 2 == 1))
            {
                throw new ArgumentException("signature length must be an even number between 4 and 16 bytes");
            }

            byte[] keyStream = BuildKeyStream(key, nonce, encryptedData.Length);

            byte[] data = ByteUtils.XOR(encryptedData, 0, keyStream, 16, encryptedData.Length);

            byte[] mac = CalculateMac(key, nonce, data, associatedData, signature.Length);
            byte[] expectedSignature = ByteUtils.XOR(keyStream, 0, mac, 0, mac.Length);
            if (!ByteUtils.AreByteArraysEqual(expectedSignature, signature))
            {
                throw new CryptographicException("The computed authentication value did not match the input");
            }
            return data;
        }

        private static byte[] BuildKeyStream(byte[] key, byte[] nonce, int dataLength)
        {
            int paddingLength = (16 - (dataLength % 16) % 16);
            int keyStreamLength = 16 + dataLength + paddingLength;
            int KeyStreamBlockCount = keyStreamLength / 16;
            byte[] keyStreamInput = new byte[keyStreamLength];
            for (int index = 0; index < KeyStreamBlockCount; index++)
            {
                byte[] aBlock = BuildABlock(nonce, index);
                ByteWriter.WriteBytes(keyStreamInput, index * 16, aBlock);
            }

            return AesEncrypt(key, new byte[16], keyStreamInput, CipherMode.ECB);
        }

        private static byte[] BuildB0Block(byte[] nonce, bool hasAssociatedData, int signatureLength, int messageLength)
        {
            byte[] b0 = new byte[16];
            Array.Copy(nonce, 0, b0, 1, nonce.Length);
            int lengthFieldLength = 15 - nonce.Length;
            b0[0] = ComputeFlagsByte(hasAssociatedData, signatureLength, lengthFieldLength);

            int temp = messageLength;
            for (int index = 15; index > 15 - lengthFieldLength; index--)
            {
                b0[index] = (byte)(temp % 256);
                temp /= 256;
            }

            return b0;
        }

        private static byte[] BuildABlock(byte[] nonce, int blockIndex)
        {
            byte[] aBlock = new byte[16];
            Array.Copy(nonce, 0, aBlock, 1, nonce.Length);
            int lengthFieldLength = 15 - nonce.Length;
            aBlock[0] = (byte)(lengthFieldLength - 1);

            int temp = blockIndex;
            for (int index = 15; index > 15 - lengthFieldLength; index--)
            {
                aBlock[index] = (byte)(temp % 256);
                temp /= 256;
            }

            return aBlock;
        }

        private static byte ComputeFlagsByte(bool hasAssociatedData, int signatureLength, int lengthFieldLength)
        {
            byte flags = 0;
            if (hasAssociatedData)
            {
                flags |= 0x40;
            }

            flags |= (byte)(lengthFieldLength - 1); // L'
            flags |= (byte)(((signatureLength - 2) / 2) << 3); // M'

            return flags;
        }

        private static byte[] AesEncrypt(byte[] key, byte[] iv, byte[] data, CipherMode cipherMode)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                RijndaelManaged aes = new RijndaelManaged();
                aes.Mode = cipherMode;
                aes.Padding = PaddingMode.None;

                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();

                    return ms.ToArray();
                }
            }
        }
    }
}