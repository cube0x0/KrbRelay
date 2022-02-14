/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Utilities;

namespace SMBLibrary.Authentication.NTLM
{
    public class NTLMCryptography
    {
        public static byte[] ComputeLMv1Response(byte[] challenge, string password)
        {
            byte[] hash = LMOWFv1(password);
            return DesLongEncrypt(hash, challenge);
        }

        public static byte[] ComputeNTLMv1Response(byte[] challenge, string password)
        {
            byte[] hash = NTOWFv1(password);
            return DesLongEncrypt(hash, challenge);
        }

        public static byte[] ComputeNTLMv1ExtendedSessionSecurityResponse(byte[] serverChallenge, byte[] clientChallenge, string password)
        {
            byte[] passwordHash = NTOWFv1(password);
            byte[] challengeHash = MD5.Create().ComputeHash(ByteUtils.Concatenate(serverChallenge, clientChallenge));
            byte[] challengeHashShort = new byte[8];
            Array.Copy(challengeHash, 0, challengeHashShort, 0, 8);
            return DesLongEncrypt(passwordHash, challengeHashShort);
        }

        public static byte[] ComputeLMv2Response(byte[] serverChallenge, byte[] clientChallenge, string password, string user, string domain)
        {
            byte[] key = LMOWFv2(password, user, domain);
            byte[] bytes = ByteUtils.Concatenate(serverChallenge, clientChallenge);
            HMACMD5 hmac = new HMACMD5(key);
            byte[] hash = hmac.ComputeHash(bytes, 0, bytes.Length);

            return ByteUtils.Concatenate(hash, clientChallenge);
        }

        /// <summary>
        /// [MS-NLMP] https://msdn.microsoft.com/en-us/library/cc236700.aspx
        /// </summary>
        /// <param name="clientChallengeStructurePadded">ClientChallengeStructure with 4 zero bytes padding, a.k.a. temp</param>
        public static byte[] ComputeNTLMv2Proof(byte[] serverChallenge, byte[] clientChallengeStructurePadded, string password, string user, string domain)
        {
            byte[] key = NTOWFv2(password, user, domain);
            byte[] temp = clientChallengeStructurePadded;

            HMACMD5 hmac = new HMACMD5(key);
            byte[] _NTProof = hmac.ComputeHash(ByteUtils.Concatenate(serverChallenge, temp), 0, serverChallenge.Length + temp.Length);
            return _NTProof;
        }

        public static byte[] DesEncrypt(byte[] key, byte[] plainText)
        {
            return DesEncrypt(key, plainText, 0, plainText.Length);
        }

        public static byte[] DesEncrypt(byte[] key, byte[] plainText, int inputOffset, int inputCount)
        {
            ICryptoTransform encryptor = CreateWeakDesEncryptor(CipherMode.ECB, key, new byte[key.Length]);
            byte[] result = new byte[inputCount];
            encryptor.TransformBlock(plainText, inputOffset, inputCount, result, 0);
            return result;
        }

        public static ICryptoTransform CreateWeakDesEncryptor(CipherMode mode, byte[] rgbKey, byte[] rgbIV)
        {
            DES des = DES.Create();
            des.Mode = mode;
            DESCryptoServiceProvider sm = des as DESCryptoServiceProvider;
            MethodInfo mi = sm.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] Par = { rgbKey, mode, rgbIV, sm.FeedbackSize, 0 };
            ICryptoTransform trans = mi.Invoke(sm, Par) as ICryptoTransform;
            return trans;
        }

        /// <summary>
        /// DESL()
        /// </summary>
        public static byte[] DesLongEncrypt(byte[] key, byte[] plainText)
        {
            if (key.Length != 16)
            {
                throw new ArgumentException("Invalid key length");
            }

            if (plainText.Length != 8)
            {
                throw new ArgumentException("Invalid plain-text length");
            }
            byte[] padded = new byte[21];
            Array.Copy(key, padded, key.Length);

            byte[] k1 = new byte[7];
            byte[] k2 = new byte[7];
            byte[] k3 = new byte[7];
            Array.Copy(padded, 0, k1, 0, 7);
            Array.Copy(padded, 7, k2, 0, 7);
            Array.Copy(padded, 14, k3, 0, 7);

            byte[] r1 = DesEncrypt(ExtendDESKey(k1), plainText);
            byte[] r2 = DesEncrypt(ExtendDESKey(k2), plainText);
            byte[] r3 = DesEncrypt(ExtendDESKey(k3), plainText);

            byte[] result = new byte[24];
            Array.Copy(r1, 0, result, 0, 8);
            Array.Copy(r2, 0, result, 8, 8);
            Array.Copy(r3, 0, result, 16, 8);

            return result;
        }

        public static Encoding GetOEMEncoding()
        {
            return Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
        }

        /// <summary>
        /// LM Hash
        /// </summary>
        public static byte[] LMOWFv1(string password)
        {
            byte[] plainText = ASCIIEncoding.ASCII.GetBytes("KGS!@#$%");
            byte[] passwordBytes = GetOEMEncoding().GetBytes(password.ToUpper());
            byte[] key = new byte[14];
            Array.Copy(passwordBytes, key, Math.Min(passwordBytes.Length, 14));

            byte[] k1 = new byte[7];
            byte[] k2 = new byte[7];
            Array.Copy(key, 0, k1, 0, 7);
            Array.Copy(key, 7, k2, 0, 7);

            byte[] part1 = DesEncrypt(ExtendDESKey(k1), plainText);
            byte[] part2 = DesEncrypt(ExtendDESKey(k2), plainText);

            return ByteUtils.Concatenate(part1, part2);
        }

        /// <summary>
        /// NTLM hash (NT hash)
        /// </summary>
        public static byte[] NTOWFv1(string password)
        {
            byte[] passwordBytes = UnicodeEncoding.Unicode.GetBytes(password);
            return new MD4().GetByteHashFromBytes(passwordBytes);
        }

        /// <summary>
        /// LMOWFv2 is identical to NTOWFv2
        /// </summary>
        public static byte[] LMOWFv2(string password, string user, string domain)
        {
            return NTOWFv2(password, user, domain);
        }

        public static byte[] NTOWFv2(string password, string user, string domain)
        {
            byte[] passwordBytes = UnicodeEncoding.Unicode.GetBytes(password);
            byte[] key = new MD4().GetByteHashFromBytes(passwordBytes);
            string text = user.ToUpper() + domain;
            byte[] bytes = UnicodeEncoding.Unicode.GetBytes(text);
            HMACMD5 hmac = new HMACMD5(key);
            return hmac.ComputeHash(bytes, 0, bytes.Length);
        }

        /// <summary>
        /// Extends a 7-byte key into an 8-byte key.
        /// Note: The DES key ostensibly consists of 64 bits, however, only 56 of these are actually used by the algorithm.
        /// Eight bits are used solely for checking parity, and are thereafter discarded
        /// </summary>
        private static byte[] ExtendDESKey(byte[] key)
        {
            byte[] result = new byte[8];
            int i;

            result[0] = (byte)((key[0] >> 1) & 0xff);
            result[1] = (byte)((((key[0] & 0x01) << 6) | (((key[1] & 0xff) >> 2) & 0xff)) & 0xff);
            result[2] = (byte)((((key[1] & 0x03) << 5) | (((key[2] & 0xff) >> 3) & 0xff)) & 0xff);
            result[3] = (byte)((((key[2] & 0x07) << 4) | (((key[3] & 0xff) >> 4) & 0xff)) & 0xff);
            result[4] = (byte)((((key[3] & 0x0F) << 3) | (((key[4] & 0xff) >> 5) & 0xff)) & 0xff);
            result[5] = (byte)((((key[4] & 0x1F) << 2) | (((key[5] & 0xff) >> 6) & 0xff)) & 0xff);
            result[6] = (byte)((((key[5] & 0x3F) << 1) | (((key[6] & 0xff) >> 7) & 0xff)) & 0xff);
            result[7] = (byte)(key[6] & 0x7F);
            for (i = 0; i < 8; i++)
            {
                result[i] = (byte)(result[i] << 1);
            }

            return result;
        }

        /// <summary>
        /// [MS-NLMP] 3.4.5.1 - KXKEY - NTLM v1
        /// </summary>
        /// <remarks>
        /// If NTLM v2 is used, KeyExchangeKey MUST be set to the value of SessionBaseKey.
        /// </remarks>
        public static byte[] KXKey(byte[] sessionBaseKey, NegotiateFlags negotiateFlags, byte[] lmChallengeResponse, byte[] serverChallenge, byte[] lmowf)
        {
            if ((negotiateFlags & NegotiateFlags.ExtendedSessionSecurity) == 0)
            {
                if ((negotiateFlags & NegotiateFlags.LanManagerSessionKey) > 0)
                {
                    byte[] k1 = ByteReader.ReadBytes(lmowf, 0, 7);
                    byte[] k2 = ByteUtils.Concatenate(ByteReader.ReadBytes(lmowf, 7, 1), new byte[] { 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD });
                    byte[] temp1 = DesEncrypt(ExtendDESKey(k1), ByteReader.ReadBytes(lmChallengeResponse, 0, 8));
                    byte[] temp2 = DesEncrypt(ExtendDESKey(k2), ByteReader.ReadBytes(lmChallengeResponse, 0, 8));
                    byte[] keyExchangeKey = ByteUtils.Concatenate(temp1, temp2);
                    return keyExchangeKey;
                }
                else
                {
                    if ((negotiateFlags & NegotiateFlags.RequestLMSessionKey) > 0)
                    {
                        byte[] keyExchangeKey = ByteUtils.Concatenate(ByteReader.ReadBytes(lmowf, 0, 8), new byte[8]);
                        return keyExchangeKey;
                    }
                    else
                    {
                        return sessionBaseKey;
                    }
                }
            }
            else
            {
                byte[] buffer = ByteUtils.Concatenate(serverChallenge, ByteReader.ReadBytes(lmChallengeResponse, 0, 8));
                byte[] keyExchangeKey = new HMACMD5(sessionBaseKey).ComputeHash(buffer);
                return keyExchangeKey;
            }
        }
    }
}