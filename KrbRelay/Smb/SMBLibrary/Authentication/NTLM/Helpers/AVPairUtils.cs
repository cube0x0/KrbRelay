/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.Text;
using Utilities;

namespace SMBLibrary.Authentication.NTLM
{
    public class AVPairUtils
    {
        public static KeyValuePairList<AVPairKey, byte[]> GetAVPairSequence(string domainName, string computerName)
        {
            KeyValuePairList<AVPairKey, byte[]> pairs = new KeyValuePairList<AVPairKey, byte[]>();
            pairs.Add(AVPairKey.NbDomainName, UnicodeEncoding.Unicode.GetBytes(domainName));
            pairs.Add(AVPairKey.NbComputerName, UnicodeEncoding.Unicode.GetBytes(computerName));
            return pairs;
        }

        public static byte[] GetAVPairSequenceBytes(KeyValuePairList<AVPairKey, byte[]> pairs)
        {
            int length = GetAVPairSequenceLength(pairs);
            byte[] result = new byte[length];
            int offset = 0;
            WriteAVPairSequence(result, ref offset, pairs);
            return result;
        }

        public static int GetAVPairSequenceLength(KeyValuePairList<AVPairKey, byte[]> pairs)
        {
            int length = 0;
            foreach (KeyValuePair<AVPairKey, byte[]> pair in pairs)
            {
                length += 4 + pair.Value.Length;
            }
            return length + 4;
        }

        public static void WriteAVPairSequence(byte[] buffer, ref int offset, KeyValuePairList<AVPairKey, byte[]> pairs)
        {
            foreach (KeyValuePair<AVPairKey, byte[]> pair in pairs)
            {
                WriteAVPair(buffer, ref offset, pair.Key, pair.Value);
            }
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort)AVPairKey.EOL);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, 0);
        }

        private static void WriteAVPair(byte[] buffer, ref int offset, AVPairKey key, byte[] value)
        {
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort)key);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort)value.Length);
            ByteWriter.WriteBytes(buffer, ref offset, value);
        }

        public static KeyValuePairList<AVPairKey, byte[]> ReadAVPairSequence(byte[] buffer, int offset)
        {
            KeyValuePairList<AVPairKey, byte[]> result = new KeyValuePairList<AVPairKey, byte[]>();
            AVPairKey key = (AVPairKey)LittleEndianConverter.ToUInt16(buffer, offset);
            while (key != AVPairKey.EOL)
            {
                KeyValuePair<AVPairKey, byte[]> pair = ReadAVPair(buffer, ref offset);
                result.Add(pair);
                key = (AVPairKey)LittleEndianConverter.ToUInt16(buffer, offset);
            }

            return result;
        }

        private static KeyValuePair<AVPairKey, byte[]> ReadAVPair(byte[] buffer, ref int offset)
        {
            AVPairKey key = (AVPairKey)LittleEndianReader.ReadUInt16(buffer, ref offset);
            ushort length = LittleEndianReader.ReadUInt16(buffer, ref offset);
            byte[] value = ByteReader.ReadBytes(buffer, ref offset, length);
            return new KeyValuePair<AVPairKey, byte[]>(key, value);
        }
    }
}