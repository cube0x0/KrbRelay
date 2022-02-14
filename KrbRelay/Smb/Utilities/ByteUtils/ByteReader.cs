/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using System.Text;

namespace Utilities
{
    public class ByteReader
    {
        public static byte ReadByte(byte[] buffer, int offset)
        {
            return buffer[offset];
        }

        public static byte ReadByte(byte[] buffer, ref int offset)
        {
            offset++;
            return buffer[offset - 1];
        }

        public static byte[] ReadBytes(byte[] buffer, int offset, int length)
        {
            byte[] result = new byte[length];
            Array.Copy(buffer, offset, result, 0, length);
            return result;
        }

        public static byte[] ReadBytes(byte[] buffer, ref int offset, int length)
        {
            offset += length;
            return ReadBytes(buffer, offset - length, length);
        }

        /// <summary>
        /// Will return the ANSI string stored in the buffer
        /// </summary>
        public static string ReadAnsiString(byte[] buffer, int offset, int count)
        {
            // ASCIIEncoding.ASCII.GetString will convert some values to '?' (byte value of 63)
            // Any codepage will do, but the only one that Mono supports is 28591.
            return ASCIIEncoding.GetEncoding(28591).GetString(buffer, offset, count);
        }

        public static string ReadAnsiString(byte[] buffer, ref int offset, int count)
        {
            offset += count;
            return ReadAnsiString(buffer, offset - count, count);
        }

        public static string ReadUTF16String(byte[] buffer, int offset, int numberOfCharacters)
        {
            int numberOfBytes = numberOfCharacters * 2;
            return Encoding.Unicode.GetString(buffer, offset, numberOfBytes);
        }

        public static string ReadUTF16String(byte[] buffer, ref int offset, int numberOfCharacters)
        {
            int numberOfBytes = numberOfCharacters * 2;
            offset += numberOfBytes;
            return ReadUTF16String(buffer, offset - numberOfBytes, numberOfCharacters);
        }

        public static string ReadNullTerminatedAnsiString(byte[] buffer, int offset)
        {
            StringBuilder builder = new StringBuilder();
            char c = (char)ByteReader.ReadByte(buffer, offset);
            while (c != '\0')
            {
                builder.Append(c);
                offset++;
                c = (char)ByteReader.ReadByte(buffer, offset);
            }
            return builder.ToString();
        }

        public static string ReadNullTerminatedUTF16String(byte[] buffer, int offset)
        {
            StringBuilder builder = new StringBuilder();
            char c = (char)LittleEndianConverter.ToUInt16(buffer, offset);
            while (c != 0)
            {
                builder.Append(c);
                offset += 2;
                c = (char)LittleEndianConverter.ToUInt16(buffer, offset);
            }
            return builder.ToString();
        }

        public static string ReadNullTerminatedAnsiString(byte[] buffer, ref int offset)
        {
            string result = ReadNullTerminatedAnsiString(buffer, offset);
            offset += result.Length + 1;
            return result;
        }

        public static string ReadNullTerminatedUTF16String(byte[] buffer, ref int offset)
        {
            string result = ReadNullTerminatedUTF16String(buffer, offset);
            offset += result.Length * 2 + 2;
            return result;
        }

        public static byte[] ReadBytes(Stream stream, int count)
        {
            MemoryStream temp = new MemoryStream();
            ByteUtils.CopyStream(stream, temp, count);
            return temp.ToArray();
        }

        /// <summary>
        /// Return all bytes from current stream position to the end of the stream
        /// </summary>
        public static byte[] ReadAllBytes(Stream stream)
        {
            MemoryStream temp = new MemoryStream();
            ByteUtils.CopyStream(stream, temp);
            return temp.ToArray();
        }

        public static string ReadAnsiString(Stream stream, int length)
        {
            byte[] buffer = ReadBytes(stream, length);
            return ASCIIEncoding.GetEncoding(28591).GetString(buffer);
        }

        public static string ReadNullTerminatedAnsiString(Stream stream)
        {
            StringBuilder builder = new StringBuilder();
            char c = (char)stream.ReadByte();
            while (c != '\0')
            {
                builder.Append(c);
                c = (char)stream.ReadByte();
            }
            return builder.ToString();
        }
    }
}