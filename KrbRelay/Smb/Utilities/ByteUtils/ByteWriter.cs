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
    public class ByteWriter
    {
        public static void WriteByte(byte[] buffer, int offset, byte value)
        {
            buffer[offset] = value;
        }

        public static void WriteByte(byte[] buffer, ref int offset, byte value)
        {
            buffer[offset] = value;
            offset += 1;
        }

        public static void WriteBytes(byte[] buffer, int offset, byte[] bytes)
        {
            WriteBytes(buffer, offset, bytes, bytes.Length);
        }

        public static void WriteBytes(byte[] buffer, ref int offset, byte[] bytes)
        {
            WriteBytes(buffer, offset, bytes);
            offset += bytes.Length;
        }

        public static void WriteBytes(byte[] buffer, int offset, byte[] bytes, int length)
        {
            Array.Copy(bytes, 0, buffer, offset, length);
        }

        public static void WriteBytes(byte[] buffer, ref int offset, byte[] bytes, int length)
        {
            Array.Copy(bytes, 0, buffer, offset, length);
            offset += length;
        }

        public static void WriteAnsiString(byte[] buffer, int offset, string value)
        {
            WriteAnsiString(buffer, offset, value, value.Length);
        }

        public static void WriteAnsiString(byte[] buffer, ref int offset, string value)
        {
            WriteAnsiString(buffer, ref offset, value, value.Length);
        }

        public static void WriteAnsiString(byte[] buffer, int offset, string value, int maximumLength)
        {
            byte[] bytes = ASCIIEncoding.GetEncoding(28591).GetBytes(value);
            Array.Copy(bytes, 0, buffer, offset, Math.Min(value.Length, maximumLength));
        }

        public static void WriteAnsiString(byte[] buffer, ref int offset, string value, int fieldLength)
        {
            WriteAnsiString(buffer, offset, value, fieldLength);
            offset += fieldLength;
        }

        public static void WriteUTF16String(byte[] buffer, int offset, string value)
        {
            WriteUTF16String(buffer, offset, value, value.Length);
        }

        public static void WriteUTF16String(byte[] buffer, ref int offset, string value)
        {
            WriteUTF16String(buffer, ref offset, value, value.Length);
        }

        public static void WriteUTF16String(byte[] buffer, int offset, string value, int maximumNumberOfCharacters)
        {
            byte[] bytes = UnicodeEncoding.Unicode.GetBytes(value);
            int maximumNumberOfBytes = Math.Min(value.Length, maximumNumberOfCharacters) * 2;
            Array.Copy(bytes, 0, buffer, offset, maximumNumberOfBytes);
        }

        public static void WriteUTF16String(byte[] buffer, ref int offset, string value, int numberOfCharacters)
        {
            WriteUTF16String(buffer, offset, value, numberOfCharacters);
            offset += numberOfCharacters * 2;
        }

        public static void WriteNullTerminatedAnsiString(byte[] buffer, int offset, string value)
        {
            WriteAnsiString(buffer, offset, value);
            WriteByte(buffer, offset + value.Length, 0x00);
        }

        public static void WriteNullTerminatedAnsiString(byte[] buffer, ref int offset, string value)
        {
            WriteNullTerminatedAnsiString(buffer, offset, value);
            offset += value.Length + 1;
        }

        public static void WriteNullTerminatedUTF16String(byte[] buffer, int offset, string value)
        {
            WriteUTF16String(buffer, offset, value);
            WriteBytes(buffer, offset + value.Length * 2, new byte[] { 0x00, 0x00 });
        }

        public static void WriteNullTerminatedUTF16String(byte[] buffer, ref int offset, string value)
        {
            WriteNullTerminatedUTF16String(buffer, offset, value);
            offset += value.Length * 2 + 2;
        }

        public static void WriteBytes(Stream stream, byte[] bytes)
        {
            stream.Write(bytes, 0, bytes.Length);
        }

        public static void WriteBytes(Stream stream, byte[] bytes, int count)
        {
            stream.Write(bytes, 0, count);
        }

        public static void WriteAnsiString(Stream stream, string value)
        {
            WriteAnsiString(stream, value, value.Length);
        }

        public static void WriteAnsiString(Stream stream, string value, int fieldLength)
        {
            byte[] bytes = ASCIIEncoding.GetEncoding(28591).GetBytes(value);
            stream.Write(bytes, 0, Math.Min(bytes.Length, fieldLength));
            if (bytes.Length < fieldLength)
            {
                byte[] zeroFill = new byte[fieldLength - bytes.Length];
                stream.Write(zeroFill, 0, zeroFill.Length);
            }
        }

        public static void WriteUTF8String(Stream stream, string value)
        {
            byte[] bytes = UnicodeEncoding.UTF8.GetBytes(value);
            stream.Write(bytes, 0, bytes.Length);
        }

        public static void WriteUTF16String(Stream stream, string value)
        {
            byte[] bytes = UnicodeEncoding.Unicode.GetBytes(value);
            stream.Write(bytes, 0, bytes.Length);
        }

        public static void WriteUTF16BEString(Stream stream, string value)
        {
            byte[] bytes = UnicodeEncoding.BigEndianUnicode.GetBytes(value);
            stream.Write(bytes, 0, bytes.Length);
        }
    }
}