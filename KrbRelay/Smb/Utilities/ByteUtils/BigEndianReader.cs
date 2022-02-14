/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;

namespace Utilities
{
    public class BigEndianReader
    {
        public static short ReadInt16(byte[] buffer, ref int offset)
        {
            offset += 2;
            return BigEndianConverter.ToInt16(buffer, offset - 2);
        }

        public static ushort ReadUInt16(byte[] buffer, ref int offset)
        {
            offset += 2;
            return BigEndianConverter.ToUInt16(buffer, offset - 2);
        }

        public static uint ReadUInt24(byte[] buffer, int offset)
        {
            return (uint)((buffer[offset + 0] << 16) | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 0));
        }

        public static uint ReadUInt24(byte[] buffer, ref int offset)
        {
            offset += 3;
            return ReadUInt24(buffer, offset - 3);
        }

        public static int ReadInt32(byte[] buffer, ref int offset)
        {
            offset += 4;
            return BigEndianConverter.ToInt32(buffer, offset - 4);
        }

        public static uint ReadUInt32(byte[] buffer, ref int offset)
        {
            offset += 4;
            return BigEndianConverter.ToUInt32(buffer, offset - 4);
        }

        public static long ReadInt64(byte[] buffer, ref int offset)
        {
            offset += 8;
            return BigEndianConverter.ToInt64(buffer, offset - 8);
        }

        public static ulong ReadUInt64(byte[] buffer, ref int offset)
        {
            offset += 8;
            return BigEndianConverter.ToUInt64(buffer, offset - 8);
        }

        public static Guid ReadGuid(byte[] buffer, ref int offset)
        {
            offset += 16;
            return BigEndianConverter.ToGuid(buffer, offset - 16);
        }

        public static short ReadInt16(Stream stream)
        {
            byte[] buffer = new byte[2];
            stream.Read(buffer, 0, 2);
            return BigEndianConverter.ToInt16(buffer, 0);
        }

        public static ushort ReadUInt16(Stream stream)
        {
            byte[] buffer = new byte[2];
            stream.Read(buffer, 0, 2);
            return BigEndianConverter.ToUInt16(buffer, 0);
        }

        public static uint ReadUInt24(Stream stream)
        {
            byte[] buffer = new byte[4];
            stream.Read(buffer, 1, 3);
            return BigEndianConverter.ToUInt32(buffer, 0);
        }

        public static int ReadInt32(Stream stream)
        {
            byte[] buffer = new byte[4];
            stream.Read(buffer, 0, 4);
            return BigEndianConverter.ToInt32(buffer, 0);
        }

        public static uint ReadUInt32(Stream stream)
        {
            byte[] buffer = new byte[4];
            stream.Read(buffer, 0, 4);
            return BigEndianConverter.ToUInt32(buffer, 0);
        }

        public static long ReadInt64(Stream stream)
        {
            byte[] buffer = new byte[8];
            stream.Read(buffer, 0, 8);
            return BigEndianConverter.ToInt64(buffer, 0);
        }

        public static ulong ReadUInt64(Stream stream)
        {
            byte[] buffer = new byte[8];
            stream.Read(buffer, 0, 8);
            return BigEndianConverter.ToUInt64(buffer, 0);
        }

        public static Guid ReadGuid(Stream stream)
        {
            byte[] buffer = new byte[16];
            stream.Read(buffer, 0, 16);
            return BigEndianConverter.ToGuid(buffer, 0);
        }
    }
}