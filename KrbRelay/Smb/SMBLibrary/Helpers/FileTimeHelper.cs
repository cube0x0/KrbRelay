/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary
{
    public class FileTimeHelper
    {
        public static readonly DateTime MinFileTimeValue = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static DateTime ReadFileTime(byte[] buffer, int offset)
        {
            long span = LittleEndianConverter.ToInt64(buffer, offset);
            if (span >= 0)
            {
                return DateTime.FromFileTimeUtc(span);
            }
            else
            {
                throw new System.IO.InvalidDataException("FILETIME cannot be negative");
            }
        }

        public static DateTime ReadFileTime(byte[] buffer, ref int offset)
        {
            offset += 8;
            return ReadFileTime(buffer, offset - 8);
        }

        public static void WriteFileTime(byte[] buffer, int offset, DateTime time)
        {
            long span = time.ToFileTimeUtc();
            LittleEndianWriter.WriteInt64(buffer, offset, span);
        }

        public static void WriteFileTime(byte[] buffer, ref int offset, DateTime time)
        {
            WriteFileTime(buffer, offset, time);
            offset += 8;
        }

        public static DateTime? ReadNullableFileTime(byte[] buffer, int offset)
        {
            long span = LittleEndianConverter.ToInt64(buffer, offset);
            if (span > 0)
            {
                return DateTime.FromFileTimeUtc(span);
            }
            else if (span == 0)
            {
                return null;
            }
            else
            {
                throw new System.IO.InvalidDataException("FILETIME cannot be negative");
            }
        }

        public static DateTime? ReadNullableFileTime(byte[] buffer, ref int offset)
        {
            offset += 8;
            return ReadNullableFileTime(buffer, offset - 8);
        }

        public static void WriteFileTime(byte[] buffer, int offset, DateTime? time)
        {
            long span = 0;
            if (time.HasValue)
            {
                span = time.Value.ToFileTimeUtc();
            }
            LittleEndianWriter.WriteInt64(buffer, offset, span);
        }

        public static void WriteFileTime(byte[] buffer, ref int offset, DateTime? time)
        {
            WriteFileTime(buffer, offset, time);
            offset += 8;
        }

        /// <summary>
        /// When setting file attributes, a value of -1 indicates to the server that it MUST NOT change this attribute for all subsequent operations on the same file handle.
        /// </summary>
        public static SetFileTime ReadSetFileTime(byte[] buffer, int offset)
        {
            long span = LittleEndianConverter.ToInt64(buffer, offset);
            return SetFileTime.FromFileTimeUtc(span);
        }

        /// <summary>
        /// When setting file attributes, a value of -1 indicates to the server that it MUST NOT change this attribute for all subsequent operations on the same file handle.
        /// </summary>
        public static void WriteSetFileTime(byte[] buffer, int offset, SetFileTime time)
        {
            long span = time.ToFileTimeUtc();
            LittleEndianWriter.WriteInt64(buffer, offset, span);
        }
    }
}