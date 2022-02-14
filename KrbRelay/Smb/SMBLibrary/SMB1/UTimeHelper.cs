/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// UTime - The number of seconds since Jan 1, 1970, 00:00:00
    /// </summary>
    public class UTimeHelper
    {
        public static readonly DateTime MinUTimeValue = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Local);

        public static DateTime ReadUTime(byte[] buffer, int offset)
        {
            uint span = LittleEndianConverter.ToUInt32(buffer, offset);
            return MinUTimeValue.AddSeconds(span);
        }

        public static DateTime ReadUTime(byte[] buffer, ref int offset)
        {
            offset += 4;
            return ReadUTime(buffer, offset - 4);
        }

        public static DateTime? ReadNullableUTime(byte[] buffer, int offset)
        {
            uint span = LittleEndianConverter.ToUInt32(buffer, offset);
            if (span > 0)
            {
                return MinUTimeValue.AddSeconds(span);
            }
            else
            {
                return null;
            }
        }

        public static DateTime? ReadNullableUTime(byte[] buffer, ref int offset)
        {
            offset += 4;
            return ReadNullableUTime(buffer, offset - 4);
        }

        public static void WriteUTime(byte[] buffer, int offset, DateTime time)
        {
            TimeSpan timespan = time - MinUTimeValue;
            uint span = (uint)timespan.TotalSeconds;
            LittleEndianWriter.WriteUInt32(buffer, offset, span);
        }

        public static void WriteUTime(byte[] buffer, ref int offset, DateTime time)
        {
            WriteUTime(buffer, offset, time);
            offset += 4;
        }

        public static void WriteUTime(byte[] buffer, int offset, DateTime? time)
        {
            uint span = 0;
            if (time.HasValue)
            {
                TimeSpan timespan = time.Value - MinUTimeValue;
                span = (uint)timespan.TotalSeconds;
            }
            LittleEndianWriter.WriteUInt32(buffer, offset, span);
        }

        public static void WriteUTime(byte[] buffer, ref int offset, DateTime? time)
        {
            WriteUTime(buffer, offset, time);
            offset += 4;
        }
    }
}