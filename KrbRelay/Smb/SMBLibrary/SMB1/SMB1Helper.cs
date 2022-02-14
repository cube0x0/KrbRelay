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
    public class SMB1Helper
    {
        public static DateTime? ReadNullableFileTime(byte[] buffer, int offset)
        {
            long span = LittleEndianConverter.ToInt64(buffer, offset);
            if (span >= 0)
            {
                return DateTime.FromFileTimeUtc(span);
            }
            else if (span == 0)
            {
                return null;
            }
            else
            {
                // Tick = 100ns
                return DateTime.UtcNow.Subtract(TimeSpan.FromTicks(span));
            }
        }

        public static DateTime? ReadNullableFileTime(byte[] buffer, ref int offset)
        {
            offset += 8;
            return ReadNullableFileTime(buffer, offset - 8);
        }

        /// <summary>
        /// SMB_DATE
        /// </summary>
        public static DateTime ReadSMBDate(byte[] buffer, int offset)
        {
            ushort value = LittleEndianConverter.ToUInt16(buffer, offset);
            int year = ((value & 0xFE00) >> 9) + 1980;
            int month = ((value & 0x01E0) >> 5);
            int day = (value & 0x001F);
            // SMB_DATE & SMB_TIME are represented in the local time zone of the server
            return new DateTime(year, month, day, 0, 0, 0, DateTimeKind.Local);
        }

        public static void WriteSMBDate(byte[] buffer, int offset, DateTime date)
        {
            int year = date.Year - 1980;
            int month = date.Month;
            int day = date.Day;
            ushort value = (ushort)(year << 9 | month << 5 | day);
            LittleEndianWriter.WriteUInt16(buffer, offset, value);
        }

        /// <summary>
        /// SMB_DATE
        /// </summary>
        public static TimeSpan ReadSMBTime(byte[] buffer, int offset)
        {
            ushort value = LittleEndianConverter.ToUInt16(buffer, offset);
            int hours = ((value & 0xF800) >> 11);
            int minutes = ((value & 0x07E0) >> 5);
            int seconds = (value & 0x001F);
            return new TimeSpan(hours, minutes, seconds);
        }

        public static void WriteSMBTime(byte[] buffer, int offset, TimeSpan time)
        {
            ushort value = (ushort)(time.Hours << 11 | time.Minutes << 5 | time.Seconds);
            LittleEndianWriter.WriteUInt16(buffer, offset, value);
        }

        public static DateTime ReadSMBDateTime(byte[] buffer, int offset)
        {
            DateTime date = ReadSMBDate(buffer, offset);
            TimeSpan time = ReadSMBTime(buffer, offset + 2);
            return date.Add(time);
        }

        public static void WriteSMBDateTime(byte[] buffer, int offset, DateTime dateTime)
        {
            WriteSMBDate(buffer, offset, dateTime.Date);
            WriteSMBTime(buffer, offset + 2, dateTime.TimeOfDay);
        }

        public static DateTime? ReadNullableSMBDateTime(byte[] buffer, int offset)
        {
            uint value = LittleEndianConverter.ToUInt32(buffer, offset);
            if (value > 0)
            {
                return ReadSMBDateTime(buffer, offset);
            }
            return null;
        }

        public static void WriteSMBDateTime(byte[] buffer, int offset, DateTime? dateTime)
        {
            if (dateTime.HasValue)
            {
                WriteSMBDateTime(buffer, offset, dateTime.Value);
            }
            else
            {
                LittleEndianWriter.WriteUInt32(buffer, offset, 0);
            }
        }

        public static string ReadSMBString(byte[] buffer, int offset, bool isUnicode)
        {
            if (isUnicode)
            {
                return ByteReader.ReadNullTerminatedUTF16String(buffer, offset);
            }
            else
            {
                return ByteReader.ReadNullTerminatedAnsiString(buffer, offset);
            }
        }

        public static string ReadSMBString(byte[] buffer, ref int offset, bool isUnicode)
        {
            if (isUnicode)
            {
                return ByteReader.ReadNullTerminatedUTF16String(buffer, ref offset);
            }
            else
            {
                return ByteReader.ReadNullTerminatedAnsiString(buffer, ref offset);
            }
        }

        public static void WriteSMBString(byte[] buffer, int offset, bool isUnicode, string value)
        {
            if (isUnicode)
            {
                ByteWriter.WriteNullTerminatedUTF16String(buffer, offset, value);
            }
            else
            {
                ByteWriter.WriteNullTerminatedAnsiString(buffer, offset, value);
            }
        }

        public static void WriteSMBString(byte[] buffer, ref int offset, bool isUnicode, string value)
        {
            if (isUnicode)
            {
                ByteWriter.WriteNullTerminatedUTF16String(buffer, ref offset, value);
            }
            else
            {
                ByteWriter.WriteNullTerminatedAnsiString(buffer, ref offset, value);
            }
        }

        public static string ReadFixedLengthString(byte[] buffer, ref int offset, bool isUnicode, int byteCount)
        {
            if (isUnicode)
            {
                return ByteReader.ReadUTF16String(buffer, ref offset, byteCount / 2);
            }
            else
            {
                return ByteReader.ReadAnsiString(buffer, ref offset, byteCount);
            }
        }

        public static void WriteFixedLengthString(byte[] buffer, ref int offset, bool isUnicode, string value)
        {
            if (isUnicode)
            {
                ByteWriter.WriteUTF16String(buffer, ref offset, value);
            }
            else
            {
                ByteWriter.WriteAnsiString(buffer, ref offset, value);
            }
        }
    }
}