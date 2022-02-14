/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.4.15 - FileFullEaInformation data element
    /// </summary>
    public class FileFullEAEntry
    {
        public const int FixedLength = 8;

        public uint NextEntryOffset;
        public ExtendedAttributeFlags Flags;
        private byte EaNameLength;
        private ushort EaValueLength;
        public string EaName; // 8-bit ASCII followed by a single terminating null character byte
        public string EaValue; // 8-bit ASCII

        public FileFullEAEntry()
        {
        }

        public FileFullEAEntry(byte[] buffer, int offset)
        {
            NextEntryOffset = LittleEndianReader.ReadUInt32(buffer, ref offset);
            Flags = (ExtendedAttributeFlags)ByteReader.ReadByte(buffer, ref offset);
            EaNameLength = ByteReader.ReadByte(buffer, ref offset);
            EaValueLength = LittleEndianReader.ReadUInt16(buffer, ref offset);
            EaName = ByteReader.ReadAnsiString(buffer, ref offset, EaNameLength);
            offset++; // terminating null
            EaValue = ByteReader.ReadAnsiString(buffer, ref offset, EaValueLength);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            EaNameLength = (byte)EaName.Length;
            EaValueLength = (ushort)EaValue.Length;
            LittleEndianWriter.WriteUInt32(buffer, ref offset, NextEntryOffset);
            ByteWriter.WriteByte(buffer, ref offset, (byte)Flags);
            ByteWriter.WriteByte(buffer, ref offset, EaNameLength);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, EaValueLength);
            ByteWriter.WriteAnsiString(buffer, ref offset, EaName);
            ByteWriter.WriteByte(buffer, ref offset, 0); // terminating null
            ByteWriter.WriteAnsiString(buffer, ref offset, EaValue);
        }

        public int Length
        {
            get
            {
                return FixedLength + EaName.Length + 1 + EaValue.Length;
            }
        }
    }
}