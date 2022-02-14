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
    /// [MS-DTYP] ACE_HEADER
    /// </summary>
    public class AceHeader
    {
        public const int Length = 4;

        public AceType AceType;
        public AceFlags AceFlags;
        public ushort AceSize;

        public AceHeader()
        {
        }

        public AceHeader(byte[] buffer, int offset)
        {
            AceType = (AceType)ByteReader.ReadByte(buffer, offset + 0);
            AceFlags = (AceFlags)ByteReader.ReadByte(buffer, offset + 1);
            AceSize = LittleEndianConverter.ToUInt16(buffer, offset + 2);
        }

        public void WriteBytes(byte[] buffer, ref int offset)
        {
            ByteWriter.WriteByte(buffer, ref offset, (byte)AceType);
            ByteWriter.WriteByte(buffer, ref offset, (byte)AceFlags);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, AceSize);
        }
    }
}