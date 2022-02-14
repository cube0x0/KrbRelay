/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 WRITE Response
    /// </summary>
    public class WriteResponse : SMB2Command
    {
        public const int FixedSize = 16;
        public const int DeclaredSize = 17;

        private ushort StructureSize;
        public ushort Reserved;
        public uint Count;
        public uint Remaining;
        private ushort WriteChannelInfoOffset;
        private ushort WriteChannelInfoLength;
        public byte[] WriteChannelInfo = new byte[0];

        public WriteResponse() : base(SMB2CommandName.Write)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public WriteResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 2);
            Count = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            Remaining = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 8);
            WriteChannelInfoOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 12);
            WriteChannelInfoLength = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 14);
            WriteChannelInfo = ByteReader.ReadBytes(buffer, offset + WriteChannelInfoOffset, WriteChannelInfoLength);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            WriteChannelInfoOffset = 0;
            WriteChannelInfoLength = (ushort)WriteChannelInfo.Length;
            if (WriteChannelInfo.Length > 0)
            {
                WriteChannelInfoOffset = SMB2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, Count);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, Remaining);
            LittleEndianWriter.WriteUInt16(buffer, offset + 12, WriteChannelInfoOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 14, WriteChannelInfoLength);
            if (WriteChannelInfo.Length > 0)
            {
                ByteWriter.WriteBytes(buffer, offset + FixedSize, WriteChannelInfo);
            }
        }

        public override int CommandLength
        {
            get
            {
                return FixedSize + WriteChannelInfo.Length;
            }
        }
    }
}