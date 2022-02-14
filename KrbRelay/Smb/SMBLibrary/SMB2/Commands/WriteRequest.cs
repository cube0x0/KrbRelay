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
    /// SMB2 WRITE Request
    /// </summary>
    public class WriteRequest : SMB2Command
    {
        public const int FixedSize = 48;
        public const int DeclaredSize = 49;

        private ushort StructureSize;
        private ushort DataOffset;
        private uint DataLength;
        public ulong Offset;
        public FileID FileId;
        public uint Channel;
        public uint RemainingBytes;
        private ushort WriteChannelInfoOffset;
        private ushort WriteChannelInfoLength;
        public WriteFlags Flags;
        public byte[] Data = new byte[0];
        public byte[] WriteChannelInfo = new byte[0];

        public WriteRequest() : base(SMB2CommandName.Write)
        {
            StructureSize = DeclaredSize;
        }

        public WriteRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            DataOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 2);
            DataLength = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            Offset = LittleEndianConverter.ToUInt64(buffer, offset + SMB2Header.Length + 8);
            FileId = new FileID(buffer, offset + SMB2Header.Length + 16);
            Channel = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 32);
            RemainingBytes = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 36);
            WriteChannelInfoOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 40);
            WriteChannelInfoLength = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 42);
            Flags = (WriteFlags)LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 44);
            Data = ByteReader.ReadBytes(buffer, offset + DataOffset, (int)DataLength);
            WriteChannelInfo = ByteReader.ReadBytes(buffer, offset + WriteChannelInfoOffset, WriteChannelInfoLength);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            // Note: DataLength is UInt32 while WriteChannelInfoOffset is UInt16
            // so it is best to put WriteChannelInfo before Data.
            WriteChannelInfoOffset = 0;
            WriteChannelInfoLength = (ushort)WriteChannelInfo.Length;
            if (WriteChannelInfo.Length > 0)
            {
                WriteChannelInfoOffset = SMB2Header.Length + FixedSize;
            }
            DataOffset = 0;
            DataLength = (uint)Data.Length;
            if (Data.Length > 0)
            {
                DataOffset = (ushort)(SMB2Header.Length + FixedSize + WriteChannelInfo.Length);
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, DataOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, DataLength);
            LittleEndianWriter.WriteUInt64(buffer, offset + 8, Offset);
            FileId.WriteBytes(buffer, offset + 16);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, Channel);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, RemainingBytes);
            LittleEndianWriter.WriteUInt16(buffer, offset + 40, WriteChannelInfoOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 42, WriteChannelInfoLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 44, (uint)Flags);
            if (WriteChannelInfo.Length > 0)
            {
                ByteWriter.WriteBytes(buffer, offset + FixedSize, WriteChannelInfo);
            }
            if (Data.Length > 0)
            {
                ByteWriter.WriteBytes(buffer, offset + FixedSize + WriteChannelInfo.Length, Data);
            }
        }

        public override int CommandLength
        {
            get
            {
                return FixedSize + Data.Length + WriteChannelInfo.Length;
            }
        }
    }
}