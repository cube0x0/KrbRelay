/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 READ Request
    /// </summary>
    public class ReadRequest : SMB2Command
    {
        public const int FixedSize = 48;
        public const int DeclaredSize = 49;

        private ushort StructureSize;
        public byte Padding;
        public ReadFlags Flags;
        public uint ReadLength;
        public ulong Offset;
        public FileID FileId;
        public uint MinimumCount;
        public uint Channel;
        public uint RemainingBytes;
        private ushort ReadChannelInfoOffset;
        private ushort ReadChannelInfoLength;
        public byte[] ReadChannelInfo = new byte[0];

        public ReadRequest() : base(SMB2CommandName.Read)
        {
            StructureSize = DeclaredSize;
        }

        public ReadRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            Padding = ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 2);
            Flags = (ReadFlags)ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 3);
            ReadLength = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            Offset = LittleEndianConverter.ToUInt64(buffer, offset + SMB2Header.Length + 8);
            FileId = new FileID(buffer, offset + SMB2Header.Length + 16);
            MinimumCount = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 32);
            Channel = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 36);
            RemainingBytes = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 40);
            ReadChannelInfoOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 44);
            ReadChannelInfoLength = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 46);
            if (ReadChannelInfoLength > 0)
            {
                ReadChannelInfo = ByteReader.ReadBytes(buffer, offset + ReadChannelInfoOffset, ReadChannelInfoLength);
            }
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            ReadChannelInfoOffset = 0;
            ReadChannelInfoLength = (ushort)ReadChannelInfo.Length;
            if (ReadChannelInfo.Length > 0)
            {
                ReadChannelInfoOffset = SMB2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            ByteWriter.WriteByte(buffer, offset + 2, Padding);
            ByteWriter.WriteByte(buffer, offset + 3, (byte)Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, ReadLength);
            LittleEndianWriter.WriteUInt64(buffer, offset + 8, Offset);
            FileId.WriteBytes(buffer, offset + 16);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, MinimumCount);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, Channel);
            LittleEndianWriter.WriteUInt32(buffer, offset + 40, RemainingBytes);
            LittleEndianWriter.WriteUInt16(buffer, offset + 44, ReadChannelInfoOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 46, ReadChannelInfoLength);
            if (ReadChannelInfo.Length > 0)
            {
                ByteWriter.WriteBytes(buffer, offset + FixedSize, ReadChannelInfo);
            }
            else
            {
                // The client MUST set one byte of [the buffer] field to 0
                ByteWriter.WriteBytes(buffer, offset + FixedSize, new byte[1]);
            }
        }

        public override int CommandLength
        {
            get
            {
                // The client MUST set one byte of [the buffer] field to 0
                return Math.Max(FixedSize + ReadChannelInfo.Length, DeclaredSize);
            }
        }
    }
}