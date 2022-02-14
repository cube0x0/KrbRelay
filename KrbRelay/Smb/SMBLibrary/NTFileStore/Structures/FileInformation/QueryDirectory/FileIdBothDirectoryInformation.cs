/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.4.17 - FileIdBothDirectoryInformation
    /// </summary>
    public class FileIdBothDirectoryInformation : QueryDirectoryFileInformation
    {
        public const int FixedLength = 104;

        public DateTime CreationTime;
        public DateTime LastAccessTime;
        public DateTime LastWriteTime;
        public DateTime ChangeTime;
        public long EndOfFile;
        public long AllocationSize;
        public FileAttributes FileAttributes;
        private uint FileNameLength;
        public uint EaSize;
        private byte ShortNameLength;
        public byte Reserved1;
        public string ShortName = String.Empty; // Short (8.3) file name in UTF16 (24 bytes)
        public ushort Reserved2;
        public ulong FileId;
        public string FileName = String.Empty;

        public FileIdBothDirectoryInformation()
        {
        }

        public FileIdBothDirectoryInformation(byte[] buffer, int offset) : base(buffer, offset)
        {
            CreationTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 8));
            LastAccessTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 16));
            LastWriteTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 24));
            ChangeTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + 32));
            EndOfFile = LittleEndianConverter.ToInt64(buffer, offset + 40);
            AllocationSize = LittleEndianConverter.ToInt64(buffer, offset + 48);
            FileAttributes = (FileAttributes)LittleEndianConverter.ToUInt32(buffer, offset + 56);
            FileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 60);
            EaSize = LittleEndianConverter.ToUInt32(buffer, offset + 64);
            ShortNameLength = ByteReader.ReadByte(buffer, offset + 68);
            Reserved1 = ByteReader.ReadByte(buffer, offset + 69);
            ShortName = ByteReader.ReadUTF16String(buffer, offset + 70, ShortNameLength / 2);
            Reserved2 = LittleEndianConverter.ToUInt16(buffer, offset + 94);
            FileId = LittleEndianConverter.ToUInt64(buffer, offset + 96);
            FileName = ByteReader.ReadUTF16String(buffer, offset + 104, (int)FileNameLength / 2);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            base.WriteBytes(buffer, offset);
            ShortNameLength = (byte)(ShortName.Length * 2);
            FileNameLength = (uint)(FileName.Length * 2);
            LittleEndianWriter.WriteInt64(buffer, offset + 8, CreationTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 16, LastAccessTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 24, LastWriteTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 32, ChangeTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 40, EndOfFile);
            LittleEndianWriter.WriteInt64(buffer, offset + 48, AllocationSize);
            LittleEndianWriter.WriteUInt32(buffer, offset + 56, (uint)FileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, offset + 60, FileNameLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 64, EaSize);
            ByteWriter.WriteByte(buffer, offset + 68, ShortNameLength);
            ByteWriter.WriteByte(buffer, offset + 69, Reserved1);
            ByteWriter.WriteUTF16String(buffer, offset + 70, ShortName);
            LittleEndianWriter.WriteUInt16(buffer, offset + 94, Reserved2);
            LittleEndianWriter.WriteUInt64(buffer, offset + 96, FileId);
            ByteWriter.WriteUTF16String(buffer, offset + 104, FileName);
        }

        public override FileInformationClass FileInformationClass
        {
            get
            {
                return FileInformationClass.FileIdBothDirectoryInformation;
            }
        }

        public override int Length
        {
            get
            {
                return FixedLength + FileName.Length * 2;
            }
        }
    }
}