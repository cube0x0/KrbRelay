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
    /// SMB_QUERY_FILE_ALL_INFO
    /// </summary>
    public class QueryFileAllInfo : QueryInformation
    {
        public const int FixedLength = 72;

        public DateTime? CreationTime;
        public DateTime? LastAccessTime;
        public DateTime? LastWriteTime;
        public DateTime? LastChangeTime;
        public ExtendedFileAttributes ExtFileAttributes;
        public uint Reserved1;
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        public bool DeletePending;
        public bool Directory;
        public ushort Reserved2;
        public uint EaSize;

        // uint FileNameLength; // In bytes
        public string FileName; // Unicode

        public QueryFileAllInfo()
        {
        }

        public QueryFileAllInfo(byte[] buffer, int offset)
        {
            CreationTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastAccessTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastWriteTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastChangeTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            ExtFileAttributes = (ExtendedFileAttributes)LittleEndianReader.ReadUInt32(buffer, ref offset);
            Reserved1 = LittleEndianReader.ReadUInt32(buffer, ref offset);
            AllocationSize = LittleEndianReader.ReadInt64(buffer, ref offset);
            EndOfFile = LittleEndianReader.ReadInt64(buffer, ref offset);
            NumberOfLinks = LittleEndianReader.ReadUInt32(buffer, ref offset);
            DeletePending = (ByteReader.ReadByte(buffer, ref offset) > 0);
            Directory = (ByteReader.ReadByte(buffer, ref offset) > 0);
            Reserved2 = LittleEndianReader.ReadUInt16(buffer, ref offset);
            EaSize = LittleEndianReader.ReadUInt32(buffer, ref offset);
            uint fileNameLength = LittleEndianReader.ReadUInt32(buffer, ref offset);
            FileName = ByteReader.ReadUTF16String(buffer, ref offset, (int)(fileNameLength / 2));
        }

        public override byte[] GetBytes()
        {
            uint fileNameLength = (uint)(FileName.Length * 2);
            byte[] buffer = new byte[FixedLength + fileNameLength];
            int offset = 0;
            FileTimeHelper.WriteFileTime(buffer, ref offset, CreationTime);
            FileTimeHelper.WriteFileTime(buffer, ref offset, LastAccessTime);
            FileTimeHelper.WriteFileTime(buffer, ref offset, LastWriteTime);
            FileTimeHelper.WriteFileTime(buffer, ref offset, LastChangeTime);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint)ExtFileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, Reserved1);
            LittleEndianWriter.WriteInt64(buffer, ref offset, AllocationSize);
            LittleEndianWriter.WriteInt64(buffer, ref offset, EndOfFile);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, NumberOfLinks);
            ByteWriter.WriteByte(buffer, ref offset, Convert.ToByte(DeletePending));
            ByteWriter.WriteByte(buffer, ref offset, Convert.ToByte(Directory));
            LittleEndianWriter.WriteUInt16(buffer, ref offset, Reserved2);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, EaSize);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, fileNameLength);
            ByteWriter.WriteUTF16String(buffer, ref offset, FileName);
            return buffer;
        }

        public override QueryInformationLevel InformationLevel
        {
            get
            {
                return QueryInformationLevel.SMB_QUERY_FILE_ALL_INFO;
            }
        }
    }
}